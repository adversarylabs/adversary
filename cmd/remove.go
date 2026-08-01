package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/spf13/cobra"
)

// maxRemovePasses bounds re-enumeration after concurrent pack/pull races so a
// pathological writer cannot force an infinite remove loop.
const maxRemovePasses = 8

type removeOptions struct {
	all    bool
	yes    bool
	dryRun bool
	format string
}

func newRemoveCommand(app *application.App) *cobra.Command {
	opts := &removeOptions{}
	cmd := &cobra.Command{
		Use:     "remove [name|reference|digest]...",
		Aliases: []string{"rm"},
		Short:   "Remove adversaries from the local store",
		Long: `Remove one or more adversaries from the local content-addressable store.

Selectors match:
  • package name (all installed versions), e.g. go/cli
  • name:version, e.g. go/cli:0.0.15
  • stored reference or content digest

Use --all to remove every local adversary (--yes required unless --dry-run).

References are deleted first; unreachable blobs are garbage-collected so disk
space is reclaimed. The remote catalog is never modified.

Concurrent pack/pull is handled by re-scanning the store until matching
references are gone (or a bounded number of passes is exhausted).`,
		Example: `  adversary remove go/cli
  adversary remove go/cli:0.0.15 security/secrets
  adversary remove --all --yes
  adversary remove --dry-run --all
  adversary rm go/cli`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, false)
			if err != nil {
				return err
			}
			if opts.all && len(args) > 0 {
				return &application.Error{
					Operation: "remove",
					Kind:      "usage",
					Err:       fmt.Errorf("--all cannot be combined with name arguments"),
				}
			}
			if !opts.all && len(args) == 0 {
				return &application.Error{
					Operation: "remove",
					Kind:      "usage",
					Err:       fmt.Errorf("specify at least one name/reference/digest, or use --all"),
				}
			}
			if opts.all && !opts.yes && !opts.dryRun {
				return &application.Error{
					Operation: "remove",
					Kind:      "confirmation",
					Err:       fmt.Errorf("remove --all requires --yes (or use --dry-run)"),
				}
			}

			dto, err := removeLocalAdversaries(app.Dependencies(), removePlan{
				All:       opts.all,
				Selectors: args,
				DryRun:    opts.dryRun,
			})
			if err != nil {
				return err
			}
			if format == "json" {
				return writeJSON(cmd.OutOrStdout(), "remove", dto)
			}
			return writeRemoveText(cmd.OutOrStdout(), dto)
		},
	}
	cmd.Flags().BoolVar(&opts.all, "all", false, "remove every local adversary")
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "confirm remove --all")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "show what would be removed without deleting")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	return cmd
}

type removePlan struct {
	All       bool
	Selectors []string
	DryRun    bool
}

type removeDTO struct {
	Removed          []removeItemDTO `json:"removed"`
	DryRun           bool            `json:"dryRun"`
	PlannedDeletions int             `json:"plannedDeletions"`
	GarbageCollected int             `json:"garbageCollected,omitempty"`
}

type removeItemDTO struct {
	Name               string `json:"name"`
	Version            string `json:"version,omitempty"`
	Digest             string `json:"digest,omitempty"`
	CanonicalReference string `json:"canonicalReference,omitempty"`
}

func removeLocalAdversaries(deps application.Dependencies, plan removePlan) (removeDTO, error) {
	if plan.DryRun {
		entries, err := deps.Repository.ReferenceEntries()
		if err != nil {
			return removeDTO{}, &application.Error{Operation: "remove", Kind: "repository", Err: err}
		}
		targets, err := planTargets(entries, plan, true)
		if err != nil {
			return removeDTO{}, err
		}
		return removeDTO{
			Removed:          summarizeRemoved(targets),
			DryRun:           true,
			PlannedDeletions: countUniqueDigests(targets),
		}, nil
	}

	removedByDigest := make(map[string]removeItemDTO)
	var removeOrder []string
	var gcDeleted int
	sawMatch := false

	for pass := 0; pass < maxRemovePasses; pass++ {
		entries, err := deps.Repository.ReferenceEntries()
		if err != nil {
			return removeDTO{}, &application.Error{Operation: "remove", Kind: "repository", Err: err}
		}
		// After the first pass, missing selectors are fine (already removed).
		targets, err := planTargets(entries, plan, pass == 0)
		if err != nil {
			return removeDTO{}, err
		}
		if len(targets) == 0 {
			break
		}
		sawMatch = true

		progress := false
		var casStuck error
		for _, entry := range targets {
			err := deleteStoredRef(deps.Repository, entry.CanonicalReference, entry.Digest)
			if err != nil {
				if errors.Is(err, repository.ErrCAS) {
					// Digest moved under us; next pass re-snapshots and retries.
					casStuck = err
					continue
				}
				return removeDTO{}, &application.Error{
					Operation: "remove",
					Kind:      "repository",
					Resource:  entry.CanonicalReference,
					Err:       err,
				}
			}
			progress = true
			if _, seen := removedByDigest[entry.Digest]; !seen {
				removedByDigest[entry.Digest] = removeItemDTO{
					Name:               entry.Record.Name,
					Version:            entry.Record.Version,
					Digest:             entry.Digest,
					CanonicalReference: entry.CanonicalReference,
				}
				removeOrder = append(removeOrder, entry.Digest)
			}
		}

		// Always GC after a pass that deleted something so partial progress
		// still reclaims blobs even if a later pass fails.
		if progress {
			n, err := garbageCollectUnreachable(deps.Repository)
			if err != nil {
				return removeDTO{}, err
			}
			gcDeleted += n
		}

		if !progress {
			if casStuck != nil {
				return removeDTO{}, &application.Error{
					Operation: "remove",
					Kind:      "repository",
					Err:       fmt.Errorf("could not finish remove amid concurrent store updates: %w", casStuck),
				}
			}
			break
		}
	}

	// Final scan: concurrent pack/pull may have recreated matching refs.
	entries, err := deps.Repository.ReferenceEntries()
	if err != nil {
		return removeDTO{}, &application.Error{Operation: "remove", Kind: "repository", Err: err}
	}
	remaining, err := planTargets(entries, plan, false)
	if err != nil {
		return removeDTO{}, err
	}
	if len(remaining) > 0 {
		return removeDTO{}, &application.Error{
			Operation: "remove",
			Kind:      "repository",
			Err: fmt.Errorf(
				"remove did not converge after %d passes (%d matching reference(s) remain); retry",
				maxRemovePasses, len(remaining),
			),
		}
	}

	if !plan.All && !sawMatch && len(plan.Selectors) > 0 {
		// planTargets on pass 0 would have returned not_found; defensive.
		return removeDTO{}, &application.Error{
			Operation: "remove",
			Kind:      "not_found",
			Resource:  plan.Selectors[0],
			Err:       fmt.Errorf("no local adversary matches %q", plan.Selectors[0]),
		}
	}

	removed := make([]removeItemDTO, 0, len(removeOrder))
	for _, d := range removeOrder {
		removed = append(removed, removedByDigest[d])
	}
	return removeDTO{
		Removed:          removed,
		DryRun:           false,
		PlannedDeletions: len(removed),
		GarbageCollected: gcDeleted,
	}, nil
}

// planTargets selects references to delete. requireMatch errors when a selector
// matches nothing (first pass / dry-run); later passes allow empty results.
func planTargets(entries []repository.Entry, plan removePlan, requireMatch bool) ([]repository.Entry, error) {
	if plan.All {
		return append([]repository.Entry(nil), entries...), nil
	}
	targets, err := selectRemoveTargets(entries, plan.Selectors, requireMatch)
	if err != nil {
		return nil, err
	}
	sortRemoveTargets(targets)
	return targets, nil
}

func sortRemoveTargets(targets []repository.Entry) {
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Record.Name != targets[j].Record.Name {
			return strings.ToLower(targets[i].Record.Name) < strings.ToLower(targets[j].Record.Name)
		}
		if targets[i].Record.Version != targets[j].Record.Version {
			return targets[i].Record.Version < targets[j].Record.Version
		}
		return targets[i].CanonicalReference < targets[j].CanonicalReference
	})
}

func summarizeRemoved(targets []repository.Entry) []removeItemDTO {
	byDigest := make(map[string]removeItemDTO)
	var order []string
	for _, entry := range targets {
		if _, seen := byDigest[entry.Digest]; seen {
			continue
		}
		byDigest[entry.Digest] = removeItemDTO{
			Name:               entry.Record.Name,
			Version:            entry.Record.Version,
			Digest:             entry.Digest,
			CanonicalReference: entry.CanonicalReference,
		}
		order = append(order, entry.Digest)
	}
	out := make([]removeItemDTO, 0, len(order))
	for _, d := range order {
		out = append(out, byDigest[d])
	}
	return out
}

func countUniqueDigests(targets []repository.Entry) int {
	seen := make(map[string]bool, len(targets))
	for _, entry := range targets {
		seen[entry.Digest] = true
	}
	return len(seen)
}

// deleteStoredRef deletes a reference. Already-gone refs succeed. ErrCAS is
// returned to the caller so a re-snapshot pass can retry with a fresh digest
// rather than deleting an unrelated tip blindly.
func deleteStoredRef(repo application.Repository, ref, digest string) error {
	err := repo.DeleteRef(ref, digest)
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if errors.Is(err, repository.ErrCAS) {
		// Confirm whether the ref still exists. If gone, another remover won.
		if _, resolveErr := repo.Resolve(ref); resolveErr != nil {
			if os.IsNotExist(resolveErr) || errors.Is(resolveErr, os.ErrNotExist) {
				return nil
			}
		}
		return err
	}
	return err
}

func garbageCollectUnreachable(repo application.Repository) (int, error) {
	plan, err := repo.PlanGC()
	if err != nil {
		return 0, &application.Error{Operation: "remove gc plan", Kind: "repository", Err: err}
	}
	if len(plan.Delete) == 0 && len(plan.DeleteContent) == 0 {
		return 0, nil
	}
	report, err := repo.ApplyGC(plan, false)
	if err != nil {
		// CAS on GC means the plan is stale; replan once and apply.
		if errors.Is(err, repository.ErrCAS) {
			plan, err = repo.PlanGC()
			if err != nil {
				return 0, &application.Error{Operation: "remove gc plan", Kind: "repository", Err: err}
			}
			report, err = repo.ApplyGC(plan, false)
		}
		if err != nil {
			return 0, &application.Error{Operation: "remove gc apply", Kind: "repository", Resource: plan.ID, Err: err}
		}
	}
	return len(report.DeletedRecords), nil
}

func writeRemoveText(w io.Writer, dto removeDTO) error {
	prefix := "Removed"
	if dto.DryRun {
		prefix = "Would remove"
	}
	for _, item := range dto.Removed {
		name := item.Name
		if name == "" {
			name = item.CanonicalReference
		}
		line := fmt.Sprintf("%s: %s", prefix, name)
		if item.Version != "" {
			line += " " + item.Version
		}
		if item.CanonicalReference != "" {
			line += " (" + item.CanonicalReference + ")"
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if dto.DryRun {
		_, err := fmt.Fprintf(w, "Dry run: %d adversary(ies) would be removed.\n", dto.PlannedDeletions)
		return err
	}
	if dto.PlannedDeletions == 0 {
		_, err := fmt.Fprintln(w, "No matching local adversaries.")
		return err
	}
	_, err := fmt.Fprintf(w, "Removed %d adversary(ies)", dto.PlannedDeletions)
	if err != nil {
		return err
	}
	if dto.GarbageCollected > 0 {
		_, err = fmt.Fprintf(w, "; garbage-collected %d record(s)", dto.GarbageCollected)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

// selectRemoveTargets picks every local reference that matches any selector.
// Matching a package name selects all refs for all versions of that name.
// Matching a digest selects every ref that points at that digest.
// When requireMatch is true, unknown selectors error so typos do not silently no-op.
func selectRemoveTargets(entries []repository.Entry, selectors []string, requireMatch bool) ([]repository.Entry, error) {
	digestWanted := map[string]bool{}
	for _, raw := range selectors {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			return nil, &application.Error{
				Operation: "remove",
				Kind:      "usage",
				Err:       fmt.Errorf("empty selector"),
			}
		}
		matched := 0
		for _, entry := range entries {
			if entryMatchesRemoveSelector(entry, sel) {
				digestWanted[entry.Digest] = true
				matched++
			}
		}
		if matched == 0 && requireMatch {
			return nil, &application.Error{
				Operation: "remove",
				Kind:      "not_found",
				Resource:  sel,
				Err:       fmt.Errorf("no local adversary matches %q", sel),
			}
		}
	}
	out := make([]repository.Entry, 0, len(entries))
	seenRef := map[string]bool{}
	for _, entry := range entries {
		if !digestWanted[entry.Digest] {
			continue
		}
		key := entry.CanonicalReference + "\x00" + entry.Digest
		if seenRef[key] {
			continue
		}
		seenRef[key] = true
		out = append(out, entry)
	}
	return out, nil
}

func entryMatchesRemoveSelector(entry repository.Entry, selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}
	name := strings.TrimSpace(entry.Record.Name)
	version := strings.TrimSpace(entry.Record.Version)
	ref := strings.TrimSpace(entry.CanonicalReference)
	digest := strings.TrimSpace(entry.Digest)

	if strings.EqualFold(name, selector) {
		return true
	}
	if ref != "" && (strings.EqualFold(ref, selector) || ref == selector) {
		return true
	}
	if digest != "" {
		if digest == selector || strings.EqualFold(digest, selector) {
			return true
		}
		// Accept bare hex when stored form is sha256:<hex>.
		if strings.HasPrefix(digest, "sha256:") && strings.EqualFold(strings.TrimPrefix(digest, "sha256:"), selector) {
			return true
		}
		if strings.HasPrefix(selector, "sha256:") && strings.EqualFold(digest, selector) {
			return true
		}
	}
	// name:version (tag after last colon when not a host:port form).
	if name != "" {
		if head, ver, ok := cutNameVersion(selector); ok {
			if strings.EqualFold(name, head) && version == ver {
				return true
			}
		}
	}
	return false
}

// cutNameVersion splits "name:version" but not "host:port/path" or digests.
func cutNameVersion(selector string) (name, version string, ok bool) {
	if strings.HasPrefix(selector, "sha256:") {
		return "", "", false
	}
	// host:port/... is a reference, not name:version.
	if strings.Contains(selector, "/") {
		// Allow domain/name:version
		colon := strings.LastIndex(selector, ":")
		if colon <= 0 {
			return "", "", false
		}
		slash := strings.LastIndex(selector, "/")
		if colon < slash {
			return "", "", false // port in host:port/path
		}
		return selector[:colon], selector[colon+1:], selector[colon+1:] != ""
	}
	colon := strings.LastIndex(selector, ":")
	if colon <= 0 || colon == len(selector)-1 {
		return "", "", false
	}
	// host:port alone has no slash — treat as name:version only when left side
	// looks like a package name (no dots-only host ambiguity for our catalog).
	return selector[:colon], selector[colon+1:], true
}
