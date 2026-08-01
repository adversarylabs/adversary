package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/spf13/cobra"
)

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
space is reclaimed. The remote catalog is never modified.`,
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

			deps := app.Dependencies()
			// Every runnable reference (not collapsed by digest) so :latest and
			// version tags for the same package are all deleted.
			entries, err := deps.Repository.ReferenceEntries()
			if err != nil {
				return &application.Error{Operation: "remove", Kind: "repository", Err: err}
			}

			var targets []repository.Entry
			if opts.all {
				targets = append([]repository.Entry(nil), entries...)
			} else {
				targets, err = selectRemoveTargets(entries, args)
				if err != nil {
					return err
				}
			}

			// Stable order for output and deterministic CAS ops.
			sort.SliceStable(targets, func(i, j int) bool {
				if targets[i].Record.Name != targets[j].Record.Name {
					return strings.ToLower(targets[i].Record.Name) < strings.ToLower(targets[j].Record.Name)
				}
				if targets[i].Record.Version != targets[j].Record.Version {
					return targets[i].Record.Version < targets[j].Record.Version
				}
				return targets[i].CanonicalReference < targets[j].CanonicalReference
			})

			if len(targets) == 0 {
				if format == "json" {
					return writeJSON(cmd.OutOrStdout(), "remove", removeDTO{Removed: []removeItemDTO{}, DryRun: opts.dryRun})
				}
				fmt.Fprintln(cmd.OutOrStdout(), "No matching local adversaries.")
				return nil
			}

			// Delete every matching reference. Report one row per digest (package
			// version) so text output is not noisy when :latest and :version share
			// content; still delete all refs so GC can reclaim blobs.
			removedByDigest := make(map[string]removeItemDTO)
			var removeOrder []string
			for _, entry := range targets {
				if !opts.dryRun {
					if err := deps.Repository.DeleteRef(entry.CanonicalReference, entry.Digest); err != nil {
						return &application.Error{
							Operation: "remove",
							Kind:      "repository",
							Resource:  entry.CanonicalReference,
							Err:       err,
						}
					}
				}
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
			removed := make([]removeItemDTO, 0, len(removeOrder))
			for _, d := range removeOrder {
				removed = append(removed, removedByDigest[d])
			}

			var gcDeleted int
			if !opts.dryRun && len(removed) > 0 {
				plan, err := deps.Repository.PlanGC()
				if err != nil {
					return &application.Error{Operation: "remove gc plan", Kind: "repository", Err: err}
				}
				report, err := deps.Repository.ApplyGC(plan, false)
				if err != nil {
					return &application.Error{Operation: "remove gc apply", Kind: "repository", Resource: plan.ID, Err: err}
				}
				gcDeleted = len(report.DeletedRecords)
			}

			dto := removeDTO{
				Removed:          removed,
				DryRun:           opts.dryRun,
				GarbageCollected: gcDeleted,
				PlannedDeletions: len(removed),
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
// Unknown selectors are errors so typos do not silently no-op.
func selectRemoveTargets(entries []repository.Entry, selectors []string) ([]repository.Entry, error) {
	// First pass: digests selected by name/version/ref/digest match.
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
		if matched == 0 {
			return nil, &application.Error{
				Operation: "remove",
				Kind:      "not_found",
				Resource:  sel,
				Err:       fmt.Errorf("no local adversary matches %q", sel),
			}
		}
	}
	// Second pass: include every reference for selected digests so aliases
	// (:latest, alternate spellings) are removed with the package.
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
