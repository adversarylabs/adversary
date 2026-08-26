package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	semver "github.com/Masterminds/semver/v3"
	"github.com/adversarylabs/adversary/internal/application"
	"golang.org/x/term"
)

// ensureAccessibleAdversaries verifies every remote catalog entry the user can
// access (newest version per repository identity), pulls anything not already
// at the resolved digest, and prints docker-pull-style status lines:
//
//	Ensuring 10 accessible adversaries
//	  ✓  go-cli            0.0.15   up to date
//	  ✓  secrets           0.0.6    installed
//	  ✗  dockercompose              failed: 404 Not Found
//	9 ready · 1 failed
//
// Catalog entries often ship an untagged repository reference plus a separate
// Version field. Untagged pulls resolve to :latest, which many packages never
// publish — so ensure pins the catalog version onto the pull reference.
//
// Catalog list failures warn and return nil so offline use continues, except
// context cancellation/deadline which always propagate. Once the catalog is
// available, any package pull failure makes the automatic run fail rather than
// silently selecting from an incomplete candidate set.
func ensureAccessibleAdversaries(
	ctx context.Context,
	app *application.App,
	apiURL, profile string,
	stderr io.Writer,
) error {
	if stderr == nil {
		stderr = io.Discard
	}
	deps := app.Dependencies()
	remote, err := fetchRemoteInventory(ctx, deps, apiURL, profile, "")
	if err != nil {
		if isContextError(err) {
			return err
		}
		fmt.Fprintf(stderr, "Warning: could not list remote adversaries (%v); using local store only.\n", err)
		return nil
	}
	if len(remote) == 0 {
		return nil
	}

	type chosen struct {
		name, ref, version string
	}
	best := make(map[string]chosen, len(remote))
	order := make([]string, 0, len(remote))
	for _, item := range remote {
		ref := strings.TrimSpace(item.Reference)
		if ref == "" {
			ref = strings.TrimSpace(item.Name)
		}
		if ref == "" {
			continue
		}
		key := inventoryIdentityKey(ref)
		version := strings.TrimSpace(item.Version)
		if version == "" {
			version = referenceVersionHint(ref)
		}
		// Pin the catalog version before selection so newest-version comparison
		// and the eventual pull use the same concrete tag.
		ref = catalogPullReference(ref, version)
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = shortInventoryIdentity(ref)
		}
		if prev, ok := best[key]; ok {
			if !preferCatalogVersion(version, prev.version) {
				continue
			}
			best[key] = chosen{name: name, ref: ref, version: version}
			continue
		}
		best[key] = chosen{name: name, ref: ref, version: version}
		order = append(order, key)
	}
	if len(order) == 0 {
		return nil
	}

	n := len(order)
	fmt.Fprintf(stderr, "Ensuring %d accessible adversaries\n", n)

	useCR := ensureWriterIsTTY(stderr)
	ready, installed, failed := 0, 0, 0
	for i, key := range order {
		item := best[key]
		if err := ctx.Err(); err != nil {
			return err
		}
		label := displayAdversaryName(item.name, item.ref)
		writeEnsureStatus(stderr, useCR, i+1, n, label, item.version, "checking…", false)

		result, pullErr := pullAdversary(ctx, item.ref, apiURL, profile, app, io.Discard)
		if pullErr != nil {
			if isContextError(pullErr) {
				if useCR {
					fmt.Fprintln(stderr)
				}
				return pullErr
			}
			failed++
			writeEnsureStatus(stderr, useCR, i+1, n, label, item.version, "failed: "+shortPullError(pullErr), true)
			continue
		}
		if result.AlreadyPresent {
			ready++
			writeEnsureStatus(stderr, useCR, i+1, n, label, item.version, "up to date", true)
			continue
		}
		installed++
		ready++
		writeEnsureStatus(stderr, useCR, i+1, n, label, item.version, "installed", true)
	}

	fmt.Fprintf(stderr, "%d ready", ready)
	if installed > 0 {
		fmt.Fprintf(stderr, " · %d newly installed", installed)
	}
	if failed > 0 {
		fmt.Fprintf(stderr, " · %d failed", failed)
	}
	fmt.Fprintln(stderr)
	if failed > 0 {
		return &accessibleAdversarySyncError{Failed: failed, Total: n}
	}
	return nil
}

type accessibleAdversarySyncError struct {
	Failed int
	Total  int
}

func (e *accessibleAdversarySyncError) Error() string {
	return fmt.Sprintf("failed to install %d of %d accessible adversaries", e.Failed, e.Total)
}

func ensureWriterIsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func writeEnsureStatus(w io.Writer, useCR bool, index, total int, name, version, status string, done bool) {
	mark := "·"
	switch {
	case strings.HasPrefix(status, "failed"):
		mark = "✗"
	case status == "up to date" || status == "installed":
		mark = "✓"
	case strings.Contains(status, "check") || strings.Contains(status, "download") || strings.Contains(status, "pull"):
		mark = "↓"
	}
	line := fmt.Sprintf("  %s  %-24s %-10s %s", mark, truncateRunes(name, 24), truncateRunes(version, 10), status)
	if useCR {
		// Clear line and rewrite in place while in progress; newline when final.
		fmt.Fprintf(w, "\r\033[K%s", line)
		if done {
			fmt.Fprintln(w)
		}
		return
	}
	if done {
		fmt.Fprintln(w, line)
	}
}

func displayAdversaryName(name, ref string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		// Prefer short publisher/name when the catalog includes a full path.
		if short := shortInventoryIdentity(name); short != "" && strings.Contains(name, "/") {
			return short
		}
		return name
	}
	return shortInventoryIdentity(ref)
}

func shortPullError(err error) string {
	msg := err.Error()
	// Keep the useful tail of nested OCI errors.
	for _, prefix := range []string{
		"OCI resolve network: ",
		"OCI get ",
		"pull: ",
	} {
		if i := strings.Index(msg, prefix); i >= 0 {
			msg = msg[i+len(prefix):]
		}
	}
	if len(msg) > 80 {
		return msg[:77] + "..."
	}
	return msg
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	if max == 1 {
		return "…"
	}
	return string(runes[:max-1]) + "…"
}

// shortInventoryIdentity returns publisher/name (last two path segments) or the
// final segment so full registry refs match local short names.
func shortInventoryIdentity(ref string) string {
	key := inventoryIdentityKey(ref)
	if key == "" {
		return ""
	}
	parts := strings.Split(key, "/")
	switch {
	case len(parts) >= 2:
		return strings.ToLower(parts[len(parts)-2] + "/" + parts[len(parts)-1])
	default:
		return strings.ToLower(parts[0])
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// preferCatalogVersion reports whether candidate should replace current for a
// single repository identity. Prefers higher concrete semver over "latest"
// (catalog "latest" often lacks a published mutable tag), then "latest" over
// non-semver, then lexicographic fallback.
func preferCatalogVersion(candidate, current string) bool {
	candidate = strings.TrimSpace(candidate)
	current = strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	left, leftErr := semver.NewVersion(candidate)
	right, rightErr := semver.NewVersion(current)
	if leftErr == nil && rightErr == nil {
		return left.GreaterThan(right)
	}
	if leftErr == nil && rightErr != nil {
		// Concrete semver beats mutable "latest" and other non-semver labels.
		return true
	}
	if leftErr != nil && rightErr == nil {
		return false
	}
	if strings.EqualFold(candidate, "latest") && !strings.EqualFold(current, "latest") {
		return true
	}
	if strings.EqualFold(current, "latest") && !strings.EqualFold(candidate, "latest") {
		return false
	}
	return candidate > current
}

// catalogPullReference returns the reference ensure should pull. Catalog
// entries frequently omit a tag while providing Version separately; untagged
// pulls resolve to :latest and 404 when that tag was never published. When the
// ref is not already tag- or digest-pinned and version is set, append :version.
func catalogPullReference(ref, version string) string {
	ref = strings.TrimSpace(ref)
	version = strings.TrimSpace(version)
	if ref == "" || version == "" {
		return ref
	}
	if strings.Contains(ref, "@") {
		return ref
	}
	if referenceVersionHint(ref) != "" {
		return ref
	}
	// Reject versions that would produce an invalid tag (contain path separators
	// or look like a digest prefix). Catalog versions are short labels.
	if strings.ContainsAny(version, "/@") || strings.HasPrefix(strings.ToLower(version), "sha256:") {
		return ref
	}
	return ref + ":" + version
}

// referenceVersionHint extracts a trailing tag from a reference when the API
// did not supply Version. Digests yield an empty hint.
func referenceVersionHint(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "@") {
		return ""
	}
	colon := strings.LastIndex(ref, ":")
	if colon <= 0 {
		return ""
	}
	if slash := strings.LastIndex(ref, "/"); slash > colon {
		return ""
	}
	return ref[colon+1:]
}

// inventoryIdentityKey strips tag/digest so multiple versions of the same
// repository collapse to one pull target. Pure string form — no oci import
// (cmd handlers must not bypass App reference ports).
func inventoryIdentityKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	// Digest form: name@sha256:...
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	// Tag form: name:tag (colon after the last path segment, not a port).
	if colon := strings.LastIndex(ref, ":"); colon > 0 {
		slash := strings.LastIndex(ref, "/")
		if slash < colon {
			// Keep host:port/path (colon before a later slash); strip only trailing tags.
			ref = ref[:colon]
		}
	}
	return strings.ToLower(ref)
}
