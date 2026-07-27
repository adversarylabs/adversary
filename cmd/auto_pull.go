package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"github.com/adversarylabs/adversary/internal/application"
)

// ensureAccessibleAdversaries pulls every remote catalog entry the user can
// access so automatic `run` (no adversary refs) detects against the full
// inventory, not only what happened to be installed earlier.
//
// Remote catalog failures warn and return nil so offline/local-only use still
// works, except context cancellation/deadline which always propagate.
// Individual non-cancellation pull failures warn and continue.
func ensureAccessibleAdversaries(
	ctx context.Context,
	app *application.App,
	apiURL, profile string,
	stderr io.Writer,
) error {
	deps := app.Dependencies()
	remote, err := fetchRemoteInventory(ctx, deps, apiURL, profile, "")
	if err != nil {
		if isContextError(err) {
			return err
		}
		if stderr != nil {
			fmt.Fprintf(stderr, "Warning: could not list remote adversaries (%v); using local store only.\n", err)
		}
		return nil
	}
	if len(remote) == 0 {
		return nil
	}

	// One pull per repository identity, preferring the newest catalog version
	// (not first-hit order, which can install a stale tag).
	type chosen struct {
		ref     string
		version string
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
		if prev, ok := best[key]; ok {
			if !preferCatalogVersion(version, prev.version) {
				continue
			}
			best[key] = chosen{ref: ref, version: version}
			continue
		}
		best[key] = chosen{ref: ref, version: version}
		order = append(order, key)
	}
	if len(order) == 0 {
		return nil
	}

	targets := make([]string, 0, len(order))
	for _, key := range order {
		targets = append(targets, best[key].ref)
	}

	if stderr != nil {
		fmt.Fprintf(stderr, "Ensuring %d accessible adversaries are installed...\n", len(targets))
	}
	pulled, failed := 0, 0
	for _, ref := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := pullAdversary(ctx, ref, apiURL, profile, app, stderr); err != nil {
			if isContextError(err) {
				return err
			}
			failed++
			if stderr != nil {
				fmt.Fprintf(stderr, "Warning: pull %s failed: %v\n", ref, err)
			}
			continue
		}
		pulled++
	}
	if stderr != nil {
		fmt.Fprintf(stderr, "Installed or verified %d adversaries", pulled)
		if failed > 0 {
			fmt.Fprintf(stderr, " (%d pull failures)", failed)
		}
		fmt.Fprintln(stderr)
	}
	return nil
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// preferCatalogVersion reports whether candidate should replace current for a
// single repository identity. Prefers "latest", then higher semver, then
// lexicographic fallback when versions are not semver.
func preferCatalogVersion(candidate, current string) bool {
	candidate = strings.TrimSpace(candidate)
	current = strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	if strings.EqualFold(candidate, "latest") && !strings.EqualFold(current, "latest") {
		return true
	}
	if strings.EqualFold(current, "latest") && !strings.EqualFold(candidate, "latest") {
		return false
	}
	left, leftErr := semver.NewVersion(candidate)
	right, rightErr := semver.NewVersion(current)
	if leftErr == nil && rightErr == nil {
		return left.GreaterThan(right)
	}
	return candidate > current
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
