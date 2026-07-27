package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	semver "github.com/Masterminds/semver/v3"
	"github.com/adversarylabs/adversary/internal/application"
)

// ensureAccessibleAdversaries installs remote catalog entries that are not
// already present locally so automatic `run` can select from the full
// inventory. Already-installed identities are skipped (no network re-resolve).
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

	localKeys, err := localInstalledIdentityKeys(app)
	if err != nil {
		return err
	}

	targets := make([]string, 0, len(order))
	already := 0
	for _, key := range order {
		ref := best[key].ref
		if identityInstalled(localKeys, ref, best[key].version) {
			already++
			continue
		}
		targets = append(targets, ref)
	}

	if len(targets) == 0 {
		if stderr != nil && already > 0 {
			fmt.Fprintf(stderr, "Catalog: %d accessible adversaries already installed locally.\n", already)
		}
		return nil
	}

	if stderr != nil {
		fmt.Fprintf(stderr, "Installing %d missing adversaries (%d already local)...\n", len(targets), already)
	}
	pulled, failed := 0, 0
	for _, ref := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Quiet per-item progress; summary below. Failures still get a one-line warning.
		var pullLog bytes.Buffer
		if _, err := pullAdversary(ctx, ref, apiURL, profile, app, &pullLog); err != nil {
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
		fmt.Fprintf(stderr, "Installed %d adversaries", pulled)
		if already > 0 {
			fmt.Fprintf(stderr, " (%d already local)", already)
		}
		if failed > 0 {
			fmt.Fprintf(stderr, " (%d pull failures)", failed)
		}
		fmt.Fprintln(stderr)
	}
	return nil
}

func localInstalledIdentityKeys(app *application.App) (map[string]struct{}, error) {
	entries, err := app.Dependencies().Resolver.Entries(10000)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(entries)*4)
	for _, entry := range entries {
		for _, candidate := range []string{entry.CanonicalReference, entry.Record.Name} {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if k := inventoryIdentityKey(candidate); k != "" {
				keys[k] = struct{}{}
			}
			if k := shortInventoryIdentity(candidate); k != "" {
				keys[k] = struct{}{}
			}
			// Also key name@version so versioned catalog refs can match records.
			if v := strings.TrimSpace(entry.Record.Version); v != "" && entry.Record.Name != "" {
				keys[strings.ToLower(entry.Record.Name)+"@"+v] = struct{}{}
			}
		}
	}
	return keys, nil
}

func identityInstalled(localKeys map[string]struct{}, ref, version string) bool {
	if len(localKeys) == 0 {
		return false
	}
	if k := inventoryIdentityKey(ref); k != "" {
		if _, ok := localKeys[k]; ok {
			return true
		}
	}
	if k := shortInventoryIdentity(ref); k != "" {
		if _, ok := localKeys[k]; ok {
			return true
		}
	}
	// Prefer exact name@version when catalog supplies a version.
	version = strings.TrimSpace(version)
	if version != "" {
		name := shortInventoryIdentity(ref)
		if name != "" {
			if _, ok := localKeys[strings.ToLower(name)+"@"+version]; ok {
				return true
			}
		}
	}
	return false
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
