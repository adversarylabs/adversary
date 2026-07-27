package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
)

// ensureAccessibleAdversaries pulls every remote catalog entry the user can
// access so auto detection runs against the full inventory, not only what
// happened to be installed earlier.
//
// Remote catalog failures warn and return nil so offline/local-only use still
// works. Individual pull failures warn and continue.
func ensureAccessibleAdversaries(
	ctx context.Context,
	app *application.App,
	apiURL, profile string,
	stderr io.Writer,
) error {
	deps := app.Dependencies()
	remote, err := fetchRemoteInventory(ctx, deps, apiURL, profile, "")
	if err != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "Warning: could not list remote adversaries (%v); using local store only.\n", err)
		}
		return nil
	}
	if len(remote) == 0 {
		return nil
	}

	// One pull per repository identity (first catalog hit wins; API order preferred).
	seen := make(map[string]struct{}, len(remote))
	targets := make([]string, 0, len(remote))
	for _, item := range remote {
		ref := strings.TrimSpace(item.Reference)
		if ref == "" {
			ref = strings.TrimSpace(item.Name)
		}
		if ref == "" {
			continue
		}
		key := inventoryIdentityKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, ref)
	}
	if len(targets) == 0 {
		return nil
	}

	if stderr != nil {
		fmt.Fprintf(stderr, "Ensuring %d accessible adversaries are installed...\n", len(targets))
	}
	pulled, failed := 0, 0
	for _, ref := range targets {
		if _, err := pullAdversary(ctx, ref, apiURL, profile, app, stderr); err != nil {
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
