package cmd

import (
	"context"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func newPushCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "push <local-ref> [remote-ref]",
		Short: "Push a locally packed adversary to an OCI registry",
		Example: `  adversary push dockerfile-reviewer:0.1.0
  adversary push security-reviewer:0.1.0 ghcr.io/acme/security-reviewer:0.1.0
  adversary push sha256:abc123 ghcr.io/acme/security-reviewer:0.1.0
  adversary push ghcr.io/acme/security-reviewer:0.1.0`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, legacyJSON)
			if err != nil {
				return err
			}
			if legacyJSON {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			resolver := app.Dependencies().Resolver
			_, err = pushUnified(cmd.Context(), app, resolver, cmd.OutOrStdout(), cmd.ErrOrStderr(), args, valueOf(apiURL), valueOf(profile), resolved)
			return err
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}

func pushUnified(ctx context.Context, app *application.App, resolver application.Resolver, stdout, stderr io.Writer, args []string, apiURL, profile, format string) (bool, error) {
	hasExact, _ := resolver.HasExact(args[0])
	resolution, err := resolver.Lookup(ctx, args[0])
	if err != nil {
		if os.IsNotExist(err) && !hasExact {
			return true, fmt.Errorf("artifact %q is not present in the unified repository", args[0])
		}
		return true, err
	}
	if resolution.Local {
		return true, fmt.Errorf("artifact %q is not present in the unified repository", args[0])
	}
	manifest, blobs, yaml, err := resolver.Payload(resolution.Record)
	if err != nil {
		return true, err
	}
	remote := args[0]
	if len(args) == 2 {
		remote = args[1]
	} else if !hasExplicitRegistry(args[0]) {
		remote, err = defaultAdversaryLabsPushRef(ctx, app.Dependencies(), args[0], pushRecord{Name: resolution.Record.Name, ManifestName: resolution.Record.Name, Version: resolution.Record.Version, Digest: resolution.Record.Digest}, apiURL, profile)
		if err != nil {
			return true, err
		}
	}
	ref, err := oci.ParseReference(remote)
	if err != nil {
		return true, err
	}
	registry, err := app.Dependencies().Registries.New(apiURL, profile)
	if err != nil {
		return true, err
	}
	if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
		registry.SetPlainHTTP(true)
	}
	fmt.Fprintf(stderr, "Pushing %s (%s) to %s\n", resolution.CanonicalReference, resolution.Digest, ref.Locator())
	digest, err := registry.Push(ctx, ref, manifest, blobs)
	if err != nil {
		return true, err
	}
	artifactDigest, _, err := registry.PushAdversaryManifestReferrer(ctx, ref, digest, yaml)
	if err != nil {
		return true, err
	}
	if err := registerExactRef(resolver, ref.Locator(), digest); err != nil {
		return true, err
	}
	if format == "json" {
		return true, writeJSON(stdout, "push", pushDTO{ref.Locator(), digest, artifactDigest})
	}
	fmt.Fprintf(stdout, "Canonical reference: %s\nImage digest\n\n%s\nDigest: %s\nPublished adversary manifest referrer\n\n%s\n", ref.Locator(), digest, digest, artifactDigest)
	return true, nil
}
