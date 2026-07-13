package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/spf13/cobra"
)

func readSmallSource(src blobsource.Source, limit int64) ([]byte, error) {
	if src == nil {
		return nil, nil
	}
	if src.Size() > limit {
		return nil, fmt.Errorf("metadata exceeds %d byte limit", limit)
	}
	r, err := src.Open()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(r, limit+1))
	return data, errors.Join(readErr, r.Close())
}

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

func pushUnified(ctx context.Context, app *application.App, resolver application.Resolver, stdout, stderr io.Writer, args []string, apiURL, profile, format string) (_ bool, retErr error) {
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
	lease, err := resolver.PayloadSources(resolution.Record)
	if err != nil {
		return true, err
	}
	leaseOpen := true
	defer func() {
		if leaseOpen {
			retErr = errors.Join(retErr, lease.Close())
		}
	}()
	manifest, err := readSmallSource(lease.Manifest, 4<<20)
	if err != nil {
		return true, err
	}
	yaml, err := readSmallSource(lease.AdversaryManifest, 1<<20)
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
	ref, err := app.Dependencies().References.Parse(remote)
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
	digest, err := registry.PushSources(ctx, ref, manifest, lease.Blobs)
	if err != nil {
		return true, err
	}
	localManifestDigest := lease.Manifest.Digest()
	if err := lease.Close(); err != nil {
		return true, fmt.Errorf("release local payload after upload: %w", err)
	}
	leaseOpen = false
	if digest != localManifestDigest {
		if _, importErr := resolver.CommitEquivalentManifest(resolution.Record.Digest, digest, manifest); importErr != nil {
			return true, fmt.Errorf("commit registry manifest digest %s: %w", digest, importErr)
		}
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
