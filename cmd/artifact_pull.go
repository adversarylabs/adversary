package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/spf13/cobra"
)

func newPullCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull and install an adversary from an OCI registry",
		Example: `  adversary pull security-reviewer
  adversary pull adversarylabs/security-reviewer
  adversary pull ghcr.io/acme/security-reviewer
  adversary pull localhost:5000/security-reviewer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, legacyJSON)
			if err != nil {
				return err
			}
			if legacyJSON {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}

			pulled, err := pullAdversary(cmd.Context(), args[0], valueOf(apiURL), valueOf(profile), app, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			result := pullDTO{Name: pulled.Record.Name, Version: pulled.Record.Version, Tag: pulled.Reference.Tag, CanonicalReference: pulled.Reference.Locator(), Digest: pulled.Record.Digest}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "pull", result)
			}
			return writePullText(cmd.OutOrStdout(), result)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}

func writePullText(w io.Writer, result pullDTO) error {
	if _, err := fmt.Fprintf(w, "Installed: %s\nVersion: %s\n", result.Name, result.Version); err != nil {
		return err
	}
	if result.Tag != "" {
		if _, err := fmt.Fprintf(w, "Tag: %s\n", result.Tag); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "Canonical reference: %s\nDigest: %s\n", result.CanonicalReference, result.Digest)
	return err
}

func pulledMetadataSources(artifact *oci.PulledSources) (blobsource.Source, blobsource.Source, error) {
	if artifact == nil {
		return nil, nil, fmt.Errorf("pulled artifact is required")
	}
	manifest, err := pulledByteSource(artifact.RawManifest, artifact.ManifestDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("bind pulled manifest digest: %w", err)
	}
	if len(artifact.AdversaryManifest) == 0 && artifact.AdversaryManifestDigest == "" {
		return manifest, nil, nil
	}
	adversaryManifest, err := pulledByteSource(artifact.AdversaryManifest, artifact.AdversaryManifestDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("bind pulled adversary manifest digest: %w", err)
	}
	return manifest, adversaryManifest, nil
}

func pulledByteSource(data []byte, digest string) (blobsource.Source, error) {
	if err := oci.VerifyDigest(data, digest); err != nil {
		return nil, err
	}
	return blobsource.New(int64(len(data)), digest, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

func registerExactRef(resolver application.Resolver, ref, digest string) error {
	current, err := resolver.ResolveRecord(ref)
	if err == nil {
		if current.Digest == digest {
			return nil
		}
		return resolver.UpdateRef(ref, current.Digest, digest)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return resolver.UpdateRef(ref, "", digest)
}

type pullResult struct {
	Record    repository.Record
	Reference oci.Reference
}

// pullAdversary resolves a mutable reference once (to its current digest) and
// returns the exact record installed for that digest. The resolved digest is
// pinned for any download so PullSources does not re-resolve a mutable tag.
// Both explicit pulls and run's auto-pull use this result.
func pullAdversary(ctx context.Context, refStr, apiURL, profile string, app *application.App, stderr io.Writer) (pullResult, error) {
	resolver := app.Dependencies().Resolver
	ref, err := app.Dependencies().References.Parse(refStr)
	if err != nil {
		return pullResult{}, err
	}
	registry, err := app.Dependencies().Registries.New(apiURL, profile)
	if err != nil {
		return pullResult{}, err
	}
	if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
		registry.SetPlainHTTP(true)
	}
	fmt.Fprintln(stderr, "Pulling manifest...")
	fmt.Fprintln(stderr)
	digest, err := registry.Resolve(ctx, ref)
	if err != nil {
		return pullResult{}, err
	}
	// Pin the resolved digest so PullSources uses exactly this digest for a mutable
	// tag (resolves the mutable reference once, avoiding a second tag resolution
	// that could see yet another digest).
	pinned := ref
	pinned.Tag = ""
	pinned.Digest = digest
	if existing, resolveErr := resolver.ResolveRecord(digest); resolveErr == nil {
		if err := registerExactRef(resolver, ref.Locator(), existing.Digest); err != nil {
			return pullResult{}, err
		}
		// best-effort pull metric (AMB-8)
		reportPull(ctx, app, apiURL, profile, ref.Locator(), existing.Digest)
		return pullResult{Record: existing, Reference: ref}, nil
	} else if !os.IsNotExist(resolveErr) {
		return pullResult{}, resolveErr
	}

	fmt.Fprintln(stderr, "Downloading layers...")
	artifact, err := registry.PullSources(ctx, pinned)
	if err != nil {
		return pullResult{}, err
	}
	manifestSource, adversarySource, sourceErr := pulledMetadataSources(artifact)
	if sourceErr != nil {
		return pullResult{}, errors.Join(sourceErr, artifact.Close())
	}
	unified, importErr := resolver.ImportSources(repository.SourceImport{Reference: ref.Locator(), Name: artifact.Manifest.Annotations["ai.adversary.full_name"], Version: artifact.Manifest.Annotations["ai.adversary.version"], Manifest: manifestSource, Blobs: artifact.Blobs, AdversaryManifest: adversarySource})
	if err := errors.Join(importErr, artifact.Close()); err != nil {
		return pullResult{}, err
	}
	// best-effort pull metric (AMB-8)
	reportPull(ctx, app, apiURL, profile, ref.Locator(), unified.Digest)
	return pullResult{Record: unified, Reference: ref}, nil
}

// reportPull records a pull metric best-effort. Errors are swallowed so they never break pull.
func reportPull(ctx context.Context, app *application.App, apiURL, profile, reference, digest string) {
	if reference == "" {
		return
	}
	deps := app.Dependencies()
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	if err != nil || !ok || auth.Token == "" {
		return
	}
	client := deps.API.New(apiURL)
	_ = client.RecordPull(ctx, auth.Token, reference, digest)
}
