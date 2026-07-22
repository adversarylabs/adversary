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

			// Delegate to shared pullAdversary helper (AMB-11 enables auto-pull in run command).
			if err := pullAdversary(cmd.Context(), args[0], valueOf(apiURL), valueOf(profile), app, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return err
			}

			resolver := app.Dependencies().Resolver
			ref, err := app.Dependencies().References.Parse(args[0])
			if err != nil {
				return err
			}
			registry, err := app.Dependencies().Registries.New(valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
			digest, err := registry.Resolve(cmd.Context(), ref)
			if err != nil {
				return err
			}
			rec, err := resolver.ResolveRecord(digest)
			if err != nil {
				return err
			}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "pull", pullDTO{Name: rec.Name, Version: rec.Version, Tag: ref.Tag, CanonicalReference: ref.Locator(), Digest: rec.Digest})
			}
			return writePullText(cmd.OutOrStdout(), pullDTO{Name: rec.Name, Version: rec.Version, Tag: ref.Tag, CanonicalReference: ref.Locator(), Digest: rec.Digest})
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

// pullAdversary performs the core pull/install for a reference.
// Shared between `adversary pull` and auto-pull inside `adversary run` (see AMB-11).
// Status is printed to stderr; on success for auto-pull we return silently after import.
// The caller (pull cmd) can still emit the final Installed text.
func pullAdversary(ctx context.Context, refStr, apiURL, profile string, app *application.App, stdout, stderr io.Writer) error {
	resolver := app.Dependencies().Resolver
	ref, err := app.Dependencies().References.Parse(refStr)
	if err != nil {
		return err
	}
	registry, err := app.Dependencies().Registries.New(apiURL, profile)
	if err != nil {
		return err
	}
	if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
		registry.SetPlainHTTP(true)
	}
	fmt.Fprintln(stderr, "Pulling manifest...")
	fmt.Fprintln(stderr)
	digest, err := registry.Resolve(ctx, ref)
	if err != nil {
		return err
	}
	if existing, resolveErr := resolver.ResolveRecord(digest); resolveErr == nil {
		if err := registerExactRef(resolver, ref.Locator(), existing.Digest); err != nil {
			return err
		}
		// success early (already present or registered); explicit pull caller will print result
		return nil
	} else if !os.IsNotExist(resolveErr) {
		return resolveErr
	}

	fmt.Fprintln(stderr, "Downloading layers...")
	artifact, err := registry.PullSources(ctx, ref)
	if err != nil {
		return err
	}
	manifestSource, adversarySource, sourceErr := pulledMetadataSources(artifact)
	if sourceErr != nil {
		return errors.Join(sourceErr, artifact.Close())
	}
	unified, importErr := resolver.ImportSources(repository.SourceImport{Reference: ref.Locator(), Name: artifact.Manifest.Annotations["ai.adversary.full_name"], Version: artifact.Manifest.Annotations["ai.adversary.version"], Manifest: manifestSource, Blobs: artifact.Blobs, AdversaryManifest: adversarySource})
	if err := errors.Join(importErr, artifact.Close()); err != nil {
		return err
	}
	_ = unified // explicit pull path uses it for output DTO
	return nil
}
