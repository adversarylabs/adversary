package cmd

import (
	"errors"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/spf13/cobra"
	"os"
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
			resolver := app.Dependencies().Resolver
			ref, err := oci.ParseReference(args[0])
			if err != nil {
				return err
			}
			registry, err := app.Dependencies().Registries.New(valueOf(apiURL), valueOf(profile))
			if err != nil {
				return err
			}
			if ref.Registry == "localhost" || hasLocalhostPort(ref.Registry) {
				registry.SetPlainHTTP(true)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Pulling manifest...")
			fmt.Fprintln(cmd.ErrOrStderr())
			digest, err := registry.Resolve(cmd.Context(), ref)
			if err != nil {
				return err
			}
			if existing, resolveErr := resolver.ResolveRecord(digest); resolveErr == nil {
				if err := registerExactRef(resolver, ref.Locator(), existing.Digest); err != nil {
					return err
				}
				if resolved == "json" {
					return writeJSON(cmd.OutOrStdout(), "pull", pullDTO{existing.Name, existing.Version, ref.Locator(), existing.Digest})
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Installed: %s\nVersion: %s\nCanonical reference: %s\nDigest: %s\n", existing.Name, existing.Version, ref.Locator(), existing.Digest)
				return nil
			} else if !os.IsNotExist(resolveErr) {
				return resolveErr
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Downloading layers...")
			artifact, err := registry.PullSources(cmd.Context(), ref)
			if err != nil {
				return err
			}
			var adversarySource blobsource.Source
			if len(artifact.AdversaryManifest) > 0 {
				adversarySource = blobsource.Bytes(artifact.AdversaryManifest)
			}
			unified, importErr := resolver.ImportSources(repository.SourceImport{Reference: ref.Locator(), Name: artifact.Manifest.Annotations["ai.adversary.full_name"], Version: artifact.Manifest.Annotations["ai.adversary.version"], Manifest: blobsource.Bytes(artifact.RawManifest), Blobs: artifact.Blobs, AdversaryManifest: adversarySource})
			if err := errors.Join(importErr, artifact.Close()); err != nil {
				return err
			}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "pull", pullDTO{unified.Name, unified.Version, ref.Locator(), unified.Digest})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed: %s\nVersion: %s\nCanonical reference: %s\nDigest: %s\n", unified.Name, unified.Version, ref.Locator(), unified.Digest)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}
func registerExactRef(resolver application.Resolver, ref, digest string) error {
	current, err := resolver.ResolveRecord(ref)
	if err == nil {
		if current.Digest == digest {
			return nil
		}
		return fmt.Errorf("%w: %s currently points to %s", repository.ErrCAS, ref, current.Digest)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return resolver.UpdateRef(ref, "", digest)
}
