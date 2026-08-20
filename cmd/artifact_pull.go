package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/namespacesig"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/officialsig"
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

// registerExactRef points the durable local reference at digest, creating or
// CAS-updating the tag (including :latest) so subsequent runs resolve the
// newly pulled content.
func registerExactRef(resolver application.Resolver, ref, digest string) error {
	current, err := resolver.ResolveRecord(ref)
	if err == nil {
		if current.Digest == digest {
			return nil
		}
		if updateErr := resolver.UpdateRef(ref, current.Digest, digest); updateErr != nil {
			return fmt.Errorf("retarget %s from %s to %s: %w", ref, current.Digest, digest, updateErr)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if createErr := resolver.UpdateRef(ref, "", digest); createErr != nil {
		return fmt.Errorf("create local reference %s -> %s: %w", ref, digest, createErr)
	}
	return nil
}

// registerVersionRef also pins registry/name:version when the pulled tag was
// mutable (e.g. :latest). Without this, alias indexes may list name:version
// while no durable FQ refs/<hash>.json exists, and run fails looking up the
// expanded reference.
func registerVersionRef(resolver application.Resolver, pulled oci.Reference, rec repository.Record) error {
	version := strings.TrimSpace(rec.Version)
	if version == "" || strings.EqualFold(version, "latest") {
		return nil
	}
	if pulled.Tag == version && pulled.Digest == "" {
		// Already registered as the exact version tag.
		return nil
	}
	versionRef := oci.Reference{
		Registry:   pulled.Registry,
		Repository: pulled.Repository,
		Tag:        version,
	}
	locator := versionRef.Locator()
	if locator == "" || locator == pulled.Locator() {
		return nil
	}
	if err := registerExactRef(resolver, locator, rec.Digest); err != nil {
		return fmt.Errorf("register version reference %s: %w", locator, err)
	}
	return nil
}

type pullResult struct {
	Record         repository.Record
	Reference      oci.Reference
	AlreadyPresent bool // true when the resolved digest was already in the local store
}

// pullAdversary resolves a mutable reference once (to its current digest) and
// returns the exact record installed for that digest. The resolved digest is
// pinned for any download so PullSources does not re-resolve a mutable tag.
// Both explicit pulls and run's auto-pull use this result.
func pullAdversary(ctx context.Context, refStr, apiURL, profile string, app *application.App, stderr io.Writer) (pullResult, error) {
	if stderr == nil {
		stderr = io.Discard
	}
	refStr = canonicalCatalogReference(refStr)
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
		// Also pin name:version so `adversary run go/concurrency:0.0.10` has a
		// durable FQ ref, not only an alias index entry.
		if err := registerVersionRef(resolver, ref, existing); err != nil {
			return pullResult{}, err
		}
		if !app.Dependencies().Repository.HasVerifiedOfficialSignature(existing.Digest) &&
			!app.Dependencies().Repository.HasVerifiedNamespaceSignature(existing.Digest, ref.Registry, ref.Repository) {
			if err := fetchAndStoreArtifactTrust(ctx, app, registry, ref, existing.Digest, apiURL, profile, stderr); err != nil {
				fmt.Fprintf(stderr, "Warning: trusted signature not stored (%v)\n", err)
			}
		}
		// best-effort pull metric (AMB-8); respects telemetry opt-out env vars
		reportPull(ctx, app, apiURL, profile, ref.Locator(), existing.Digest)
		return pullResult{Record: existing, Reference: ref, AlreadyPresent: true}, nil
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
	// Install content without binding the caller's tag in ImportSources.
	// ImportSources rejects retargeting a tag that already points at a different
	// digest (CAS). Pulls of mutable tags such as :latest must overwrite the
	// local pointer after content is installed.
	unified, importErr := resolver.ImportSources(repository.SourceImport{
		Reference:         "",
		Name:              artifact.Manifest.Annotations["ai.adversary.full_name"],
		Version:           artifact.Manifest.Annotations["ai.adversary.version"],
		Manifest:          manifestSource,
		Blobs:             artifact.Blobs,
		AdversaryManifest: adversarySource,
	})
	if err := errors.Join(importErr, artifact.Close()); err != nil {
		return pullResult{}, err
	}
	if err := registerExactRef(resolver, ref.Locator(), unified.Digest); err != nil {
		return pullResult{}, fmt.Errorf("update local reference %s: %w", ref.Locator(), err)
	}
	if err := registerVersionRef(resolver, ref, unified); err != nil {
		return pullResult{}, err
	}
	// Best-effort: fetch and store a verified signature so host-exec trust works offline.
	if err := fetchAndStoreArtifactTrust(ctx, app, registry, ref, unified.Digest, apiURL, profile, stderr); err != nil {
		fmt.Fprintf(stderr, "Warning: trusted signature not stored (%v)\n", err)
	}
	// best-effort pull metric (AMB-8); respects telemetry opt-out env vars
	reportPull(ctx, app, apiURL, profile, ref.Locator(), unified.Digest)
	return pullResult{Record: unified, Reference: ref, AlreadyPresent: false}, nil
}

func fetchAndStoreArtifactTrust(ctx context.Context, app *application.App, registry application.OCIRegistry, ref oci.Reference, digest, apiURL, profile string, stderr io.Writer) error {
	officialErr := fetchAndStoreOfficialSignature(ctx, app, registry, ref, digest, stderr)
	if officialErr == nil {
		return nil
	}
	namespaceErr := fetchAndStoreNamespaceSignature(ctx, app, registry, ref, digest, apiURL, profile, stderr)
	if namespaceErr == nil {
		return nil
	}
	return fmt.Errorf("official: %v; namespace: %v", officialErr, namespaceErr)
}

func fetchAndStoreOfficialSignature(ctx context.Context, app *application.App, registry application.OCIRegistry, ref oci.Reference, digest string, stderr io.Writer) error {
	data, err := registry.GetOfficialSignatureReferrer(ctx, ref, digest)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no official signature referrer")
	}
	env, err := officialsig.ParseEnvelope(data)
	if err != nil {
		return err
	}
	if err := officialsig.Verify(env, digest, officialsig.DefaultKeyring()); err != nil {
		return err
	}
	raw, err := officialsig.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	if err := app.Dependencies().Repository.SaveOfficialSignature(digest, raw); err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "Official signature verified and stored.")
	}
	return nil
}

func fetchAndStoreNamespaceSignature(ctx context.Context, app *application.App, registry application.OCIRegistry, ref oci.Reference, digest, apiURL, profile string, stderr io.Writer) error {
	deps := app.Dependencies()
	if !isHostedNamespaceRegistry(ref.Registry) {
		return fmt.Errorf("namespace trust is not available from external registry %s", ref.Registry)
	}
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(auth.Token) == "" {
		return fmt.Errorf("namespace trust requires an authenticated profile")
	}
	envelopeData, err := registry.GetNamespaceSignatureReferrer(ctx, ref, digest)
	if err != nil {
		return err
	}
	trustData, err := registry.GetNamespaceTrustReferrer(ctx, ref, digest)
	if err != nil {
		return err
	}
	if len(envelopeData) == 0 || len(trustData) == 0 {
		return fmt.Errorf("namespace signature referrers are missing")
	}
	envelope, err := namespacesig.ParseEnvelope(envelopeData)
	if err != nil {
		return err
	}
	bundle, err := namespacesig.ParseTrustBundle(trustData)
	if err != nil {
		return err
	}
	client := adversarylabs.NewClientWithBaseURL(adversarylabs.ConfigStore{}, apiURL)
	root, err := client.NamespaceTrustRoot(ctx, auth.Token)
	if err != nil {
		return err
	}
	if err := namespacesig.Verify(envelope, bundle, ref.Registry, ref.Repository, digest, root); err != nil {
		return err
	}
	if err := deps.Repository.SaveNamespaceSignature(digest, envelopeData, trustData, root); err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "Team namespace signature verified and stored.")
	}
	return nil
}
