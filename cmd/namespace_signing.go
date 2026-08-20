package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/namespacesig"
	"github.com/adversarylabs/adversary/pkg/oci"
)

// attachHostedNamespaceSignature makes signing part of the hosted-registry
// publish transaction from the user's perspective. External registries never
// enter this path and therefore remain untrusted by default.
type hostedNamespaceSignature struct {
	SignatureDigest string
	TrustDigest     string
}

func attachHostedNamespaceSignature(ctx context.Context, app *application.App, registry application.OCIRegistry, ref oci.Reference, digest, apiURL, profile string, stderr io.Writer) (*hostedNamespaceSignature, error) {
	deps := app.Dependencies()
	if !isHostedNamespaceRegistry(ref.Registry) {
		return nil, nil
	}
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	if err != nil || !ok {
		return nil, err
	}
	namespace := cleanRegistryNamespace(registryNamespaceFromAuth(auth, deps.RegistryNS))
	owner, _, _ := strings.Cut(ref.Repository, "/")
	if namespace == "" || !strings.EqualFold(owner, namespace) {
		return nil, nil
	}

	client := adversarylabs.NewClientWithBaseURL(adversarylabs.ConfigStore{}, apiURL)
	var result namespacesig.SigningResult
	for attempt := 0; attempt < 6; attempt++ {
		result, err = client.SignNamespaceDigest(ctx, auth.Token, ref.Repository, digest)
		if err == nil || !strings.Contains(err.Error(), "409") {
			break
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err != nil {
		return nil, fmt.Errorf("automatically sign hosted private adversary: %w", err)
	}
	root := namespacesig.Root{KeyID: result.TrustBundle.RootKeyID, PublicKey: result.RootPublicKey}
	if err := namespacesig.Verify(result.Envelope, result.TrustBundle, ref.Registry, ref.Repository, digest, root); err != nil {
		return nil, fmt.Errorf("verify platform namespace signature before publish: %w", err)
	}
	envelope, err := namespacesig.MarshalEnvelope(result.Envelope)
	if err != nil {
		return nil, err
	}
	trust, err := namespacesig.MarshalTrustBundle(result.TrustBundle)
	if err != nil {
		return nil, err
	}
	signatureDigest, _, err := registry.PushAttachedReferrer(ctx, ref, digest, namespacesig.SignatureMediaType, "namespace-signature.json", namespacesig.SignatureArtifactKind, envelope)
	if err != nil {
		return nil, err
	}
	trustDigest, _, err := registry.PushAttachedReferrer(ctx, ref, digest, namespacesig.TrustMediaType, "namespace-trust.json", namespacesig.TrustArtifactKind, trust)
	if err != nil {
		return nil, err
	}
	if err := deps.Repository.SaveNamespaceSignature(digest, envelope, trust, root); err != nil && stderr != nil {
		fmt.Fprintf(stderr, "Warning: could not cache namespace signature locally: %v\n", err)
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "Platform namespace signature verified and published")
	}
	return &hostedNamespaceSignature{SignatureDigest: signatureDigest, TrustDigest: trustDigest}, nil
}

func isHostedNamespaceRegistry(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == adversarylabs.DefaultRegistry ||
		strings.HasSuffix(host, ".adversarylabs.ai") ||
		host == "localhost" || hasLocalhostPort(host)
}
