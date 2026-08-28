package namespacesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestVerifyDelegatedNamespaceSignature(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	teamPublic, teamPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := TrustBundle{SpecVersion: 1, MediaType: TrustMediaType, Namespace: "example-team", TeamID: "team-123", KeyID: "namespace:team-123:v1", PublicKey: base64.StdEncoding.EncodeToString(teamPublic), IssuedAt: "2026-08-20T12:00:00.000Z", RootKeyID: "namespace-root:v1"}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(rootPrivate, trustMessage(bundle)))
	envelope := Envelope{SpecVersion: 1, MediaType: SignatureMediaType, Registry: "registry.adversarylabs.ai", Repository: "example-team/reviewer", Namespace: bundle.Namespace, TeamID: bundle.TeamID, SubjectDigest: "sha256:" + repeat("ab", 32), KeyID: bundle.KeyID, SignedAt: bundle.IssuedAt}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(teamPrivate, signatureMessage(envelope)))
	root := Root{KeyID: bundle.RootKeyID, PublicKey: base64.StdEncoding.EncodeToString(rootPublic)}

	if err := Verify(envelope, bundle, envelope.Registry, envelope.Repository, envelope.SubjectDigest, root); err != nil {
		t.Fatal(err)
	}
	envelope.SubjectDigest = "sha256:" + repeat("cd", 32)
	if err := Verify(envelope, bundle, envelope.Registry, envelope.Repository, envelope.SubjectDigest, root); err == nil {
		t.Fatal("tampered digest verified")
	}
}

func TestVerifyDelegatedNestedNamespaceSignature(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	teamPublic, teamPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := TrustBundle{SpecVersion: 1, MediaType: TrustMediaType, Namespace: "adversarylabs", TeamID: "team-123", KeyID: "namespace:team-123:v1", PublicKey: base64.StdEncoding.EncodeToString(teamPublic), IssuedAt: "2026-08-20T12:00:00.000Z", RootKeyID: "namespace-root:v1"}
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(rootPrivate, trustMessage(bundle)))
	envelope := Envelope{SpecVersion: 1, MediaType: SignatureMediaType, Registry: "registry.adversarylabs.ai", Repository: "adversarylabs/go/security", Namespace: bundle.Namespace, TeamID: bundle.TeamID, SubjectDigest: "sha256:" + repeat("ab", 32), KeyID: bundle.KeyID, SignedAt: bundle.IssuedAt}
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(teamPrivate, signatureMessage(envelope)))
	root := Root{KeyID: bundle.RootKeyID, PublicKey: base64.StdEncoding.EncodeToString(rootPublic)}

	if err := Verify(envelope, bundle, envelope.Registry, envelope.Repository, envelope.SubjectDigest, root); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPlatformTypeScriptVector(t *testing.T) {
	const raw = `{"signature":{"specVersion":1,"mediaType":"application/vnd.adversarylabs.namespace-signature.v1+json","registry":"registry.adversarylabs.ai","repository":"example-team/reviewer","namespace":"example-team","teamId":"team-123","subjectDigest":"sha256:abababababababababababababababababababababababababababababababab","keyId":"namespace:team-123:v1","signedAt":"2026-08-20T12:00:00.000Z","signature":"iaXo4PDimmci/g6vldzIggNuIzKc559XhLz+rYRfTRNbVyGY203vrsLH8jqoaJEKvKNCpUUoPr7+LfdmAYs0BQ=="},"trustBundle":{"specVersion":1,"mediaType":"application/vnd.adversarylabs.namespace-trust.v1+json","namespace":"example-team","teamId":"team-123","keyId":"namespace:team-123:v1","publicKey":"FTDUQsnJYb0H3ywOfLhT2I6bF3PjWMIxZfPFOTMwipo=","issuedAt":"2026-08-20T12:00:00.000Z","rootKeyId":"namespace-root:v1","signature":"oaHAfiZGuywnPI6EjA+hbkzYyqGhlGkBSQn81EN5CkcYbSSy7kuY+jVVXDvJTspl29hgSDB+CGR3l7u0O0JCBA=="},"rootPublicKey":"GDVDi4Fx/Rd7RhGE2/w3oq8gva+S4pp6kBBphtVILH8="}`
	var result SigningResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	root := Root{KeyID: result.TrustBundle.RootKeyID, PublicKey: result.RootPublicKey}
	if err := Verify(result.Envelope, result.TrustBundle, result.Envelope.Registry, result.Envelope.Repository, result.Envelope.SubjectDigest, root); err != nil {
		t.Fatalf("TypeScript signature did not verify in Go: %v", err)
	}
	if err := Verify(result.Envelope, result.TrustBundle, "ghcr.io", result.Envelope.Repository, result.Envelope.SubjectDigest, root); err == nil {
		t.Fatal("copying the signature to GHCR inherited hosted-registry trust")
	}
}

func repeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
