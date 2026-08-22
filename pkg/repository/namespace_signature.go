package repository

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/adversarylabs/adversary/pkg/namespacesig"
)

type namespaceSignatureEvidence struct {
	Envelope    namespacesig.Envelope    `json:"signature"`
	TrustBundle namespacesig.TrustBundle `json:"trustBundle"`
	Root        namespacesig.Root        `json:"root"`
}

// SaveNamespaceSignature stores only already-verified evidence. The root is a
// public key fetched over the authenticated Adversary Labs API connection.
func (r Repository) SaveNamespaceSignature(digest string, envelopeData, trustData []byte, root namespacesig.Root) error {
	if err := r.init(); err != nil {
		return err
	}
	envelope, err := namespacesig.ParseEnvelope(envelopeData)
	if err != nil {
		return err
	}
	bundle, err := namespacesig.ParseTrustBundle(trustData)
	if err != nil {
		return err
	}
	if err := namespacesig.Verify(envelope, bundle, envelope.Registry, envelope.Repository, digest, root); err != nil {
		return err
	}
	data, err := json.Marshal(namespaceSignatureEvidence{Envelope: envelope, TrustBundle: bundle, Root: root})
	if err != nil {
		return err
	}
	return r.atomic(namespaceSignaturePath(digest, envelope.Registry, envelope.Repository), data)
}

func (r Repository) HasVerifiedNamespaceSignature(digest, registry, repository string) bool {
	if err := r.init(); err != nil {
		return false
	}
	data, err := r.read(namespaceSignaturePath(digest, registry, repository))
	if err != nil {
		return false
	}
	var evidence namespaceSignatureEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return false
	}
	return namespacesig.Verify(evidence.Envelope, evidence.TrustBundle, registry, repository, digest, evidence.Root) == nil
}

func (r Repository) LoadNamespaceSignature(digest, registry, repository string) ([]byte, error) {
	if err := r.init(); err != nil {
		return nil, err
	}
	if digest == "" {
		return nil, fmt.Errorf("digest is required")
	}
	return r.read(namespaceSignaturePath(digest, registry, repository))
}

func namespaceSignaturePath(digest, registry, repository string) string {
	sum := sha256.Sum256([]byte(registry + "\x00" + repository + "\x00" + digest))
	return fmt.Sprintf("namespace-signatures/%x.json", sum)
}
