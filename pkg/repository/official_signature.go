package repository

import (
	"fmt"

	"github.com/adversarylabs/adversary/pkg/officialsig"
)

// SaveOfficialSignature stores a signature envelope for digest under the local store.
// Callers should Verify before treating the artifact as official.
func (r Repository) SaveOfficialSignature(digest string, envelope []byte) error {
	if err := r.init(); err != nil {
		return err
	}
	if digest == "" {
		return fmt.Errorf("digest is required")
	}
	if len(envelope) == 0 {
		return fmt.Errorf("empty official signature")
	}
	if _, err := officialsig.ParseEnvelope(envelope); err != nil {
		return err
	}
	return r.atomic("official-signatures/"+key(digest)+".json", envelope)
}

// LoadOfficialSignature returns the stored envelope for digest, if any.
func (r Repository) LoadOfficialSignature(digest string) ([]byte, error) {
	if err := r.init(); err != nil {
		return nil, err
	}
	return r.read("official-signatures/" + key(digest) + ".json")
}

// HasVerifiedOfficialSignature reports whether a stored envelope verifies for digest
// under the default official keyring.
func (r Repository) HasVerifiedOfficialSignature(digest string) bool {
	return r.HasVerifiedOfficialSignatureWithKeyring(digest, officialsig.DefaultKeyring())
}

// HasVerifiedOfficialSignatureWithKeyring verifies a stored envelope with keys.
func (r Repository) HasVerifiedOfficialSignatureWithKeyring(digest string, keys officialsig.Keyring) bool {
	data, err := r.LoadOfficialSignature(digest)
	if err != nil {
		return false
	}
	env, err := officialsig.ParseEnvelope(data)
	if err != nil {
		return false
	}
	return officialsig.Verify(env, digest, keys) == nil
}
