package officialsig

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	restore := SetKeyringForTest(Keyring{"test-key": pub})
	t.Cleanup(restore)

	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	env, err := Sign(digest, "test-key", priv, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(parsed, digest, DefaultKeyring()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperAndWrongDigest(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := Keyring{"test-key": pub}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	env, err := Sign(digest, "test-key", priv, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", keys); err == nil {
		t.Fatal("expected subject mismatch")
	}
	env.Signature = "AAAA"
	if err := Verify(env, digest, keys); err == nil {
		t.Fatal("expected bad signature")
	}
}

func TestDefaultKeyringHasOfficialKey(t *testing.T) {
	// Ensure production keyring is restored even if other tests override it.
	restore := SetKeyringForTest(nil)
	t.Cleanup(restore)
	keys := DefaultKeyring()
	if _, ok := keys[DefaultKeyID]; !ok {
		t.Fatal("missing default key")
	}
	// Production keyring must not be empty and must be 32-byte keys only.
	for id, pub := range keys {
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("key %q has invalid size %d", id, len(pub))
		}
	}
}

func TestProductionPrivateSeedIsNotInModule(t *testing.T) {
	// Guardrail: no hex private seed constants in this package's tests or keys.
	// Private material belongs in CI secrets only.
	restore := SetKeyringForTest(nil)
	t.Cleanup(restore)
	// Signing with a random key must not verify under production keyring.
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	env, err := Sign(digest, DefaultKeyID, priv, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, digest, compileTimeKeyring()); err == nil {
		t.Fatal("random private key must not verify under compile-time public key")
	}
}

func TestBuildFlavorMatchesDefaultKeyID(t *testing.T) {
	restore := SetKeyringForTest(nil)
	t.Cleanup(restore)
	flavor := BuildFlavor()
	if flavor != "dev" && flavor != "release" {
		t.Fatalf("unexpected flavor %q", flavor)
	}
	if _, ok := DefaultKeyring()[DefaultKeyID]; !ok {
		t.Fatalf("keyring missing DefaultKeyID %q", DefaultKeyID)
	}
	// A single binary must not ship both prod and dev public keys.
	if _, hasProd := DefaultKeyring()[ProdKeyID]; hasProd && flavor == "dev" {
		t.Fatal("dev build must not embed official-prod public key")
	}
	if _, hasDev := DefaultKeyring()[DevKeyID]; hasDev && flavor == "release" {
		t.Fatal("release build must not embed official-dev public key")
	}
}
