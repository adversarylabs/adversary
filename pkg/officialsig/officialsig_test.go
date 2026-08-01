package officialsig

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// testSeed is the private seed for embeddedOfficialV1PublicKey (CI/dev only).
const testSeed = "7bef45c91f3ead4f9f79362390d0f32d86347b5ee93138a7bfb93245941b4850"

func testPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, err := ParsePrivateKeySeed(testSeed)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != embeddedOfficialV1PublicKey {
		t.Fatalf("test seed does not match embedded public key")
	}
	return priv
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv := testPrivate(t)
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	env, err := Sign(digest, DefaultKeyID, priv, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
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
	priv := testPrivate(t)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	env, err := Sign(digest, DefaultKeyID, priv, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DefaultKeyring()); err == nil {
		t.Fatal("expected subject mismatch")
	}
	env.Signature = "AAAA"
	if err := Verify(env, digest, DefaultKeyring()); err == nil {
		t.Fatal("expected bad signature")
	}
}

func TestDefaultKeyringHasOfficialKey(t *testing.T) {
	keys := DefaultKeyring()
	if _, ok := keys[DefaultKeyID]; !ok {
		t.Fatal("missing default key")
	}
}
