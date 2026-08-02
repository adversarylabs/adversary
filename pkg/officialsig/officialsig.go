// Package officialsig implements Adversary Labs official catalog signatures.
//
// Official free-catalog packages are signed with an Ed25519 key. The CLI embeds
// the corresponding public key(s) and verifies signatures without external tools.
// CI may sign with the same library (see scripts/sign-official) or any process
// that emits a compatible envelope as an OCI referrer.
//
// This is intentionally smaller than Notation/Cosign for the verify path:
// users only need the adversary binary. Key rotation is a later TUF/keyring step.
package officialsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SpecVersion is the envelope format version.
const SpecVersion = 1

// MediaType is the OCI referrer / blob media type for signature envelopes.
const MediaType = "application/vnd.adversarylabs.official-signature.v1+json"

// ArtifactTagKind is used for digest-derived fallback tags (like adversary-manifest).
const ArtifactTagKind = "official-signature"

// DefaultKeyID is the key id for the embedded official public key.
const DefaultKeyID = "official-v1"

// Envelope is the signed document attached as an OCI referrer to an artifact digest.
type Envelope struct {
	SpecVersion   int    `json:"specVersion"`
	SubjectDigest string `json:"subjectDigest"`
	KeyID         string `json:"keyID"`
	SignedAt      string `json:"signedAt"`
	Signature     string `json:"signature"` // base64.StdEncoding of ed25519 signature
}

// Keyring maps key ids to Ed25519 public keys trusted for official signatures.
type Keyring map[string]ed25519.PublicKey

// productionKeyring is the shipped CLI trust store (public keys only).
func productionKeyring() Keyring {
	return Keyring{DefaultKeyID: mustParsePublicKey(embeddedOfficialV1PublicKey)}
}

// activeKeyring is the keyring used by DefaultKeyring. Tests may replace it via
// SetKeyringForTest; production never ships private keys.
var activeKeyring = productionKeyring()

// DefaultKeyring returns the active official public keyring.
func DefaultKeyring() Keyring {
	return activeKeyring
}

// SetKeyringForTest replaces the active keyring for the duration of a test.
// The returned function restores the previous keyring. Private keys used with
// this keyring must be generated in-process — never committed.
func SetKeyringForTest(k Keyring) (restore func()) {
	prev := activeKeyring
	if k == nil {
		activeKeyring = productionKeyring()
	} else {
		activeKeyring = k
	}
	return func() { activeKeyring = prev }
}

// SigningMessage is the exact byte sequence that is signed/verified.
func SigningMessage(subjectDigest, keyID, signedAt string) []byte {
	// Fixed field order and separators — do not change without a new SpecVersion.
	return []byte("adversarylabs-official-sig-v1\n" +
		strings.TrimSpace(subjectDigest) + "\n" +
		strings.TrimSpace(keyID) + "\n" +
		strings.TrimSpace(signedAt) + "\n")
}

// Sign creates an envelope for subjectDigest using the private key and keyID.
func Sign(subjectDigest, keyID string, private ed25519.PrivateKey, now time.Time) (Envelope, error) {
	subjectDigest = strings.TrimSpace(subjectDigest)
	keyID = strings.TrimSpace(keyID)
	if subjectDigest == "" {
		return Envelope{}, fmt.Errorf("subject digest is required")
	}
	if keyID == "" {
		return Envelope{}, fmt.Errorf("key id is required")
	}
	if len(private) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("invalid ed25519 private key size")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	signedAt := now.UTC().Format(time.RFC3339)
	msg := SigningMessage(subjectDigest, keyID, signedAt)
	sig := ed25519.Sign(private, msg)
	return Envelope{
		SpecVersion:   SpecVersion,
		SubjectDigest: subjectDigest,
		KeyID:         keyID,
		SignedAt:      signedAt,
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks envelope against the keyring for the claimed subject digest.
func Verify(envelope Envelope, wantSubjectDigest string, keys Keyring) error {
	if envelope.SpecVersion != SpecVersion {
		return fmt.Errorf("unsupported official signature specVersion %d", envelope.SpecVersion)
	}
	wantSubjectDigest = strings.TrimSpace(wantSubjectDigest)
	if wantSubjectDigest == "" {
		return fmt.Errorf("subject digest is required")
	}
	if envelope.SubjectDigest != wantSubjectDigest {
		return fmt.Errorf("signature subject %q does not match artifact %q", envelope.SubjectDigest, wantSubjectDigest)
	}
	pub, ok := keys[envelope.KeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("unknown or invalid official key id %q", envelope.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size")
	}
	msg := SigningMessage(envelope.SubjectDigest, envelope.KeyID, envelope.SignedAt)
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("official signature verification failed")
	}
	return nil
}

// MarshalEnvelope encodes an envelope as JSON bytes for storage or referrers.
func MarshalEnvelope(env Envelope) ([]byte, error) {
	return json.Marshal(env)
}

// ParseEnvelope decodes and lightly validates an envelope document.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("parse official signature: %w", err)
	}
	if env.SpecVersion == 0 {
		return Envelope{}, fmt.Errorf("missing specVersion")
	}
	if strings.TrimSpace(env.SubjectDigest) == "" || strings.TrimSpace(env.KeyID) == "" || strings.TrimSpace(env.Signature) == "" {
		return Envelope{}, fmt.Errorf("official signature envelope incomplete")
	}
	return env, nil
}

// GenerateKey creates a new Ed25519 key pair (for CI bootstrap / tests).
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// PublicKeyHex returns a stable hex encoding of a public key.
func PublicKeyHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

// ParsePrivateKeySeed parses a 32-byte seed or 64-byte private key from hex.
func ParsePrivateKeySeed(hexKey string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("private key must be %d-byte seed or %d-byte key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// Fingerprint returns a short id for diagnostics (not used for crypto).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func mustParsePublicKey(hexKey string) ed25519.PublicKey {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		// Built-in key must be valid; panic only on programmer error at init.
		panic("officialsig: invalid embedded public key")
	}
	return ed25519.PublicKey(raw)
}
