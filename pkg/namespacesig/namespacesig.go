// Package namespacesig verifies private adversary signatures delegated by the
// Adversary Labs platform to a team namespace.
package namespacesig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	SpecVersion           = 1
	SignatureMediaType    = "application/vnd.adversarylabs.namespace-signature.v1+json"
	TrustMediaType        = "application/vnd.adversarylabs.namespace-trust.v1+json"
	SignatureArtifactKind = "namespace-signature"
	TrustArtifactKind     = "namespace-trust"
	signatureDomain       = "adversarylabs-namespace-signature-v1"
	trustDomain           = "adversarylabs-namespace-trust-v1"
)

var (
	sha256Digest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namespaceFormat = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
)

type Envelope struct {
	SpecVersion   int    `json:"specVersion"`
	MediaType     string `json:"mediaType"`
	Registry      string `json:"registry"`
	Repository    string `json:"repository"`
	Namespace     string `json:"namespace"`
	TeamID        string `json:"teamId"`
	SubjectDigest string `json:"subjectDigest"`
	KeyID         string `json:"keyId"`
	SignedAt      string `json:"signedAt"`
	Signature     string `json:"signature"`
}

type TrustBundle struct {
	SpecVersion int    `json:"specVersion"`
	MediaType   string `json:"mediaType"`
	Namespace   string `json:"namespace"`
	TeamID      string `json:"teamId"`
	KeyID       string `json:"keyId"`
	PublicKey   string `json:"publicKey"`
	IssuedAt    string `json:"issuedAt"`
	RootKeyID   string `json:"rootKeyId"`
	Signature   string `json:"signature"`
}

type SigningResult struct {
	Envelope      Envelope    `json:"signature"`
	TrustBundle   TrustBundle `json:"trustBundle"`
	RootPublicKey string      `json:"rootPublicKey,omitempty"`
}

type Root struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

func ParseSigningResult(data []byte) (SigningResult, error) {
	var result SigningResult
	if err := json.Unmarshal(data, &result); err != nil {
		return SigningResult{}, fmt.Errorf("decode namespace signing result: %w", err)
	}
	if err := validateEnvelope(result.Envelope); err != nil {
		return SigningResult{}, err
	}
	if err := validateTrustBundle(result.TrustBundle); err != nil {
		return SigningResult{}, err
	}
	return result, nil
}

func ParseEnvelope(data []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("decode namespace signature: %w", err)
	}
	if err := validateEnvelope(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func ParseTrustBundle(data []byte) (TrustBundle, error) {
	var bundle TrustBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return TrustBundle{}, fmt.Errorf("decode namespace trust bundle: %w", err)
	}
	if err := validateTrustBundle(bundle); err != nil {
		return TrustBundle{}, err
	}
	return bundle, nil
}

func MarshalEnvelope(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func MarshalTrustBundle(bundle TrustBundle) ([]byte, error) {
	if err := validateTrustBundle(bundle); err != nil {
		return nil, err
	}
	return json.Marshal(bundle)
}

// Verify proves both that the platform delegated the team key and that the
// delegated key signed this exact immutable artifact digest.
func Verify(envelope Envelope, bundle TrustBundle, wantRegistry, wantRepository, wantDigest string, root Root) error {
	if err := validateEnvelope(envelope); err != nil {
		return err
	}
	if err := validateTrustBundle(bundle); err != nil {
		return err
	}
	wantDigest = strings.ToLower(strings.TrimSpace(wantDigest))
	wantRegistry = strings.ToLower(strings.TrimSpace(wantRegistry))
	wantRepository = strings.ToLower(strings.TrimSpace(wantRepository))
	if envelope.Registry != wantRegistry || envelope.Repository != wantRepository {
		return fmt.Errorf("signature source %s/%s does not match artifact %s/%s", envelope.Registry, envelope.Repository, wantRegistry, wantRepository)
	}
	if envelope.SubjectDigest != wantDigest {
		return fmt.Errorf("signature subject %q does not match artifact %q", envelope.SubjectDigest, wantDigest)
	}
	if envelope.Namespace != bundle.Namespace || envelope.TeamID != bundle.TeamID || envelope.KeyID != bundle.KeyID {
		return errors.New("namespace signature and trust bundle identity do not match")
	}
	if bundle.RootKeyID != strings.TrimSpace(root.KeyID) {
		return fmt.Errorf("trust bundle root %q does not match fetched root %q", bundle.RootKeyID, root.KeyID)
	}
	rootKey, err := decodePublicKey(root.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid namespace root public key: %w", err)
	}
	bundleSignature, err := decodeSignature(bundle.Signature)
	if err != nil {
		return fmt.Errorf("invalid trust bundle signature: %w", err)
	}
	if !ed25519.Verify(rootKey, trustMessage(bundle), bundleSignature) {
		return errors.New("namespace trust delegation verification failed")
	}
	teamKey, err := decodePublicKey(bundle.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid namespace public key: %w", err)
	}
	envelopeSignature, err := decodeSignature(envelope.Signature)
	if err != nil {
		return fmt.Errorf("invalid namespace signature: %w", err)
	}
	if !ed25519.Verify(teamKey, signatureMessage(envelope), envelopeSignature) {
		return errors.New("namespace signature verification failed")
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.SpecVersion != SpecVersion || envelope.MediaType != SignatureMediaType {
		return fmt.Errorf("unsupported namespace signature format")
	}
	if !validRegistry(envelope.Registry) || !strings.HasPrefix(envelope.Repository, envelope.Namespace+"/") || strings.Count(envelope.Repository, "/") != 1 || !validNamespace(envelope.Namespace) || strings.TrimSpace(envelope.TeamID) == "" || strings.TrimSpace(envelope.KeyID) == "" || strings.TrimSpace(envelope.SignedAt) == "" {
		return fmt.Errorf("incomplete namespace signature")
	}
	if !sha256Digest.MatchString(envelope.SubjectDigest) {
		return fmt.Errorf("invalid namespace signature subject digest")
	}
	return nil
}

func validateTrustBundle(bundle TrustBundle) error {
	if bundle.SpecVersion != SpecVersion || bundle.MediaType != TrustMediaType {
		return fmt.Errorf("unsupported namespace trust format")
	}
	if !validNamespace(bundle.Namespace) || strings.TrimSpace(bundle.TeamID) == "" || strings.TrimSpace(bundle.KeyID) == "" || strings.TrimSpace(bundle.IssuedAt) == "" || strings.TrimSpace(bundle.RootKeyID) == "" {
		return fmt.Errorf("incomplete namespace trust bundle")
	}
	if _, err := decodePublicKey(bundle.PublicKey); err != nil {
		return fmt.Errorf("invalid namespace public key: %w", err)
	}
	return nil
}

func validNamespace(value string) bool {
	return namespaceFormat.MatchString(value)
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected a 32-byte base64 Ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

func decodeSignature(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("expected a 64-byte base64 Ed25519 signature")
	}
	return raw, nil
}

func trustMessage(bundle TrustBundle) []byte {
	return []byte(strings.Join([]string{
		trustDomain,
		bundle.Namespace,
		bundle.TeamID,
		bundle.KeyID,
		bundle.PublicKey,
		bundle.IssuedAt,
		bundle.RootKeyID,
	}, "\n"))
}

func signatureMessage(envelope Envelope) []byte {
	return []byte(strings.Join([]string{
		signatureDomain,
		envelope.Registry,
		envelope.Repository,
		envelope.Namespace,
		envelope.TeamID,
		envelope.SubjectDigest,
		envelope.KeyID,
		envelope.SignedAt,
	}, "\n"))
}

func validRegistry(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value == strings.ToLower(value) && !strings.ContainsAny(value, "/?#@")
}
