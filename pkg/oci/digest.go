package oci

import (
	"crypto/sha256"
	_ "crypto/sha512" // register OCI-supported SHA-384 and SHA-512 algorithms
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	digestapi "github.com/opencontainers/go-digest"
)

type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func VerifyDigest(data []byte, digest string) error {
	d, err := digestapi.Parse(digest)
	if err != nil {
		return fmt.Errorf("invalid digest %q: %w", digest, err)
	}
	if err := d.Validate(); err != nil {
		return fmt.Errorf("invalid digest %q: %w", digest, err)
	}
	if !d.Algorithm().Available() {
		return fmt.Errorf("unsupported digest algorithm %q", d.Algorithm())
	}
	if d.Algorithm().FromBytes(data) != d {
		return fmt.Errorf("digest mismatch for %s", digest)
	}
	return nil
}

type digestReader struct {
	reader io.Reader
	hash   hash.Hash
}

func NewDigestReader(reader io.Reader) *digestReader {
	return &digestReader{reader: reader, hash: sha256.New()}
}

func (r *digestReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	return n, err
}

func (r *digestReader) Digest() string {
	return "sha256:" + hex.EncodeToString(r.hash.Sum(nil))
}

func DigestPath(digest string) (string, error) {
	d, err := ParseDigest(digest)
	if err != nil {
		return "", err
	}
	return d.Algorithm().String() + "/" + d.Encoded(), nil
}

func ParseDigest(value string) (digestapi.Digest, error) {
	d, err := digestapi.Parse(value)
	if err != nil || d.Validate() != nil || !d.Algorithm().Available() {
		return "", fmt.Errorf("invalid or unsupported digest %q", value)
	}
	return d, nil
}
