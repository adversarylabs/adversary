package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

type Descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func VerifyDigest(data []byte, digest string) error {
	got := Digest(data)
	if got != digest {
		return fmt.Errorf("digest mismatch: got %s, want %s", got, digest)
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
	algo, hexValue, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hexValue == "" {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return algo + "/" + hexValue, nil
}
