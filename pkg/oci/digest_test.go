package oci

import (
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"
)

func TestDigestValidation(t *testing.T) {
	valid := Digest([]byte("data"))
	if _, err := ParseDigest(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"sha256:abc", "sha256:" + strings.Repeat("0", 63), "sha256:" + strings.Repeat("g", 64), "md5:" + strings.Repeat("0", 32), "sha256/" + strings.Repeat("0", 64)} {
		if _, err := ParseDigest(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	sha512sum := sha512.Sum512([]byte("data"))
	sha512Digest := fmt.Sprintf("sha512:%x", sha512sum)
	if _, err := ParseDigest(sha512Digest); err != nil {
		t.Fatalf("sha512 rejected: %v", err)
	}
	if err := VerifyDigest([]byte("data"), sha512Digest); err != nil {
		t.Fatalf("sha512 verification failed: %v", err)
	}
	sha384Digest := fmt.Sprintf("sha384:%x", sha512.Sum384([]byte("data")))
	if _, err := ParseDigest(sha384Digest); err != nil {
		t.Fatalf("sha384 rejected: %v", err)
	}
	if err := VerifyDigest([]byte("data"), sha384Digest); err != nil {
		t.Fatalf("sha384 verification failed: %v", err)
	}
}

func FuzzParseDigest(f *testing.F) {
	f.Add(Digest(nil))
	f.Add("sha256:abc")
	f.Add("sha256:" + strings.Repeat("0", 64))
	f.Fuzz(func(t *testing.T, value string) {
		d, err := ParseDigest(value)
		if err == nil && d.String() != value {
			t.Fatalf("digest changed")
		}
	})
}
