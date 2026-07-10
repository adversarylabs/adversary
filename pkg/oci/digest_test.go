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
	if _, err := ParseDigest(fmt.Sprintf("sha512:%x", sha512sum)); err != nil {
		t.Fatalf("sha512 rejected: %v", err)
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
