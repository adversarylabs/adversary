package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWritePullTextIncludesOnlyNonEmptyTag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tag     string
		wantTag bool
	}{
		{name: "tagged reference", tag: "v1", wantTag: true},
		{name: "digest reference", wantTag: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := writePullText(&output, pullDTO{Name: "acme/reviewer", Version: "1.2.3", Tag: tc.tag, CanonicalReference: "ghcr.io/acme/reviewer", Digest: "sha256:abc"})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(output.String(), "\nTag:"); got != tc.wantTag {
				t.Fatalf("output = %q, contains tag=%t", output.String(), got)
			}
			for _, want := range []string{"Installed: acme/reviewer", "Version: 1.2.3", "Canonical reference: ghcr.io/acme/reviewer", "Digest: sha256:abc"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("output missing %q: %q", want, output.String())
				}
			}
		})
	}
}

type failingPullWriter struct{}

func (failingPullWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWritePullTextPropagatesWriterFailure(t *testing.T) {
	if err := writePullText(failingPullWriter{}, pullDTO{}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("error = %v", err)
	}
}
