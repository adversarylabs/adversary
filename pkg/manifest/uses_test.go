package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUses(t *testing.T) {
	input := strings.Replace(valid, "triggers:", `uses:
  - name: go/concurrency
    version: "0.1.0"
  - name: review/engineering
  - path: ../sibling-adversary
triggers:`, 1)
	m, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Uses) != 3 {
		t.Fatalf("%#v", m.Uses)
	}
	if m.Uses[0].Name != "go/concurrency" || m.Uses[0].Version != "0.1.0" {
		t.Fatalf("%#v", m.Uses[0])
	}
	if m.Uses[2].Path != "../sibling-adversary" {
		t.Fatalf("%#v", m.Uses[2])
	}
}

func TestValidateUsesRejects(t *testing.T) {
	cases := []struct {
		snippet string
		want    string
	}{
		{`uses:
  - name: go/x
    path: ../y
`, "exactly one"},
		{`uses:
  - {}
`, "exactly one"},
		{`uses:
  - name: Go/Bad
`, "normalized"},
		{`uses:
  - name: go/x
    version: "^1.0.0"
`, "exact tag"},
		{`uses:
  - path: ../x
    version: "1.0.0"
`, "only valid with name"},
		{`uses:
  - name: go/x
  - name: go/x
`, "duplicates"},
	}
	for _, tc := range cases {
		input := strings.Replace(valid, "triggers:", tc.snippet+"triggers:", 1)
		_, err := Parse([]byte(input))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("snippet %q: err=%v want %q", tc.snippet, err, tc.want)
		}
	}
}

func TestUseReference(t *testing.T) {
	ref, err := UseReference("/pkg", Use{Name: "go/security", Version: "0.2.0"})
	if err != nil || ref != "go/security:0.2.0" {
		t.Fatalf("%q %v", ref, err)
	}
	ref, err = UseReference("/pkg", Use{Path: "members/nit"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Clean(filepath.Join("/pkg", "members/nit"))
	if ref != want {
		t.Fatalf("got %q want %q", ref, want)
	}
}
