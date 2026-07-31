package telemetry

import "testing"

func TestDisabledWith(t *testing.T) {
	if DisabledWith(func(string) string { return "" }) {
		t.Fatal("expected enabled when env empty")
	}
	if !DisabledWith(func(k string) string {
		if k == "DO_NOT_TRACK" {
			return "1"
		}
		return ""
	}) {
		t.Fatal("DO_NOT_TRACK=1")
	}
	if !DisabledWith(func(k string) string {
		if k == "ADVERSARY_TELEMETRY" {
			return "off"
		}
		return ""
	}) {
		t.Fatal("ADVERSARY_TELEMETRY=off")
	}
	if DisabledWith(func(k string) string {
		if k == "ADVERSARY_TELEMETRY" {
			return "1"
		}
		return ""
	}) {
		t.Fatal("ADVERSARY_TELEMETRY=1 should leave enabled")
	}
}

func TestSanitizeAdversarySelection(t *testing.T) {
	got := SanitizeAdversarySelection([]string{
		"registry.adversarylabs.ai/infra/terraform:0.0.4",
		"go/security",
		"go/security",
		"./local-adv",
		"/abs/path",
		"private-reviewer",          // bare local dir name
		"internal/private-reviewer", // path-shaped, non-official domain
		"npm",                       // bare short name (ambiguous with local dirs)
		"weird!!!",
		"",
	})
	// Official catalog ids preserved; everything else buckets to local/other.
	want := []string{"infra/terraform", "go/security", "local", "other"}
	if len(got) != len(want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v want %#v", got, want)
		}
	}
}

func TestSanitizeOfficialDomainsOnly(t *testing.T) {
	if got := SanitizeAdversaryRef("ci/gitlab-ci"); got != "ci/gitlab-ci" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeAdversaryRef("internal/x"); got != "local" {
		t.Fatalf("non-official domain got %q want local", got)
	}
	if got := SanitizeAdversaryRef("private-reviewer"); got != "local" {
		t.Fatalf("bare name got %q want local", got)
	}
}
