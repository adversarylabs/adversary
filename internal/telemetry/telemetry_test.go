package telemetry

import (
	"path/filepath"
	"testing"
)

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
	for key, value := range map[string]string{
		"OTEL_SDK_DISABLED":    "true",
		"OTEL_TRACES_EXPORTER": "none",
	} {
		if !DisabledWith(func(k string) string {
			if k == key {
				return value
			}
			return ""
		}) {
			t.Fatalf("%s=%s should disable telemetry", key, value)
		}
	}
}

func TestSanitizeAdversarySelection(t *testing.T) {
	// No on-disk projects for these refs.
	pathExists = func(string) bool { return false }
	t.Cleanup(func() { pathExists = defaultPathExists })

	got := SanitizeAdversarySelection([]string{
		"registry.adversarylabs.ai/infra/terraform:0.0.4",
		"go/security",
		"go/security",
		"./local-adv",
		"/abs/path",
		"private-reviewer",
		"internal/private-reviewer",
		"npm",
		"weird!!!",
		"",
	})
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
	pathExists = func(string) bool { return false }
	t.Cleanup(func() { pathExists = defaultPathExists })

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

func TestSanitizeWindowsDrivePaths(t *testing.T) {
	pathExists = func(string) bool { return false }
	t.Cleanup(func() { pathExists = defaultPathExists })

	if got := SanitizeAdversaryRef(`C:/Users/alice/private-reviewer`); got != "local" {
		t.Fatalf("got %q want local", got)
	}
	if got := SanitizeAdversaryRef(`c:\Users\alice\tool`); got != "local" {
		t.Fatalf("got %q want local", got)
	}
}

func TestSanitizeExternalOCIHosts(t *testing.T) {
	pathExists = func(string) bool { return false }
	t.Cleanup(func() { pathExists = defaultPathExists })

	if got := SanitizeAdversaryRef("registry.example.com/go/payroll-private"); got != "external" {
		t.Fatalf("got %q want external", got)
	}
	if got := SanitizeAdversaryRef("ghcr.io/acme/security:1.0.0"); got != "external" {
		t.Fatalf("got %q want external", got)
	}
	if got := SanitizeAdversaryRef("localhost:5000/go/payroll-private"); got != "external" {
		t.Fatalf("localhost private registry got %q want external", got)
	}
	if got := SanitizeAdversaryRef("localhost:8787/infra/terraform:0.0.4"); got != "external" {
		t.Fatalf("localhost dev registry got %q want external", got)
	}
	if got := SanitizeAdversaryRef("registry.adversarylabs.ai/go/security:0.0.11"); got != "go/security" {
		t.Fatalf("got %q want go/security", got)
	}
}

func TestSanitizeCatalogShapedLocalProject(t *testing.T) {
	// Simulate on-disk ci/private-reviewer/adversary.yaml (runtime local precedence).
	pathExists = func(p string) bool {
		return p == filepath.Join("ci/private-reviewer", "adversary.yaml") ||
			p == filepath.Join("ci/private-reviewer", "adversary.yml")
	}
	t.Cleanup(func() { pathExists = defaultPathExists })

	if got := SanitizeAdversaryRef("ci/private-reviewer"); got != "local" {
		t.Fatalf("catalog-shaped local path got %q want local", got)
	}
	// Without on-disk project, same shape is a real catalog id.
	pathExists = func(string) bool { return false }
	if got := SanitizeAdversaryRef("ci/gitlab-ci"); got != "ci/gitlab-ci" {
		t.Fatalf("got %q want ci/gitlab-ci", got)
	}
}
