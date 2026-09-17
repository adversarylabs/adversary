package githubreview

import "testing"

func TestMarkerV2RoundTrip(t *testing.T) {
	line := 12
	comment := PlannedComment{
		Adversary: "library/review/engineering:1.2.3", Package: "review/engineering",
		PackageVersion: "1.2.3", FindingID: "finding with spaces", RuleID: "contract/gap",
		HeadSHA: "abc123", Anchor: Anchor{Path: "a file.go", Line: &line},
	}
	marker := MarkerV2(comment)
	got, ok, err := ParseMarker("body\n\n" + marker)
	if err != nil || !ok {
		t.Fatalf("parse marker: ok=%v err=%v", ok, err)
	}
	if got.Version != 2 || got.Package != comment.Package || got.PackageVersion != comment.PackageVersion ||
		got.FindingID != comment.FindingID || got.RuleID != comment.RuleID || got.Location != "a file.go:12" {
		t.Fatalf("marker=%+v", got)
	}
}

func TestParseMarkerV1(t *testing.T) {
	got, ok, err := ParseMarker("x <!-- adversary-review:v1 adversary=go-cli finding=f-1 loc=a.go:3 -->")
	if err != nil || !ok || got.Version != 1 || got.Package != "go-cli" || got.FindingID != "f-1" {
		t.Fatalf("marker=%+v ok=%v err=%v", got, ok, err)
	}
}

func TestParseMarkerRejectsMalformed(t *testing.T) {
	if _, ok, err := ParseMarker("<!-- adversary-review:v2 adversary=x -->"); !ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
