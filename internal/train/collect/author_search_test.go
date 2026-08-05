package collect

import (
	"testing"
)

func TestSplitOwnerRepo(t *testing.T) {
	o, r := splitOwnerRepo("hashicorp/terraform", "terraform", "")
	if o != "hashicorp" || r != "terraform" {
		t.Fatalf("%s %s", o, r)
	}
	o, r = splitOwnerRepo("", "", "https://github.com/tailscale/tailscale/pull/1")
	if o != "tailscale" || r != "tailscale" {
		t.Fatalf("%s %s", o, r)
	}
}

func TestCleanLogins(t *testing.T) {
	got := cleanLogins([]string{"@mitchellh", "mitchellh", " dhh ", ""})
	if len(got) != 2 || got[0] != "mitchellh" || got[1] != "dhh" {
		t.Fatalf("%v", got)
	}
}

func TestAuthorPRRefSkipKey(t *testing.T) {
	r := AuthorPRRef{Owner: "o", Repo: "r", Number: 9}
	if r.SkipKey() != "o/r#9" {
		t.Fatal(r.SkipKey())
	}
}
