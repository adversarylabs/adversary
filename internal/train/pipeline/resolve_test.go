package pipeline

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/train/adversaries"
)

func TestResolvePrimaryAndPackageID(t *testing.T) {
	if packageIDFromName("go-concurrency-adversary") != "go-concurrency" {
		t.Fatal()
	}
	got := resolvePrimaryAdversaryName(Options{}, []adversaries.Package{{ID: "go-concurrency"}})
	if got != "go-concurrency" {
		t.Fatal(got)
	}
	got = resolvePrimaryAdversaryName(Options{AdversaryName: "x"}, nil)
	if got != "x" {
		t.Fatal(got)
	}
	got = resolvePrimaryAdversaryName(Options{}, nil)
	if got != "engineering-review" {
		t.Fatal(got)
	}
	if normalizeConcurrency(0) != defaultHuntConcurrency {
		t.Fatal()
	}
	if normalizeConcurrency(100) != maxHuntConcurrency {
		t.Fatal()
	}
}

func TestWorkspaceAuthorOK(t *testing.T) {
	if !workspaceAuthorOK("alice", nil, nil) {
		t.Fatal()
	}
	if workspaceAuthorOK("bob", []string{"alice"}, nil) {
		t.Fatal()
	}
	if workspaceAuthorOK("alice", []string{"alice"}, []string{"alice"}) {
		t.Fatal("ignore wins")
	}
}
