package cmd

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveInitDestination(t *testing.T) {
	t.Parallel()
	got, err := resolveInitDestination("my-adversary", "")
	if err != nil || got != "my-adversary" {
		t.Fatalf("default: %q %v", got, err)
	}
	got, err = resolveInitDestination("my-adversary", "../packages")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("../packages", "my-adversary")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if _, err := resolveInitDestination("", "/tmp"); err == nil {
		t.Fatal("empty name")
	}
	if _, err := resolveInitDestination("foo/bar", "/tmp"); err == nil {
		t.Fatal("name with slash + path should fail")
	}
	if runtime.GOOS != "windows" {
		if _, err := resolveInitDestination("/abs/foo", "/tmp"); err == nil {
			t.Fatal("abs name + path should fail")
		}
	}
}
