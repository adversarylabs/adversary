package adversary

import (
	"reflect"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

func TestParseChangedRegionsKeepsEveryHunk(t *testing.T) {
	patch := []byte("@@ -3 +3,2 @@\n-old\n+new\n+more\n@@ -100,4 +101,0 @@\n-gone\n")
	want := []detection.ReviewRegion{
		{Path: "main.go", StartLine: 3, EndLine: 4},
		{Path: "main.go", StartLine: 101, EndLine: 101},
	}
	got, err := parseChangedRegions("main.go", patch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("regions = %#v, want %#v", got, want)
	}
}

func TestParseChangedRegionsDoesNotCapHunks(t *testing.T) {
	patch := []byte("@@ -1 +1 @@\n@@ -10 +10 @@\n@@ -20 +20 @@\n@@ -30 +30 @@\n@@ -40 +40 @@\n@@ -50 +50 @@\n")
	got, err := parseChangedRegions("large.go", patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("got %d regions, want all 6", len(got))
	}
}
