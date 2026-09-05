package adversary

import (
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"testing"
)

func TestSelectBeforeDownload(t *testing.T) {
	context := detection.Context{RepositoryFiles: []string{"go.mod", "main.go", "README.md"}, ChangedFiles: []detection.ChangedFile{{Path: "README.md", Status: detection.StatusModified}}}
	for _, tc := range []struct {
		name string
		d    manifest.Detection
		want bool
	}{
		{"go repo despite docs change", manifest.Detection{Files: []string{"**/*.go"}}, true},
		{"unrelated python", manifest.Detection{Files: []string{"**/*.py"}}, false},
		{"explicit change gate", manifest.Detection{Scope: "change", Files: []string{"**/*.go"}}, false},
		{"repository marker", manifest.Detection{RepositoryFiles: []string{"**/go.mod"}}, true},
		{"generalist", manifest.Detection{}, true},
		{"executable", manifest.Detection{Entrypoint: "detect.js", Files: []string{"**/*.py"}}, true},
		{"unknown scope", manifest.Detection{Scope: "future", Files: []string{"**/*.py"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := SelectBeforeDownload(manifest.Manifest{Detection: tc.d}, context)
			if got != tc.want || reason == "" {
				t.Fatalf("got %v %q", got, reason)
			}
		})
	}
}
func TestSelectionRetainsDeletedAndRenamedLanguage(t *testing.T) {
	for _, f := range []detection.ChangedFile{{Path: "last.go", Status: detection.StatusDeleted}, {Path: "last.txt", PreviousPath: "last.go", Status: detection.StatusRenamed}} {
		got, _ := SelectBeforeDownload(manifest.Manifest{Detection: manifest.Detection{Files: []string{"**/*.go"}}}, detection.Context{ChangedFiles: []detection.ChangedFile{f}})
		if !got {
			t.Fatal("deleted or renamed source must retain its reviewer")
		}
	}
}
