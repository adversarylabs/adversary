package adversary

import (
	"strings"

	"github.com/doomerlabs/doomer/pkg/detection"
	"github.com/doomerlabs/doomer/pkg/manifest"
)

// SelectBeforeDownload uses declarative scope whenever a package provides it.
// A programmatic detector is retained conservatively only when the manifest
// does not also provide a declarative gate.
func SelectBeforeDownload(m manifest.Manifest, c detection.Context) (bool, string) {
	d := m.Detection
	if d.Scope != "" && d.Scope != "repository" && d.Scope != "change" {
		return true, "unsupported selection scope"
	}
	patterns := d.Files
	if len(patterns) == 0 {
		patterns = m.Triggers.FilesChanged
	}
	if len(patterns) == 0 && len(d.RepositoryFiles) == 0 {
		if d.Entrypoint != "" {
			return true, "programmatic detector has no declarative gate; retained"
		}
		return true, "no declarative gate; retained"
	}
	scope := strings.TrimSpace(d.Scope)
	// Unspecified composition scopes follow the active change when one exists.
	// Authors that need repository-wide applicability can request it explicitly.
	if scope == "change" || scope == "" && len(c.ChangedFiles) > 0 && len(patterns) > 0 {
		if len(patterns) == 0 {
			return true, "no change-file gate; retained"
		}
		result := EvaluateDeclarativeDetection(m, c)
		return result.Applicable, result.Reasons[0]
	}
	paths := append([]string(nil), c.RepositoryFiles...)
	for _, f := range c.ChangedFiles {
		paths = append(paths, f.Path)
		if f.PreviousPath != "" {
			paths = append(paths, f.PreviousPath)
		}
	}
	if len(d.RepositoryFiles) > 0 {
		patterns = d.RepositoryFiles
	}
	if ShouldRunForChangedFiles(patterns, paths, false) {
		return true, "repository files matched detection rules"
	}
	return false, "no repository files matched detection rules"
}
