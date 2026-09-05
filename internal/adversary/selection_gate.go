package adversary

import (
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

// SelectBeforeDownload is deliberately conservative. Executable detectors and
// absent declarations cannot prove that a package is irrelevant without code.
// This gate selects packages; runtime detection still scopes individual jobs.
func SelectBeforeDownload(m manifest.Manifest, c detection.Context) (bool, string) {
	d := m.Detection
	if d.Entrypoint != "" {
		return true, "programmatic detector requires package"
	}
	if d.Scope != "" && d.Scope != "repository" && d.Scope != "change" {
		return true, "unsupported selection scope"
	}
	patterns := d.Files
	if len(patterns) == 0 {
		patterns = m.Triggers.FilesChanged
	}
	if len(patterns) == 0 && len(d.RepositoryFiles) == 0 {
		return true, "no declarative gate; retained"
	}
	if d.Scope == "change" {
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
