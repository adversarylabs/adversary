package adversary

import (
	"strings"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

// ScopeReviewContext limits a reviewer to the changed files selected by its
// declarative detection rules. The repository and graph remain available for
// context; only the patch under review is narrowed.
func ScopeReviewContext(m manifest.Manifest, context detection.Context) (detection.Context, bool) {
	patterns := m.Detection.Files
	if len(patterns) == 0 && len(m.Detection.RepositoryFiles) == 0 && strings.TrimSpace(m.Detection.Entrypoint) == "" {
		patterns = m.Triggers.FilesChanged
	}
	if len(patterns) == 0 {
		return context, false
	}
	result := EvaluateDeclarativeDetection(m, context)
	return ReviewContextForFiles(context, result.RelevantFiles), true
}

// ReviewContextForFiles preserves immutable repository identity and graph
// inputs while limiting the changed-file review target.
func ReviewContextForFiles(context detection.Context, paths []string) detection.Context {
	relevant := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		relevant[path] = struct{}{}
	}
	scoped := context
	scoped.ChangedFiles = make([]detection.ChangedFile, 0, len(relevant))
	for _, changed := range context.ChangedFiles {
		if _, ok := relevant[changed.Path]; ok {
			scoped.ChangedFiles = append(scoped.ChangedFiles, changed)
		}
	}
	return scoped
}
