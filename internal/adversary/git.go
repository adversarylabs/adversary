package adversary

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type GitDiffer interface {
	ChangedFiles(ctx context.Context, repoPath, baseRef, headRef string) ([]string, error)
}

type CommandGitDiffer struct{}

func (CommandGitDiffer) ChangedFiles(ctx context.Context, repoPath, baseRef, headRef string) ([]string, error) {
	if baseRef == "" || headRef == "" {
		return nil, fmt.Errorf("base and head refs are required")
	}

	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", baseRef+"..."+headRef)
	cmd.Dir = repoPath

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("git diff failed: %s", msg)
		}
		return nil, fmt.Errorf("git diff failed: %w", err)
	}

	return parseChangedFiles(stdout.String()), nil
}

func parseChangedFiles(output string) []string {
	lines := strings.Split(output, "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		file := strings.TrimSpace(line)
		if file != "" {
			files = append(files, file)
		}
	}
	return files
}
