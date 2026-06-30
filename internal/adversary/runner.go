package adversary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type RunOptions struct {
	AdversaryRef string
	RepoPath     string
	BaseRef      string
	HeadRef      string
	Force        bool
	Format       string
	KeepTemp     bool
	NoNetwork    bool
}

type Runner struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Git       GitDiffer
	Executor  ContainerExecutor
	MkdirTemp func(dir, pattern string) (string, error)
}

func (r Runner) Run(ctx context.Context, opts RunOptions) error {
	stdout := r.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	git := r.Git
	if git == nil {
		git = CommandGitDiffer{}
	}

	executor := r.Executor
	if executor == nil {
		executor = DockerExecutor{Stdout: r.Stdout, Stderr: r.Stderr}
	}

	mkdirTemp := r.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}

	resolved, err := ResolveReference(opts.AdversaryRef)
	if err != nil {
		return err
	}

	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = "."
	}
	repoPath, err = filepath.Abs(repoPath)
	if err != nil {
		return err
	}

	var changedFiles []string
	if opts.BaseRef != "" || opts.HeadRef != "" {
		if opts.BaseRef == "" || opts.HeadRef == "" {
			return fmt.Errorf("--base and --head must be provided together")
		}
		changedFiles, err = git.ChangedFiles(ctx, repoPath, opts.BaseRef, opts.HeadRef)
		if err != nil {
			return err
		}
	}

	if resolved.Manifest != nil && len(resolved.Manifest.RunWhen.FilesChanged) > 0 && (opts.BaseRef != "" || opts.HeadRef != "") {
		if !ShouldRunForChangedFiles(resolved.Manifest.RunWhen.FilesChanged, changedFiles, opts.Force) {
			fmt.Fprintf(stdout, "Skipped %s: no changed files matched run_when.files_changed\n", resolved.Name)
			return nil
		}
	}

	runDir, err := mkdirTemp("", "adversary-run-*")
	if err != nil {
		return err
	}
	if !opts.KeepTemp {
		defer os.RemoveAll(runDir)
	}

	input := NewInput(opts.BaseRef, opts.HeadRef, changedFiles)
	inputData, err := MarshalInput(input)
	if err != nil {
		return err
	}
	inputPath := filepath.Join(runDir, "input.json")
	if err := os.WriteFile(inputPath, inputData, 0644); err != nil {
		return err
	}

	outputPath := filepath.Join(runDir, "output.json")
	_ = os.Remove(outputPath)

	err = executor.Run(ctx, ContainerSpec{
		Image:           resolved.Image,
		Command:         resolved.Command,
		RepoPath:        repoPath,
		RunDir:          runDir,
		NetworkDisabled: opts.NoNetwork || resolved.NetworkOff,
	})
	if err != nil {
		return err
	}

	outputData, err := os.ReadFile(outputPath)
	if os.IsNotExist(err) || len(outputData) == 0 {
		fmt.Fprintln(stdout, "Completed, but no findings output was produced.")
		if opts.KeepTemp {
			fmt.Fprintf(stdout, "Temporary run directory: %s\n", runDir)
		}
		return nil
	}
	if err != nil {
		return err
	}

	findings, err := ParseFindings(outputData)
	if err != nil {
		return err
	}

	if opts.Format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(findings); err != nil {
			return err
		}
	} else {
		if err := RenderTextFindings(stdout, findings); err != nil {
			return err
		}
	}

	if opts.KeepTemp {
		fmt.Fprintf(stdout, "\nTemporary run directory: %s\n", runDir)
	}
	return nil
}
