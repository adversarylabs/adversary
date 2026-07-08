package adversary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	Build        bool
	NoBuild      bool
	Verbose      bool
	Shell        bool
	AllFiles     bool
}

type Runner struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Git       GitDiffer
	Executor  ContainerExecutor
	Builder   ImageBuilder
	MkdirTemp func(dir, pattern string) (string, error)
}

func (r Runner) Run(ctx context.Context, opts RunOptions) error {
	stdout := r.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := r.Stderr
	if stderr == nil {
		stderr = io.Discard
	}

	git := r.Git
	if git == nil {
		git = CommandGitDiffer{}
	}

	executor := r.Executor
	if executor == nil {
		executor = DockerExecutor{Stdout: r.Stdout, Stderr: r.Stderr, Stdin: os.Stdin}
	}

	builder := r.Builder
	if builder == nil {
		builder = DockerBuilder{Stdout: r.Stderr, Stderr: r.Stderr}
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

	config := NewRunConfig(resolved, repoPath, "", opts)
	if opts.Verbose {
		PrintVerboseLoad(stderr, opts.AdversaryRef, resolved)
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

	if resolved.Manifest != nil && len(resolved.Manifest.Triggers.FilesChanged) > 0 && (opts.BaseRef != "" || opts.HeadRef != "") {
		if !ShouldRunForChangedFiles(resolved.Manifest.Triggers.FilesChanged, changedFiles, opts.Force || opts.AllFiles) {
			fmt.Fprintf(stdout, "Skipped %s: no changed files matched triggers.files_changed\n", resolved.Name)
			return nil
		}
	}

	started := time.Now()
	var buildDuration time.Duration
	if ShouldBuildAdversary(resolved, opts) {
		if opts.Verbose {
			PrintVerboseBuild(stderr, resolved)
		} else {
			fmt.Fprintf(stderr, "Building adversary image %s from %s\n", resolved.Image, resolved.BuildContext)
		}
		buildStarted := time.Now()
		if _, err := builder.Build(ctx, BuildSpec{Image: resolved.Image, Context: resolved.BuildContext}); err != nil {
			return err
		}
		buildDuration = time.Since(buildStarted)
	}

	runDir, err := mkdirTemp("", "adversary-run-*")
	if err != nil {
		return err
	}
	if !opts.KeepTemp {
		defer os.RemoveAll(runDir)
	}
	config.RunDir = runDir

	input := NewInput(opts.BaseRef, opts.HeadRef, changedFiles, opts.AllFiles)
	inputData, err := MarshalInput(input)
	if err != nil {
		return err
	}
	inputPath := filepath.Join(runDir, "input.json")
	if err := os.WriteFile(inputPath, inputData, 0644); err != nil {
		return err
	}

	outputPath := filepath.Join(runDir, "output.json")
	if err := os.WriteFile(outputPath, nil, 0644); err != nil {
		return err
	}

	if opts.Verbose {
		PrintVerboseLaunch(stderr, config)
	} else {
		fmt.Fprintf(stderr, "Running %s\n", resolved.Image)
	}
	runStarted := time.Now()
	result, err := executor.Run(ctx, config.ContainerSpec())
	scanDuration := time.Since(runStarted)
	totalDuration := time.Since(started)
	printExecutionSummary(stderr, result.ExitCode, buildDuration, scanDuration, totalDuration)
	if err != nil {
		return err
	}

	if opts.Shell {
		if opts.KeepTemp {
			fmt.Fprintf(stdout, "\nTemporary run directory: %s\n", runDir)
		}
		return nil
	}

	outputData, err := os.ReadFile(outputPath)
	if os.IsNotExist(err) || len(outputData) == 0 {
		fmt.Fprintln(stdout, "Scan complete")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Files scanned: 0")
		fmt.Fprintln(stdout, "Rules executed: 0")
		fmt.Fprintln(stdout, "Findings: 0")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "No findings output was produced.")
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

func (r Runner) Inspect(opts RunOptions) error {
	stdout := r.Stdout
	if stdout == nil {
		stdout = io.Discard
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

	config := NewRunConfig(resolved, repoPath, "/tmp/adversary-run", opts)
	PrintInspect(stdout, opts.AdversaryRef, config)
	return nil
}

type RunConfig struct {
	Resolved ResolvedAdversary
	RepoPath string
	RunDir   string
	Options  RunOptions
	Env      map[string]string
}

func NewRunConfig(resolved ResolvedAdversary, repoPath, runDir string, opts RunOptions) RunConfig {
	env := map[string]string{
		"ADVERSARY_REPO":    "/workspace",
		"ADVERSARY_INPUT":   "/adversary/input.json",
		"ADVERSARY_OUTPUT":  "/adversary/output.json",
		"ADVERSARY_VERBOSE": boolEnv(opts.Verbose),
	}
	return RunConfig{
		Resolved: resolved,
		RepoPath: repoPath,
		RunDir:   runDir,
		Options:  opts,
		Env:      env,
	}
}

func (c RunConfig) ContainerSpec() ContainerSpec {
	return ContainerSpec{
		Image:           c.Resolved.Image,
		Command:         c.Resolved.Command,
		RepoPath:        c.RepoPath,
		RunDir:          c.RunDir,
		NetworkDisabled: c.Options.NoNetwork || c.Resolved.NetworkOff,
		Env:             c.Env,
		Shell:           c.Options.Shell,
	}
}

func boolEnv(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func ShouldBuildAdversary(resolved ResolvedAdversary, opts RunOptions) bool {
	if opts.NoBuild {
		return false
	}
	return resolved.LocalDir && resolved.HasDockerfile
}

func PrintVerboseLoad(w io.Writer, ref string, resolved ResolvedAdversary) {
	fmt.Fprintln(w, "Loading adversary")
	if resolved.LocalDir {
		fmt.Fprintf(w, "  Manifest: %s\n", filepath.Join(ref, "adversary.yaml"))
	}
	fmt.Fprintf(w, "  Name: %s\n", resolved.Name)
	if resolved.Manifest != nil && resolved.Manifest.Version != "" {
		fmt.Fprintf(w, "  Version: %s\n", resolved.Manifest.Version)
	}
	fmt.Fprintln(w)
}

func PrintVerboseBuild(w io.Writer, resolved ResolvedAdversary) {
	fmt.Fprintln(w, "Building image")
	fmt.Fprintf(w, "  Context: %s\n", resolved.BuildContext)
	fmt.Fprintf(w, "  Image: %s\n", resolved.Image)
	fmt.Fprintln(w)
}

func PrintVerboseLaunch(w io.Writer, config RunConfig) {
	fmt.Fprintln(w, "Launching container")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Docker command:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, FormatShellCommand(append([]string{"docker"}, dockerRunArgs(config.ContainerSpec())...)))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Mounts")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Host:      %s\n", config.RepoPath)
	fmt.Fprintln(w, "  Container: /workspace")
	fmt.Fprintf(w, "  Input:     %s/input.json -> /adversary/input.json\n", config.RunDir)
	fmt.Fprintf(w, "  Output:    %s/output.json -> /adversary/output.json\n", config.RunDir)
	fmt.Fprintln(w)
	PrintEnvironment(w, config.Env)
	fmt.Fprintln(w)
	PrintRepositoryContents(w, config.RepoPath)
	fmt.Fprintln(w)
}

func PrintInspect(w io.Writer, ref string, config RunConfig) {
	resolved := config.Resolved
	fmt.Fprintln(w, "Adversary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Name: %s\n", resolved.Name)
	if resolved.Manifest != nil && resolved.Manifest.Version != "" {
		fmt.Fprintf(w, "  Version: %s\n", resolved.Manifest.Version)
	}
	if resolved.LocalDir {
		fmt.Fprintf(w, "  Manifest: %s\n", filepath.Join(ref, "adversary.yaml"))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Image")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", resolved.Image)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Build context")
	fmt.Fprintln(w)
	if resolved.LocalDir && resolved.HasDockerfile {
		fmt.Fprintf(w, "  %s\n", resolved.BuildContext)
	} else {
		fmt.Fprintln(w, "  none")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Repository")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Host:")
	fmt.Fprintf(w, "    %s\n", config.RepoPath)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Container:")
	fmt.Fprintln(w, "    /workspace")
	fmt.Fprintln(w)
	PrintRepositoryContents(w, config.RepoPath)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Command")
	fmt.Fprintln(w)
	command := resolved.Command
	if config.Options.Shell {
		command = []string{"/bin/sh"}
	}
	if len(command) == 0 {
		fmt.Fprintln(w, "  default image command")
	} else {
		for _, part := range command {
			fmt.Fprintf(w, "  %s\n", part)
		}
	}
	fmt.Fprintln(w)
	PrintEnvironment(w, config.Env)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Docker command")
	fmt.Fprintln(w)
	fmt.Fprintln(w, FormatShellCommand(append([]string{"docker"}, dockerRunArgs(config.ContainerSpec())...)))
}

func PrintEnvironment(w io.Writer, env map[string]string) {
	fmt.Fprintln(w, "Environment")
	fmt.Fprintln(w)
	for _, key := range sortedEnvKeys(env) {
		fmt.Fprintf(w, "  %s=%s\n", key, env[key])
	}
}

func PrintRepositoryContents(w io.Writer, repoPath string) {
	fmt.Fprintln(w, "Repository contents")
	fmt.Fprintln(w)
	entries, err := RepositoryContents(repoPath)
	if err != nil {
		fmt.Fprintf(w, "  error: %v\n", err)
		return
	}
	for _, entry := range entries {
		fmt.Fprintf(w, "  %s\n", entry)
	}
}

func RepositoryContents(repoPath string) ([]string, error) {
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".git" {
			continue
		}
		if entry.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func FormatShellCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	lines := commandLines(args)
	var b strings.Builder
	for i, line := range lines {
		if i == 0 {
			b.WriteString(line)
		} else {
			b.WriteString("\n  ")
			b.WriteString(line)
		}
		if i != len(lines)-1 {
			b.WriteString(" \\")
		}
	}
	return b.String()
}

func commandLines(args []string) []string {
	lines := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if (arg == "-v" || arg == "-e" || arg == "--network") && i+1 < len(args) {
			lines = append(lines, shellQuote(arg)+" "+shellQuote(args[i+1]))
			i++
			continue
		}
		lines = append(lines, shellQuote(arg))
	}
	return lines
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n'\"\\$`") {
		return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
	}
	return s
}

func printExecutionSummary(w io.Writer, exitCode int, build, scan, total time.Duration) {
	fmt.Fprintf(w, "Container exit code: %d\n", exitCode)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Execution time")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Build:   %s\n", formatDuration(build))
	fmt.Fprintln(w, "  Startup: 0ms")
	fmt.Fprintf(w, "  Scan:    %s\n", formatDuration(scan))
	fmt.Fprintf(w, "  Total:   %s\n", formatDuration(total))
	fmt.Fprintln(w)
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return "0ms"
	}
	return d.Round(time.Millisecond).String()
}
