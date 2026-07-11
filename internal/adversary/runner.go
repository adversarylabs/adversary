package adversary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
)

type RunOptions struct {
	AdversaryRef             string
	RepoPath                 string
	BaseRef                  string
	HeadRef                  string
	Builder                  string
	Force                    bool
	Format                   string
	KeepTemp                 bool
	NoNetwork                bool
	Verbose                  bool
	IncludeSuppressed        bool
	Shell                    bool
	AllFiles                 bool
	AllowUnsafeHostExecution bool
	Build                    bool
	RunTimeout               time.Duration
	BuildTimeout             time.Duration
}

const maxRunOutputBytes int64 = 16 << 20

type FindingsError struct{ Count int }

func (e *FindingsError) Error() string {
	return fmt.Sprintf("adversary reported %d finding(s)", e.Count)
}

type ProtocolError struct{ Err error }

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("adversary output protocol failure: %v", e.Err)
}
func (e *ProtocolError) Unwrap() error { return e.Err }

type ExecutionError struct{ Err error }

func (e *ExecutionError) Error() string { return fmt.Sprintf("adversary execution failed: %v", e.Err) }
func (e *ExecutionError) Unwrap() error { return e.Err }

type Runner struct {
	Stdout                  io.Writer
	Stderr                  io.Writer
	Git                     GitDiffer
	Executor                ContainerExecutor
	MkdirTemp               func(dir, pattern string) (string, error)
	RemoveAll               func(string) error
	Repository              *repository.Repository
	Resolver                *Resolver
	RequireInjectedResolver bool
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
		executor = HostExecutor{Stdout: stderr, Stderr: stderr, Stdin: os.Stdin}
	}

	mkdirTemp := r.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}

	explicitLocalPath, err := isExplicitLocalAdversaryPath(opts.AdversaryRef)
	if err != nil {
		return err
	}
	var resolved ResolvedAdversary
	if r.Resolver != nil {
		resolved, err = ResolveReferenceWithResolver(opts.AdversaryRef, *r.Resolver)
	} else if r.RequireInjectedResolver {
		return fmt.Errorf("injected resolver is required")
	} else {
		resolved, err = ResolveReference(opts.AdversaryRef)
	}
	if err != nil {
		return err
	}
	if !resolved.LocalDir {
		return fmt.Errorf("adversary %q is not installed locally; run `adversary pull %s` first", opts.AdversaryRef, opts.AdversaryRef)
	}
	if resolved.StoreBacked {
		repo := r.Repository
		if repo == nil {
			resolver, resolverErr := DefaultResolver()
			if resolverErr != nil {
				return resolverErr
			}
			repo = &resolver.Repository
		}
		lease, leaseErr := repo.LeaseMaterialized(resolved.StoreRecord)
		if leaseErr != nil {
			return leaseErr
		}
		defer lease.Close()
		resolved.ExecutionPath = lease.Path
		resolved.BuildContext = lease.Path
		resolved.StorePath = lease.Path
	}
	if r.Executor == nil {
		if err := validateHostExecution(resolved, explicitLocalPath, opts); err != nil {
			return err
		}
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
			if opts.Format == "json" {
				skipped := review.RunEnvelope{
					ProtocolVersion: review.ProtocolVersion,
					Result: review.ReviewResult{
						Adversary:    review.ReviewAdversary{Name: resolved.Name},
						Target:       review.ReviewTarget{Repository: repoPath},
						Positives:    []review.Note{},
						Observations: []review.Note{{Key: "run-skipped", Summary: "No changed files matched triggers.files_changed."}},
						Findings:     []review.Finding{},
						Suppressed:   review.Suppressed{},
					},
				}
				encoder := json.NewEncoder(stdout)
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(skipped); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(stdout, "Skipped %s: no changed files matched triggers.files_changed\n", resolved.Name)
			}
			return nil
		}
	}

	started := time.Now()
	var buildDuration time.Duration
	if resolved.LocalDir && !resolved.StoreBacked && opts.Build {
		buildStarted := time.Now()
		buildCtx := ctx
		cancelBuild := func() {}
		if opts.BuildTimeout > 0 {
			buildCtx, cancelBuild = context.WithTimeout(ctx, opts.BuildTimeout)
		}
		if err := pack.BuildProject(buildCtx, pack.BuildOptions{
			Dir:     resolved.BuildContext,
			Builder: opts.Builder,
			Stdout:  stderr,
			Stderr:  stderr,
			Strict:  true,
		}); err != nil {
			cancelBuild()
			return err
		}
		cancelBuild()
		buildDuration = time.Since(buildStarted)
	}
	if r.Executor == nil && resolved.LocalDir && !resolved.StoreBacked {
		if err := validateLocalCommandFiles(resolved.Command); err != nil {
			if !opts.Build {
				return fmt.Errorf("local build output is unavailable or stale; rerun with --build: %w", err)
			}
			return err
		}
	}

	runDir, err := mkdirTemp(os.TempDir(), "adversary-run-*")
	if err != nil {
		return err
	}
	if !opts.KeepTemp {
		removeAll := r.RemoveAll
		if removeAll == nil {
			removeAll = os.RemoveAll
		}
		defer func() {
			if err := removeAll(runDir); err != nil && opts.Verbose {
				fmt.Fprintf(stderr, "warning: remove temporary run directory %s: %v\n", runDir, err)
			}
		}()
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
	if resolved.LocalDir {
		config.Env["ADVERSARY_REPO"] = repoPath
		config.Env["ADVERSARY_INPUT"] = inputPath
		config.Env["ADVERSARY_OUTPUT"] = outputPath
	}

	if opts.Verbose {
		PrintVerboseLaunch(stderr, config)
	}
	runStarted := time.Now()
	runCtx := ctx
	cancelRun := func() {}
	if opts.RunTimeout > 0 {
		runCtx, cancelRun = context.WithTimeout(ctx, opts.RunTimeout)
	}
	result, err := executor.Run(runCtx, config.ContainerSpec())
	cancelRun()
	scanDuration := time.Since(runStarted)
	totalDuration := time.Since(started)
	if opts.Verbose {
		printExecutionSummary(stderr, result, buildDuration, scanDuration, totalDuration)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		var child *ChildExitError
		if errors.As(err, &child) {
			return err
		}
		return &ExecutionError{Err: err}
	}

	if opts.Shell {
		if opts.KeepTemp {
			fmt.Fprintf(stderr, "Temporary run directory: %s\n", runDir)
		}
		return nil
	}

	outputData, err := readBoundedRunOutput(outputPath)
	if err != nil {
		return err
	}

	envelope, err := review.DecodeRunEnvelope(outputData)
	if err != nil {
		return &ProtocolError{Err: err}
	}

	if opts.Format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(envelope); err != nil {
			return err
		}
	} else {
		if err := review.RenderTerminal(stdout, envelope.Result); err != nil {
			return err
		}
	}

	if opts.KeepTemp {
		fmt.Fprintf(stderr, "Temporary run directory: %s\n", runDir)
	}
	if len(envelope.Result.Findings) > 0 {
		return &FindingsError{Count: len(envelope.Result.Findings)}
	}
	return nil
}

func isExplicitLocalAdversaryPath(ref string) (bool, error) {
	info, err := os.Stat(filepath.Join(ref, "adversary.yaml"))
	if err != nil || info.IsDir() {
		return false, nil
	}
	candidate, err := filepath.Abs(ref)
	if err != nil {
		return false, fmt.Errorf("classify adversary path: %w", err)
	}
	canonicalCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false, fmt.Errorf("classify adversary path safely: %w", err)
	}
	roots, err := artifactStorageRoots()
	if err != nil {
		return false, err
	}
	for _, root := range roots {
		absoluteRoot, err := filepath.Abs(root)
		if err != nil {
			return false, fmt.Errorf("classify artifact storage root: %w", err)
		}
		if pathWithin(candidate, absoluteRoot) {
			return false, nil
		}
		canonicalRoot, err := filepath.EvalSymlinks(absoluteRoot)
		if err == nil && pathWithin(canonicalCandidate, canonicalRoot) {
			return false, nil
		}
	}
	return true, nil
}

func artifactStorageRoots() ([]string, error) {
	dataRoot, err := resolverDataRoot()
	if err != nil {
		return nil, fmt.Errorf("locate unified artifact repository: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate retired artifact cache: %w", err)
	}
	// Classify the whole data root as artifact-controlled, not just the unified
	// repository subtree. This preserves the host-execution boundary for paths
	// left by retired stores without consulting those stores at runtime.
	return []string{dataRoot, filepath.Join(home, ".adversary", "cache")}, nil
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateHostExecution(resolved ResolvedAdversary, explicitLocalPath bool, opts RunOptions) error {
	if opts.Shell && !opts.AllowUnsafeHostExecution {
		return fmt.Errorf("--shell runs an unrestricted host shell; pass --allow-unsafe-host-execution to acknowledge the risk")
	}
	if opts.Shell && opts.Format == "json" {
		return fmt.Errorf("--shell cannot be combined with JSON output")
	}
	if !explicitLocalPath && !opts.AllowUnsafeHostExecution {
		return fmt.Errorf("installed or pulled adversaries run as unrestricted host processes; pass --allow-unsafe-host-execution to execute trusted code")
	}
	if opts.NoNetwork || resolved.NetworkOff {
		return fmt.Errorf("host execution cannot enforce disabled network access; use a future isolated executor instead of weakening the requested policy")
	}
	if resolved.Manifest != nil {
		permissions := resolved.Manifest.Permissions
		if len(permissions.Filesystem.Read) > 0 || len(permissions.Filesystem.Write) > 0 || len(permissions.Env) > 0 {
			return fmt.Errorf("host execution cannot enforce manifest filesystem or environment restrictions; use a future isolated executor")
		}
	}
	return nil
}

func readBoundedRunOutput(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &ProtocolError{Err: err}
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRunOutputBytes+1))
	if err != nil {
		return nil, &ProtocolError{Err: err}
	}
	if len(data) == 0 {
		return nil, &ProtocolError{Err: fmt.Errorf("output is empty")}
	}
	if int64(len(data)) > maxRunOutputBytes {
		return nil, &ProtocolError{Err: fmt.Errorf("output exceeds %d bytes", maxRunOutputBytes)}
	}
	return data, nil
}

func validateLocalCommandFiles(command []string) error {
	for _, part := range command {
		if filepath.IsAbs(part) && strings.HasSuffix(part, ".js") {
			if info, err := os.Stat(part); err != nil {
				return fmt.Errorf("local adversary command file %s was not found; run npm install and npm run build, or pack the adversary first", part)
			} else if info.IsDir() {
				return fmt.Errorf("local adversary command file %s is a directory", part)
			}
		}
	}
	return nil
}

func (r Runner) Inspect(opts RunOptions) error {
	stdout := r.Stdout
	if stdout == nil {
		stdout = io.Discard
	}

	var resolved ResolvedAdversary
	var err error
	if r.Resolver != nil {
		resolved, err = ResolveReferenceWithResolver(opts.AdversaryRef, *r.Resolver)
	} else if r.RequireInjectedResolver {
		return fmt.Errorf("injected resolver is required")
	} else {
		resolved, err = ResolveReference(opts.AdversaryRef)
	}
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

	config := NewRunConfig(resolved, repoPath, filepath.Join(os.TempDir(), "adversary-run"), opts)
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
	inputPath := ""
	outputPath := ""
	if runDir != "" {
		inputPath = filepath.Join(runDir, "input.json")
		outputPath = filepath.Join(runDir, "output.json")
	}
	env := map[string]string{
		"ADVERSARY_REPO":               repoPath,
		"ADVERSARY_INPUT":              inputPath,
		"ADVERSARY_OUTPUT":             outputPath,
		"ADVERSARY_VERBOSE":            boolEnv(opts.Verbose),
		"ADVERSARY_INCLUDE_SUPPRESSED": boolEnv(opts.IncludeSuppressed),
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
		RuntimeName:     c.Resolved.RuntimeName,
		RuntimeVersion:  c.Resolved.RuntimeVersion,
		Command:         c.Resolved.Command,
		RepoPath:        c.RepoPath,
		RunDir:          c.RunDir,
		AdversaryPath:   c.Resolved.ExecutionPath,
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

func PrintVerboseLaunch(w io.Writer, config RunConfig) {
	fmt.Fprintln(w, "Launching adversary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Command:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, FormatShellCommand(config.ContainerSpec().Command))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Paths")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Repository: %s\n", config.RepoPath)
	fmt.Fprintf(w, "  Adversary:  %s\n", config.Resolved.ExecutionPath)
	fmt.Fprintf(w, "  Run dir:    %s\n", config.RunDir)
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
	fmt.Fprintln(w, "Runtime")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", resolved.Image)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Project")
	fmt.Fprintln(w)
	if resolved.LocalDir {
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
	PrintRepositoryContents(w, config.RepoPath)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Command")
	fmt.Fprintln(w)
	command := resolved.Command
	if config.Options.Shell {
		if shell, err := platformShell(); err == nil {
			command = shell
		} else {
			command = []string{"<host shell unavailable>"}
		}
	}
	if len(command) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		for _, part := range command {
			fmt.Fprintf(w, "  %s\n", part)
		}
	}
	fmt.Fprintln(w)
	PrintEnvironment(w, config.Env)
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

func printExecutionSummary(w io.Writer, result ContainerResult, build, scan, total time.Duration) {
	kind := result.Kind
	if kind == "" {
		kind = "Process"
	}
	fmt.Fprintf(w, "%s exit code: %d\n", kind, result.ExitCode)
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
