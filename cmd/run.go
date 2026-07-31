package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/spf13/cobra"
)

type runOptions struct {
	path                     string
	base                     string
	head                     string
	builder                  string
	modelProvider            string
	model                    string
	force                    bool
	format                   string
	json                     bool
	outputFile               string
	keepTemp                 bool
	noNetwork                bool
	verbose                  bool
	debug                    bool
	includeSuppressed        bool
	shell                    bool
	allFiles                 bool
	all                      bool
	noPull                   bool
	dryRun                   bool
	explain                  bool
	minimumConfidence        string
	includes                 []string
	excludes                 []string
	detectionTimeout         time.Duration
	allowUnsafeHostExecution bool
	build                    bool
	noBuild                  bool
	runTimeout               time.Duration
	buildTimeout             time.Duration
}

func newRunCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run [adversary-ref...]",
		Short: "Run adversaries against a local source repository",
		Long: `Run adversaries against a repository.

With one or more adversary references, those adversaries run explicitly.

With no adversary references, run pulls every adversary you can access (unless
--no-pull), detects which apply to the resolved review scope, and runs the
selected set. Use --all to skip detection and run every installed adversary.
Use --all-files for a whole-repository scan instead of change inference.`,
		Example: `  adversary run
  adversary run --all
  adversary run --all-files
  adversary run --dry-run --explain
  adversary run --base main
  adversary run adversarylabs/dockerfile
  adversary run ./local-adversary --path ../project
  adversary run adversarylabs/dockerfile --base main --head feature
  adversary run adversarylabs/go-cli adversarylabs/secrets --all-files
  adversary run adversarylabs/go-cli --model-provider fireworks --model accounts/fireworks/models/your-model-id
  adversary run --all --all-files --output-file review.txt
  adversary run go-cli secrets --format json --output-file results.json`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, opts.json)
			if err != nil {
				return err
			}
			if opts.debug && cmd.Flags().Changed("verbose") {
				return fmt.Errorf("--debug and --verbose cannot be combined")
			}
			if opts.allFiles && (opts.base != "" || opts.head != "") {
				return fmt.Errorf("--all-files cannot be combined with --base or --head")
			}
			if opts.builder != "local" && opts.builder != "docker" {
				return fmt.Errorf("--builder must be local or docker")
			}
			opts.modelProvider = strings.ToLower(strings.TrimSpace(opts.modelProvider))
			opts.model = strings.TrimSpace(opts.model)
			switch opts.modelProvider {
			case "", "openai", "anthropic", "fireworks":
			default:
				return fmt.Errorf("--model-provider must be openai, anthropic, or fireworks")
			}
			if cmd.Flags().Changed("model-provider") && opts.modelProvider == "" {
				return fmt.Errorf("--model-provider must not be empty")
			}
			if cmd.Flags().Changed("model") && opts.model == "" {
				return fmt.Errorf("--model must not be empty")
			}
			if opts.shell && opts.noNetwork {
				return fmt.Errorf("--shell cannot be combined with --no-network because the host shell cannot enforce network isolation")
			}
			if opts.shell && format == "json" {
				return fmt.Errorf("--shell cannot be combined with JSON output")
			}
			if opts.shell && len(args) > 1 {
				return fmt.Errorf("--shell cannot be combined with multiple adversary references")
			}
			if opts.shell && len(args) == 0 {
				return fmt.Errorf("--shell requires exactly one adversary reference")
			}
			if opts.shell && strings.TrimSpace(opts.outputFile) != "" {
				return fmt.Errorf("--output-file cannot be combined with --shell")
			}
			if opts.build && opts.noBuild {
				return fmt.Errorf("--build and --no-build cannot be combined")
			}
			if opts.runTimeout < 0 || opts.buildTimeout < 0 || opts.detectionTimeout < 0 {
				return fmt.Errorf("timeouts cannot be negative")
			}
			opts.format = format
			if opts.json {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			if opts.debug {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --debug is deprecated; use --verbose.")
				opts.verbose = true
			}

			resultOut, progressOut, closer, err := resolveRunWriters(opts.outputFile, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if closer != nil {
				defer closer()
			}

			if len(args) == 0 {
				return runAutomaticSelection(cmd, app, opts, apiURL, profile, resultOut, progressOut)
			}
			if err := rejectAutomaticOnlyFlags(cmd, opts); err != nil {
				return err
			}
			return runAdversaries(cmd.Context(), app, opts, args, apiURL, profile, resultOut, progressOut)
		},
	}

	cmd.Flags().StringVar(&opts.path, "path", ".", "path to the source directory to review")
	cmd.Flags().StringVar(&opts.base, "base", "", "git base ref (defaults to the detected default branch when --head is set)")
	cmd.Flags().StringVar(&opts.head, "head", "", "git head ref (defaults to HEAD when --base is set)")
	cmd.Flags().StringVar(&opts.builder, "builder", "local", "build mechanism for local adversaries: local or docker")
	cmd.Flags().StringVar(&opts.modelProvider, "model-provider", "", "model provider: openai, anthropic, or fireworks (overrides ADVERSARY_MODEL_PROVIDER)")
	cmd.Flags().StringVar(&opts.model, "model", "", "provider model identifier (overrides ADVERSARY_MODEL)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "run even when triggers.files_changed does not match")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.json, "json", false, "print the versioned review result envelope as JSON")
	cmd.Flags().StringVar(&opts.outputFile, "output-file", "", "write review results to this file; progress stays on the terminal (works with one or many adversaries)")
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "require network access to be disabled (fails if the executor cannot enforce it)")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.debug, "debug", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.includeSuppressed, "include-suppressed", false, "request suppressed review findings when supported by the runtime")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "UNSAFE: launch an unrestricted host shell in the adversary working directory")
	cmd.Flags().BoolVar(&opts.allowUnsafeHostExecution, "allow-unsafe-host-execution", false, "explicitly allow unrestricted HostExecutor use for an unknown publisher")
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan the entire target instead of inferring a change")
	cmd.Flags().BoolVar(&opts.all, "all", false, "with no adversary refs: run every available adversary without detection filtering")
	cmd.Flags().BoolVar(&opts.noPull, "no-pull", false, "with no adversary refs: do not pull remote adversaries; use only the local store")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "with no adversary refs: resolve and print selections without running")
	cmd.Flags().BoolVar(&opts.explain, "explain", false, "with no adversary refs: show selected and skipped adversaries with reasons")
	cmd.Flags().StringVar(&opts.minimumConfidence, "min-confidence", "medium", "with no adversary refs: minimum confidence to run (low, medium, or high)")
	cmd.Flags().StringArrayVar(&opts.includes, "include", nil, "with no adversary refs: force an available adversary to run (repeatable)")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "with no adversary refs: exclude an adversary (repeatable; wins over include)")
	cmd.Flags().DurationVar(&opts.detectionTimeout, "detection-timeout", 30*time.Second, "with no adversary refs: maximum time for each programmatic detector")
	cmd.Flags().BoolVar(&opts.build, "build", false, "build a local adversary before running (may update dist)")
	cmd.Flags().BoolVar(&opts.noBuild, "no-build", false, "deprecated compatibility flag; local builds are skipped by default")
	_ = cmd.Flags().MarkDeprecated("no-build", "local builds are skipped by default; omit this flag")
	cmd.Flags().DurationVar(&opts.runTimeout, "timeout", 0, "maximum adversary execution time (0 disables the deadline)")
	cmd.Flags().DurationVar(&opts.buildTimeout, "build-timeout", 10*time.Minute, "maximum explicit local build time")

	return cmd
}

func rejectAutomaticOnlyFlags(cmd *cobra.Command, opts *runOptions) error {
	switch {
	case opts.all:
		return fmt.Errorf("--all cannot be combined with explicit adversary references")
	case opts.noPull:
		return fmt.Errorf("--no-pull cannot be combined with explicit adversary references")
	case opts.dryRun:
		return fmt.Errorf("--dry-run cannot be combined with explicit adversary references")
	case opts.explain:
		return fmt.Errorf("--explain cannot be combined with explicit adversary references")
	case len(opts.includes) > 0:
		return fmt.Errorf("--include cannot be combined with explicit adversary references")
	case len(opts.excludes) > 0:
		return fmt.Errorf("--exclude cannot be combined with explicit adversary references")
	case cmd.Flags().Changed("min-confidence"):
		return fmt.Errorf("--min-confidence cannot be combined with explicit adversary references")
	case cmd.Flags().Changed("detection-timeout"):
		return fmt.Errorf("--detection-timeout cannot be combined with explicit adversary references")
	default:
		return nil
	}
}

func resolveRunWriters(outputFile string, stdout, stderr io.Writer) (resultOut, progressOut io.Writer, closer func(), err error) {
	progressOut = stderr
	resultOut = stdout
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "" {
		return resultOut, progressOut, nil, nil
	}
	// Parent directories must already exist (cmd handlers cannot call os.MkdirAll).
	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open --output-file: %w", err)
	}
	fmt.Fprintf(progressOut, "Writing results to %s\n", outputFile)
	return f, progressOut, func() { _ = f.Close() }, nil
}

func runAutomaticSelection(cmd *cobra.Command, app *application.App, opts *runOptions, apiURL, profile *string, resultOut, progressOut io.Writer) error {
	// Flags that only apply to an explicit single-adversary local project loop.
	if opts.shell {
		return fmt.Errorf("--shell requires exactly one adversary reference")
	}
	if opts.force {
		return fmt.Errorf("--force is only valid with explicit adversary references")
	}
	if opts.build || opts.noBuild {
		return fmt.Errorf("--build is only valid with explicit adversary references")
	}
	if cmd.Flags().Changed("builder") {
		return fmt.Errorf("--builder is only valid with explicit adversary references")
	}
	if opts.keepTemp {
		return fmt.Errorf("--keep-temp is only valid with explicit adversary references")
	}
	if opts.noNetwork {
		return fmt.Errorf("--no-network is only valid with explicit adversary references")
	}
	if opts.verbose {
		return fmt.Errorf("--verbose is only valid with explicit adversary references")
	}

	minimum, err := detection.ParseConfidence(opts.minimumConfidence)
	if err != nil {
		return err
	}
	if !opts.noPull {
		if err := ensureAccessibleAdversaries(
			cmd.Context(),
			app,
			valueOf(apiURL),
			valueOf(profile),
			progressOut,
		); err != nil {
			return err
		}
	}
	// Selection/progress stays on the terminal (stderr when writing a result
	// file or JSON). Adversary review bodies go to resultOut.
	selectionOut := resultOut
	if opts.format == "json" || strings.TrimSpace(opts.outputFile) != "" {
		selectionOut = progressOut
	}
	autoResult, err := app.Dependencies().Runtime.Auto(cmd.Context(), application.AdversaryAutoOptions{
		RepoPath: opts.path, BaseRef: opts.base, HeadRef: opts.head, AllFiles: opts.allFiles,
		ModelProvider: opts.modelProvider, Model: opts.model,
		MinimumConfidence: minimum,
		Includes:          opts.includes, Excludes: opts.excludes,
		All: opts.all, DryRun: opts.dryRun, Explain: opts.explain, Format: opts.format,
		AllowUnsafeHostExecution: opts.allowUnsafeHostExecution, IncludeSuppressed: opts.includeSuppressed,
		RunTimeout: opts.runTimeout, DetectionTimeout: opts.detectionTimeout,
		Stdout: resultOut, Stderr: progressOut,
		ReportSelections: func(result application.AdversaryAutoResult) error {
			return renderRunSelections(selectionOut, result, opts.explain)
		},
		ReportRunStart: func(name string, index, total int) error {
			_, err := fmt.Fprintf(progressOut, "[%d/%d] %s\n", index, total, name)
			return err
		},
		ReportRunFinish: func(name string, index, total int, runErr error) error {
			switch {
			case runErr == nil:
				_, err := fmt.Fprintf(progressOut, "    ✓ done\n")
				return err
			default:
				var findings *internaladversary.FindingsError
				if errors.As(runErr, &findings) {
					_, err := fmt.Fprintf(progressOut, "    · findings: %d\n", findings.Count)
					return err
				}
				_, err := fmt.Fprintf(progressOut, "    ✗ %s\n", compactRunFailure(runErr, ""))
				return err
			}
		},
	})
	// Sanitized usage: CLI version + selected adversaries only (no flags/user/paths).
	// Skip dry-run (no actual execution) and empty selections.
	if !opts.dryRun {
		if selected := selectedAdversaryNames(autoResult); len(selected) > 0 {
			reportRunUsage(cmd.Context(), app, valueOf(apiURL), valueOf(profile), selected)
		}
	}
	if err == nil && strings.TrimSpace(opts.outputFile) != "" {
		fmt.Fprintf(progressOut, "Results written to %s\n", opts.outputFile)
	}
	return err
}

func selectedAdversaryNames(result application.AdversaryAutoResult) []string {
	var names []string
	for _, selection := range result.Selections {
		if !selection.Selected {
			continue
		}
		name := strings.TrimSpace(selection.Candidate.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func renderRunSelections(w io.Writer, result application.AdversaryAutoResult, explain bool) error {
	var output strings.Builder
	selected := 0
	for _, selection := range result.Selections {
		if selection.Selected {
			selected++
		}
	}
	if selected == 0 {
		fmt.Fprintln(&output, "No relevant adversaries detected for this change.")
	} else {
		fmt.Fprintf(&output, "Running %d adversaries\n", selected)
	}
	for _, selection := range result.Selections {
		if !selection.Selected && !explain {
			continue
		}
		name := selection.Candidate.Name
		if !selection.Selected {
			fmt.Fprintf(&output, "  ·  %-24s skipped", truncateRunes(name, 24))
			if selection.Excluded {
				fmt.Fprint(&output, " (--exclude)")
			}
			fmt.Fprintln(&output)
			if explain {
				for _, reason := range selection.Result.Reasons {
					fmt.Fprintf(&output, "       %s\n", terminalSafeText(reason))
				}
				if selection.Error != nil {
					fmt.Fprintf(&output, "       detector failure: %s\n", terminalSafeText(selection.Error.Error()))
				}
			}
			continue
		}
		// Compact one-line selection for the default path; --explain expands reasons.
		fmt.Fprintf(&output, "  →  %-24s %s", truncateRunes(name, 24), selection.Result.Confidence)
		if selection.Forced {
			fmt.Fprint(&output, " (include)")
		}
		fmt.Fprintln(&output)
		if explain {
			for _, reason := range selection.Result.Reasons {
				fmt.Fprintf(&output, "       %s\n", terminalSafeText(reason))
			}
			if len(selection.Result.RelevantFiles) > 0 {
				files := append([]string(nil), selection.Result.RelevantFiles...)
				sort.Strings(files)
				for i := range files {
					files[i] = terminalSafeText(files[i])
				}
				fmt.Fprintf(&output, "       files: %s\n", strings.Join(files, ", "))
			}
			if selection.Error != nil {
				fmt.Fprintf(&output, "       detector failure: %s\n", terminalSafeText(selection.Error.Error()))
			}
		}
	}
	if selected > 0 {
		fmt.Fprintln(&output)
	}
	_, err := io.WriteString(w, output.String())
	return err
}

func terminalSafeText(value string) string {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return strconv.QuoteToASCII(value)
	}
	return value
}

type multiRunItemDTO struct {
	Adversary string          `json:"adversary"`
	Output    json.RawMessage `json:"output,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type multiRunDTO struct {
	Results []multiRunItemDTO `json:"results"`
}

// runAdversaries runs one or more adversary refs with shared flags.
// Multiple refs concatenate reports (text sections or a JSON results array).
// When resultOut is an --output-file, progress lines go to progressOut only.
// Exit policy: first hard error wins after all runs; otherwise FindingsError with total count.
func runAdversaries(
	ctx context.Context,
	app *application.App,
	opts *runOptions,
	refs []string,
	apiURL, profile *string,
	resultOut, progressOut io.Writer,
) error {
	multi := len(refs) > 1
	jsonMode := opts.format == "json"
	toFile := strings.TrimSpace(opts.outputFile) != ""
	// Progress on multi-run or when results are redirected to a file.
	showProgress := toFile || multi

	// Sanitized usage: CLI version + requested adversary selection (1..n).
	reportRunUsage(ctx, app, valueOf(apiURL), valueOf(profile), refs)

	var items []multiRunItemDTO
	var findingsTotal int
	var hardErr error
	hardRef := ""

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if showProgress {
			fmt.Fprintf(progressOut, "[%d/%d] %s\n", i+1, len(refs), ref)
		}
		if multi && !jsonMode {
			if i > 0 {
				fmt.Fprintln(resultOut)
			}
			fmt.Fprintf(resultOut, "=== %s ===\n", ref)
		}

		var runStdout io.Writer = resultOut
		var outBuf bytes.Buffer
		if multi && jsonMode {
			runStdout = &outBuf
		}
		// Keep multi-run / output-file progress clean: capture child diagnostics
		// and print a one-line status instead of full Node stack traces.
		var childErr bytes.Buffer
		runStderr := progressOut
		if showProgress {
			runStderr = &childErr
		}

		err := runOneAdversary(ctx, app, opts, ref, runStdout, runStderr)
		if errors.Is(err, context.Canceled) {
			return err
		}

		item := multiRunItemDTO{Adversary: ref}
		// Only attach stdout when it is valid JSON so writeJSON can always encode
		// the multi-run envelope (Greptile: partial/stacktrace stdout broke RawMessage).
		nonJSONStdout := false
		if multi && jsonMode {
			raw := bytes.TrimSpace(outBuf.Bytes())
			if len(raw) > 0 {
				if json.Valid(raw) {
					item.Output = json.RawMessage(append([]byte(nil), raw...))
				} else {
					nonJSONStdout = true
				}
			}
		}

		var findings *internaladversary.FindingsError
		switch {
		case err == nil:
			if showProgress {
				writeProgressDiagnostics(progressOut, childErr.String())
				fmt.Fprintf(progressOut, "    ✓ done\n")
			}
		case errors.As(err, &findings):
			findingsTotal += findings.Count
			if showProgress {
				writeProgressDiagnostics(progressOut, childErr.String())
				fmt.Fprintf(progressOut, "    · findings: %d\n", findings.Count)
			}
		default:
			if hardErr == nil {
				hardErr = err
				hardRef = ref
			}
			if multi && jsonMode {
				item.Error = err.Error()
			}
			if showProgress {
				writeProgressDiagnostics(progressOut, childErr.String())
				fmt.Fprintf(progressOut, "    ✗ %s\n", compactRunFailure(err, childErr.String()))
			} else if multi && !jsonMode {
				fmt.Fprintf(progressOut, "adversary %q failed: %v\n", ref, err)
			}
		}
		if multi && jsonMode {
			if nonJSONStdout {
				// Non-JSON stdout is a hard failure even when the runtime returned
				// nil or FindingsError (Greptile: item.error alone left exit success).
				item.Error = joinMultiRunError(item.Error, "adversary wrote non-JSON stdout")
				if hardErr == nil {
					hardErr = fmt.Errorf("adversary wrote non-JSON stdout")
					hardRef = ref
				}
			}
			items = append(items, item)
		}
	}

	if multi && jsonMode {
		if err := writeJSON(resultOut, "run", multiRunDTO{Results: items}); err != nil {
			return err
		}
	}
	if multi || toFile {
		fmt.Fprintf(progressOut, "\nRan %d adversaries", len(refs))
		if findingsTotal > 0 {
			fmt.Fprintf(progressOut, " · findings: %d", findingsTotal)
		}
		if hardErr != nil {
			fmt.Fprintf(progressOut, " · errors: 1+")
		}
		fmt.Fprintln(progressOut)
	}
	if toFile {
		fmt.Fprintf(progressOut, "Results written to %s\n", opts.outputFile)
	}

	if hardErr != nil {
		if multi {
			return fmt.Errorf("adversary %q failed: %w", hardRef, hardErr)
		}
		return hardErr
	}
	if findingsTotal > 0 {
		return &internaladversary.FindingsError{Count: findingsTotal}
	}
	return nil
}

func joinMultiRunError(existing, next string) string {
	if existing == "" {
		return next
	}
	if next == "" {
		return existing
	}
	return existing + "; " + next
}

// writeProgressDiagnostics forwards important runner warnings that were captured
// while muting noisy host-process stderr during multi-run progress.
func writeProgressDiagnostics(w io.Writer, buffered string) {
	for _, line := range strings.Split(buffered, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "WARNING:") {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
}

// compactRunFailure turns nested host/Node failures into a short progress line.
func compactRunFailure(err error, childStderr string) string {
	if msg := firstInterestingErrorLine(childStderr); msg != "" {
		return truncateRunes(msg, 120)
	}
	if err == nil {
		return "failed"
	}
	msg := err.Error()
	for _, prefix := range []string{
		"host execution failed (child exit 1): ",
		"host execution failed: ",
		"adversary execution failed: ",
	} {
		if strings.HasPrefix(msg, prefix) {
			msg = strings.TrimPrefix(msg, prefix)
			break
		}
	}
	return truncateRunes(msg, 120)
}

func firstInterestingErrorLine(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Prefer the actual Node error line over stack frames.
		if strings.Contains(line, "Error [") || strings.HasPrefix(line, "Error:") || strings.Contains(line, "ERR_") {
			return line
		}
	}
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "at ") && !strings.HasPrefix(line, "Node.js") {
			return line
		}
	}
	return ""
}

func runOneAdversary(
	ctx context.Context,
	app *application.App,
	opts *runOptions,
	ref string,
	stdout, stderr io.Writer,
) error {
	runOpts := application.AdversaryRunOptions{
		AdversaryRef:             ref,
		RepoPath:                 opts.path,
		BaseRef:                  opts.base,
		HeadRef:                  opts.head,
		Builder:                  opts.builder,
		ModelProvider:            opts.modelProvider,
		Model:                    opts.model,
		Force:                    opts.force,
		Format:                   opts.format,
		KeepTemp:                 opts.keepTemp,
		NoNetwork:                opts.noNetwork,
		Verbose:                  opts.verbose,
		IncludeSuppressed:        opts.includeSuppressed,
		Shell:                    opts.shell,
		AllFiles:                 opts.allFiles,
		AllowUnsafeHostExecution: opts.allowUnsafeHostExecution,
		Build:                    opts.build,
		RunTimeout:               opts.runTimeout,
		BuildTimeout:             opts.buildTimeout,
		Stdout:                   stdout,
		Stderr:                   stderr,
	}
	err := app.Dependencies().Runtime.Run(ctx, runOpts)
	if errors.Is(err, context.Canceled) {
		return err
	}
	if err != nil && errors.Is(err, internaladversary.ErrNotInstalledLocally) {
		// AMB-11: auto-pull if not present locally, then retry once.
		fmt.Fprintln(stderr, "Adversary not present locally; attempting pull...")
		_, pullErr := pullAdversary(ctx, ref, app.Dependencies().DefaultAPIURL, "default", app, stderr)
		if pullErr != nil {
			return fmt.Errorf("auto-pull for %s failed: %w (original error: %v)", ref, pullErr, err)
		}
		err = app.Dependencies().Runtime.Run(ctx, runOpts)
		if errors.Is(err, context.Canceled) {
			return err
		}
	}
	return err
}
