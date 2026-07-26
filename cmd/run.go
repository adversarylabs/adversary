package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
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
	keepTemp                 bool
	noNetwork                bool
	verbose                  bool
	debug                    bool
	includeSuppressed        bool
	shell                    bool
	allFiles                 bool
	allowUnsafeHostExecution bool
	build                    bool
	noBuild                  bool
	runTimeout               time.Duration
	buildTimeout             time.Duration
}

func newRunCommand(app *application.App) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run <adversary-ref> [adversary-ref...]",
		Short: "Run one or more Adversaries against a local source repository",
		Example: `  adversary run adversarylabs/dockerfile
  adversary run ./local-adversary --path ../project
  adversary run adversarylabs/dockerfile --base main
  adversary run adversarylabs/dockerfile --base main --head feature
  adversary run adversarylabs/dockerfile --all-files
  adversary run adversarylabs/go-cli --model-provider fireworks --model accounts/fireworks/models/your-model-id
  adversary run adversarylabs/go-cli adversarylabs/secrets --path . --all-files`,
		Args: cobra.MinimumNArgs(1),
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
			if opts.build && opts.noBuild {
				return fmt.Errorf("--build and --no-build cannot be combined")
			}
			if opts.runTimeout < 0 || opts.buildTimeout < 0 {
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

			return runAdversaries(cmd.Context(), app, opts, args, cmd.OutOrStdout(), cmd.ErrOrStderr())
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
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "require network access to be disabled (fails if the executor cannot enforce it)")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.debug, "debug", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.includeSuppressed, "include-suppressed", false, "request suppressed review findings when supported by the runtime")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "UNSAFE: launch an unrestricted host shell in the adversary working directory")
	cmd.Flags().BoolVar(&opts.allowUnsafeHostExecution, "allow-unsafe-host-execution", false, "explicitly allow unrestricted HostExecutor use for an unknown publisher")
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan the entire target instead of inferring a change")
	cmd.Flags().BoolVar(&opts.build, "build", false, "build a local adversary before running (may update dist)")
	cmd.Flags().BoolVar(&opts.noBuild, "no-build", false, "deprecated compatibility flag; local builds are skipped by default")
	_ = cmd.Flags().MarkDeprecated("no-build", "local builds are skipped by default; omit this flag")
	cmd.Flags().DurationVar(&opts.runTimeout, "timeout", 0, "maximum adversary execution time (0 disables the deadline)")
	cmd.Flags().DurationVar(&opts.buildTimeout, "build-timeout", 10*time.Minute, "maximum explicit local build time")

	return cmd
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
// Exit policy: first hard error wins after all runs; otherwise FindingsError with total count.
func runAdversaries(
	ctx context.Context,
	app *application.App,
	opts *runOptions,
	refs []string,
	stdout, stderr io.Writer,
) error {
	multi := len(refs) > 1
	jsonMode := opts.format == "json"

	var items []multiRunItemDTO
	var findingsTotal int
	var hardErr error
	hardRef := ""

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if multi && !jsonMode {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "=== %s ===\n", ref)
		}

		var runStdout io.Writer = stdout
		var buf bytes.Buffer
		if multi && jsonMode {
			runStdout = &buf
		}

		err := runOneAdversary(ctx, app, opts, ref, runStdout, stderr)
		if errors.Is(err, context.Canceled) {
			return err
		}

		item := multiRunItemDTO{Adversary: ref}
		if multi && jsonMode {
			raw := bytes.TrimSpace(buf.Bytes())
			if len(raw) > 0 {
				item.Output = json.RawMessage(append([]byte(nil), raw...))
			}
		}

		var findings *internaladversary.FindingsError
		switch {
		case err == nil:
		case errors.As(err, &findings):
			findingsTotal += findings.Count
			if multi && jsonMode && item.Error == "" {
				// Findings still produced output; keep output, note via aggregate only.
			}
		default:
			if hardErr == nil {
				hardErr = err
				hardRef = ref
			}
			if multi && jsonMode {
				item.Error = err.Error()
			}
			if multi && !jsonMode {
				fmt.Fprintf(stderr, "adversary %q failed: %v\n", ref, err)
			}
		}
		if multi && jsonMode {
			items = append(items, item)
		}
	}

	if multi && jsonMode {
		if err := writeJSON(stdout, "run", multiRunDTO{Results: items}); err != nil {
			return err
		}
	}
	if multi {
		fmt.Fprintf(stderr, "\nRan %d adversaries", len(refs))
		if findingsTotal > 0 {
			fmt.Fprintf(stderr, " · findings: %d", findingsTotal)
		}
		if hardErr != nil {
			fmt.Fprintf(stderr, " · errors: 1+")
		}
		fmt.Fprintln(stderr)
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
