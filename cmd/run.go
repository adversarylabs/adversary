package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

type runOptions struct {
	repo                     string
	base                     string
	head                     string
	builder                  string
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
		Use:   "run <adversary-ref>",
		Short: "Run an Adversary against a local source repository",
		Example: `  adversary run ./smoke-tests/comment-sentence-adversary --repo .
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --format json
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD --all-files
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, opts.json)
			if err != nil {
				return err
			}
			if opts.debug && cmd.Flags().Changed("verbose") {
				return fmt.Errorf("--debug and --verbose cannot be combined")
			}
			if (opts.base == "") != (opts.head == "") {
				return fmt.Errorf("--base and --head must be provided together")
			}
			if opts.builder != "local" && opts.builder != "docker" {
				return fmt.Errorf("--builder must be local or docker")
			}
			if opts.shell && opts.noNetwork {
				return fmt.Errorf("--shell cannot be combined with --no-network because the host shell cannot enforce network isolation")
			}
			if opts.shell && format == "json" {
				return fmt.Errorf("--shell cannot be combined with JSON output")
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

			err = app.Dependencies().Runtime.Run(cmd.Context(), application.AdversaryRunOptions{
				AdversaryRef:             args[0],
				RepoPath:                 opts.repo,
				BaseRef:                  opts.base,
				HeadRef:                  opts.head,
				Builder:                  opts.builder,
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
				Stdout:                   cmd.OutOrStdout(),
				Stderr:                   cmd.ErrOrStderr(),
			})
			if errors.Is(err, context.Canceled) {
				return err
			}
			if err != nil && errors.Is(err, internaladversary.ErrNotInstalledLocally) {
				// AMB-11: auto-pull if not present locally, then retry once.
				fmt.Fprintln(cmd.ErrOrStderr(), "Adversary not present locally; attempting pull...")
				_, pullErr := pullAdversary(cmd.Context(), args[0], app.Dependencies().DefaultAPIURL, "default", app, cmd.ErrOrStderr())
				if pullErr != nil {
					return fmt.Errorf("auto-pull for %s failed: %w (original error: %v)", args[0], pullErr, err)
				}
				// retry
				err = app.Dependencies().Runtime.Run(cmd.Context(), application.AdversaryRunOptions{
					AdversaryRef:             args[0],
					RepoPath:                 opts.repo,
					BaseRef:                  opts.base,
					HeadRef:                  opts.head,
					Builder:                  opts.builder,
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
					Stdout:                   cmd.OutOrStdout(),
					Stderr:                   cmd.ErrOrStderr(),
				})
				if errors.Is(err, context.Canceled) {
					return err
				}
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().StringVar(&opts.base, "base", "", "git base ref for change context")
	cmd.Flags().StringVar(&opts.head, "head", "", "git head ref for change context")
	cmd.Flags().StringVar(&opts.builder, "builder", "local", "build mechanism for local adversaries: local or docker")
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
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan all files even when diff refs are provided")
	cmd.Flags().BoolVar(&opts.build, "build", false, "build a local adversary before running (may update dist)")
	cmd.Flags().BoolVar(&opts.noBuild, "no-build", false, "deprecated compatibility flag; local builds are skipped by default")
	_ = cmd.Flags().MarkDeprecated("no-build", "local builds are skipped by default; omit this flag")
	cmd.Flags().DurationVar(&opts.runTimeout, "timeout", 0, "maximum adversary execution time (0 disables the deadline)")
	cmd.Flags().DurationVar(&opts.buildTimeout, "build-timeout", 10*time.Minute, "maximum explicit local build time")

	return cmd
}
