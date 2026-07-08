package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/initproject"
	"github.com/spf13/cobra"
)

func Execute() error {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "adversary",
		Short:         "Run containerized source-code adversaries against a local repository",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.AddCommand(newRunCommand(stdout, stderr))
	cmd.AddCommand(newInspectCommand(stdout, stderr))
	cmd.AddCommand(newInitCommand(stdout, stderr))
	return cmd
}

type runOptions struct {
	repo      string
	base      string
	head      string
	force     bool
	format    string
	keepTemp  bool
	noNetwork bool
	build     bool
	noBuild   bool
	verbose   bool
	shell     bool
	allFiles  bool
}

type initOptions struct {
	sdk string
}

func newRunCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run <adversary-ref>",
		Short: "Run an Adversary against a local source repository",
		Example: `  adversary run ./smoke-tests/comment-sentence-adversary --repo .
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --verbose
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --format json
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --base main --head HEAD --all-files
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --shell
  adversary run ./smoke-tests/comment-sentence-adversary --repo . --no-build`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.format != "text" && opts.format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
			if opts.build && opts.noBuild {
				return fmt.Errorf("--build and --no-build cannot be used together")
			}

			runner := adversary.Runner{
				Stdout: stdout,
				Stderr: stderr,
			}

			err := runner.Run(cmd.Context(), adversary.RunOptions{
				AdversaryRef: args[0],
				RepoPath:     opts.repo,
				BaseRef:      opts.base,
				HeadRef:      opts.head,
				Force:        opts.force,
				Format:       opts.format,
				KeepTemp:     opts.keepTemp,
				NoNetwork:    opts.noNetwork,
				Build:        opts.build,
				NoBuild:      opts.noBuild,
				Verbose:      opts.verbose,
				Shell:        opts.shell,
				AllFiles:     opts.allFiles,
			})
			if errors.Is(err, context.Canceled) {
				return err
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().StringVar(&opts.base, "base", "", "git base ref for change context")
	cmd.Flags().StringVar(&opts.head, "head", "", "git head ref for change context")
	cmd.Flags().BoolVar(&opts.force, "force", false, "run even when triggers.files_changed does not match")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "force container network disabled")
	cmd.Flags().BoolVar(&opts.build, "build", false, "build a local directory adversary image before running")
	cmd.Flags().BoolVar(&opts.noBuild, "no-build", false, "skip building a local directory adversary image")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "print detailed execution diagnostics")
	cmd.Flags().BoolVar(&opts.shell, "shell", false, "launch an interactive shell in the configured container")
	cmd.Flags().BoolVar(&opts.allFiles, "all-files", false, "scan all files even when diff refs are provided")

	return cmd
}

func newInspectCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "inspect <adversary-ref>",
		Short: "Inspect a local adversary runtime configuration",
		Example: `  adversary inspect ./smoke-tests/comment-sentence-adversary --repo .
  adversary inspect adversarylabs/dockerfile --repo .`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runner := adversary.Runner{
				Stdout: stdout,
				Stderr: stderr,
			}
			return runner.Inspect(adversary.RunOptions{
				AdversaryRef: args[0],
				RepoPath:     opts.repo,
				NoNetwork:    opts.noNetwork,
			})
		},
	}

	cmd.Flags().StringVar(&opts.repo, "repo", ".", "path to the local source repository")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "force container network disabled")

	return cmd
}

func newInitCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &initOptions{}

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Create a new adversary project",
		Example: `  adversary init my-adversary
  adversary init my-adversary --sdk typescript`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := initproject.Create(initproject.Options{
				Destination: args[0],
				SDK:         opts.sdk,
			})
			if err != nil {
				return err
			}
			initproject.RenderSuccess(stdout, result, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.sdk, "sdk", initproject.DefaultSDK, "SDK template to use: typescript")

	return cmd
}
