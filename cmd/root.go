package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/adversarylabs/adversary/internal/adversary"
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
}

func newRunCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := &runOptions{}

	cmd := &cobra.Command{
		Use:   "run <adversary-ref>",
		Short: "Run an Adversary against a local source repository",
		Example: `  adversary run adversarylabs/dockerfile
  adversary run adversarylabs/github-actions --repo .
  adversary run adversarylabs/github-actions --base main --head HEAD
  adversary run adversarylabs/github-actions --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.format != "text" && opts.format != "json" {
				return fmt.Errorf("--format must be text or json")
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
	cmd.Flags().BoolVar(&opts.force, "force", false, "run even when run_when.files_changed does not match")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.keepTemp, "keep-temp", false, "do not delete the temporary run directory")
	cmd.Flags().BoolVar(&opts.noNetwork, "no-network", false, "force container network disabled")

	return cmd
}
