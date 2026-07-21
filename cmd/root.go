package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/version"
	"github.com/adversarylabs/adversary/pkg/review"
	"github.com/spf13/cobra"
)

func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), processSignals()...)
	defer stop()
	app, err := newProcessApp(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	root := NewRootCommandWithApp(app)
	root.SetContext(ctx)
	if err := root.Execute(); err != nil {
		var findings *internaladversary.FindingsError
		if !errors.As(err, &findings) {
			fmt.Fprintln(os.Stderr, err)
		}
		return err
	}
	return nil
}

func NewRootCommandWithApp(app *application.App) *cobra.Command {
	return newRootCommand(app)
}
func newRootCommand(app *application.App) *cobra.Command {
	deps := app.Dependencies()
	var apiURL string
	var profile string
	cmd := &cobra.Command{
		Use:           "adversary",
		Short:         "Run source-code adversaries against a local repository",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.Version = fmt.Sprintf("%s (commit %s, built %s, %s, review protocol %d)", version.Version, version.Commit, version.BuildDate, runtime.Version(), review.ProtocolVersion)
	cmd.SetVersionTemplate("adversary {{.Version}}\n")
	cmd.SetIn(deps.Stdin)
	cmd.SetOut(deps.Stdout)
	cmd.SetErr(deps.Stderr)
	cmd.PersistentFlags().StringVar(&apiURL, "api-url", deps.DefaultAPIURL, "Adversary Labs API endpoint (or ADVERSARY_API_URL)")
	cmd.PersistentFlags().StringVar(&profile, "profile", "default", "credential profile")

	cmd.AddCommand(newRunCommand(app))
	cmd.AddCommand(newAutoCommand(app))
	cmd.AddCommand(newInspectCommand(app))
	cmd.AddCommand(newValidateCommand(app))
	cmd.AddCommand(newInitCommand(app))
	cmd.AddCommand(newPackCommand(app))
	cmd.AddCommand(newListCommand(app))
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newLoginCommand(app, &apiURL, &profile))
	cmd.AddCommand(newLogoutCommand(app, &apiURL, &profile))
	cmd.AddCommand(newPushCommand(app, &apiURL, &profile))
	cmd.AddCommand(newPullCommand(app, &apiURL, &profile))
	cmd.AddCommand(newSearchCommand(app, &apiURL, &profile))
	cmd.AddCommand(newWhoamiCommand(app, &apiURL, &profile))
	cmd.AddCommand(newStoreCommand(app))
	cmd.AddCommand(newCompletionCommand(cmd))
	classifyCommandErrors(cmd)
	return cmd
}

func classifyCommandErrors(root *cobra.Command) {
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		if command.Args != nil {
			args := command.Args
			command.Args = func(cmd *cobra.Command, values []string) error {
				if err := args(cmd, values); err != nil {
					return &application.Error{Operation: "parse arguments", Kind: "usage", Err: err}
				}
				return nil
			}
		}
		command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
			return &application.Error{Operation: "parse flags", Kind: "usage", Err: err}
		})
		if command.RunE != nil {
			run := command.RunE
			command.RunE = func(cmd *cobra.Command, values []string) error {
				err := run(cmd, values)
				if err == nil || isTypedCommandError(err) {
					return err
				}
				return &application.Error{Operation: cmd.CommandPath(), Kind: "configuration", Err: err}
			}
		}
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(root)
}

func isTypedCommandError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var appErr *application.Error
	var findings *internaladversary.FindingsError
	var child *internaladversary.ChildExitError
	var protocol *internaladversary.ProtocolError
	var execution *internaladversary.ExecutionError
	var autoExecution *internaladversary.AutoExecutionError
	return errors.As(err, &appErr) || errors.As(err, &findings) || errors.As(err, &child) || errors.As(err, &protocol) || errors.As(err, &execution) || errors.As(err, &autoExecution)
}
