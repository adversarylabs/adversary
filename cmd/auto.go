package cmd

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/spf13/cobra"
)

type autoOptions struct {
	path                     string
	minimumConfidence        string
	includes                 []string
	excludes                 []string
	dryRun                   bool
	explain                  bool
	all                      bool
	noPull                   bool
	allowUnsafeHostExecution bool
	includeSuppressed        bool
	runTimeout               time.Duration
	detectionTimeout         time.Duration
}

func newAutoCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	opts := &autoOptions{}
	cmd := &cobra.Command{
		Use:   "auto [base-ref|base...head]",
		Short: "Pull accessible adversaries, detect relevance, and run the selected set",
		Long: `Pull every adversary you can access from the remote catalog (unless --no-pull),
then detect which ones apply to the resolved Git change and run them.

Detection still selects relevance by default. Use --all to run every installed
adversary after the pull step. Offline or local-only use: pass --no-pull.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  adversary auto
  adversary auto main
  adversary auto main...HEAD
  adversary auto --dry-run --explain
  adversary auto --all
  adversary auto --no-pull
  adversary auto --include security --exclude repository`,
		RunE: func(cmd *cobra.Command, args []string) error {
			minimum, err := detection.ParseConfidence(opts.minimumConfidence)
			if err != nil {
				return err
			}
			if opts.runTimeout < 0 || opts.detectionTimeout < 0 {
				return fmt.Errorf("timeouts cannot be negative")
			}
			if !opts.noPull {
				if err := ensureAccessibleAdversaries(
					cmd.Context(),
					app,
					valueOf(apiURL),
					valueOf(profile),
					cmd.ErrOrStderr(),
				); err != nil {
					return err
				}
			}
			argument := ""
			if len(args) == 1 {
				argument = args[0]
			}
			_, err = app.Dependencies().Runtime.Auto(cmd.Context(), application.AdversaryAutoOptions{
				ChangeArgument: argument, RepoPath: opts.path, MinimumConfidence: minimum,
				Includes: opts.includes, Excludes: opts.excludes, All: opts.all, DryRun: opts.dryRun, Explain: opts.explain,
				AllowUnsafeHostExecution: opts.allowUnsafeHostExecution, IncludeSuppressed: opts.includeSuppressed,
				RunTimeout: opts.runTimeout, DetectionTimeout: opts.detectionTimeout,
				Stdout: cmd.OutOrStdout(), Stderr: cmd.ErrOrStderr(),
				ReportSelections: func(result application.AdversaryAutoResult) error {
					return renderAutoSelections(cmd, result, opts.explain)
				},
			})
			return err
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", ".", "path to the Git source directory")
	cmd.Flags().StringVar(&opts.minimumConfidence, "min-confidence", "medium", "minimum confidence to run: low, medium, or high")
	cmd.Flags().StringArrayVar(&opts.includes, "include", nil, "force an available adversary to run (repeatable)")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "exclude an adversary from the run (repeatable; wins over include)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "resolve and print selections without running adversaries")
	cmd.Flags().BoolVar(&opts.explain, "explain", false, "show selected and skipped adversaries with reasons")
	cmd.Flags().BoolVar(&opts.all, "all", false, "run every available adversary without detection filtering")
	cmd.Flags().BoolVar(&opts.noPull, "no-pull", false, "do not pull remote adversaries; use only the local store")
	cmd.Flags().BoolVar(&opts.allowUnsafeHostExecution, "allow-unsafe-host-execution", false, "explicitly allow unrestricted HostExecutor use for an unknown publisher")
	cmd.Flags().BoolVar(&opts.includeSuppressed, "include-suppressed", false, "request suppressed review findings when supported by the runtime")
	cmd.Flags().DurationVar(&opts.runTimeout, "timeout", 0, "maximum time for each adversary execution (0 disables the deadline)")
	cmd.Flags().DurationVar(&opts.detectionTimeout, "detection-timeout", 30*time.Second, "maximum time for each programmatic detector")
	return cmd
}

func renderAutoSelections(cmd *cobra.Command, result application.AdversaryAutoResult, explain bool) error {
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
		fmt.Fprintf(&output, "Detected %d relevant adversaries\n", selected)
	}
	for _, selection := range result.Selections {
		if !selection.Selected && !explain {
			continue
		}
		status := ""
		if !selection.Selected {
			status = " (skipped)"
		}
		fmt.Fprintf(&output, "\n%s%s\n", selection.Candidate.Name, status)
		fmt.Fprintf(&output, "  %s confidence\n", selection.Result.Confidence)
		if selection.Excluded {
			fmt.Fprintln(&output, "  excluded by --exclude")
		} else if selection.Forced {
			fmt.Fprintln(&output, "  forced by --include")
		}
		for _, reason := range selection.Result.Reasons {
			fmt.Fprintf(&output, "  %s\n", terminalSafeText(reason))
		}
		if explain && len(selection.Result.RelevantFiles) > 0 {
			files := append([]string(nil), selection.Result.RelevantFiles...)
			sort.Strings(files)
			for i := range files {
				files[i] = terminalSafeText(files[i])
			}
			fmt.Fprintf(&output, "  relevant files: %s\n", strings.Join(files, ", "))
		}
		if explain && selection.Error != nil {
			fmt.Fprintf(&output, "  detector failure: %s\n", terminalSafeText(selection.Error.Error()))
		}
	}
	if selected > 0 {
		fmt.Fprintln(&output)
	}
	_, err := io.WriteString(cmd.OutOrStdout(), output.String())
	return err
}

func terminalSafeText(value string) string {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return strconv.QuoteToASCII(value)
	}
	return value
}
