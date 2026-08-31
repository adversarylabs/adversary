package cmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/feedback"
	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/spf13/cobra"
)

func newFeedbackCommand(_ *application.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feedback",
		Short: "Capture human feedback on Adversary pull-request comments",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newFeedbackIngestCommand())
	return cmd
}

func newFeedbackIngestCommand() *cobra.Command {
	var (
		eventPath                   string
		stateDir                    string
		issueRepository             string
		issueOwner                  string
		createIssue                 bool
		acknowledge                 bool
		trustedRootLogin            []string
		allowPrivateCrossRepository bool
		format                      string
		restURL                     string
	)
	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Ingest a pull_request_review_comment reply event",
		Long: `Read a GitHub pull_request_review_comment.created event, verify that it
replies to an Adversary-marked inline finding, and store a versioned feedback
candidate. Trusted, substantive rebuttals can open a deduplicated issue in the
owning adversary repository. After the candidate is recorded and handed off,
Adversary replies in the original thread to acknowledge that it learned from the
feedback. Package behavior is never changed directly by this command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			eventPath = strings.TrimSpace(eventPath)
			if eventPath == "" {
				return fmt.Errorf("--event-path is required (or set GITHUB_EVENT_PATH)")
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("--format must be text or json")
			}
			event, err := feedback.LoadEvent(eventPath)
			if err != nil {
				return err
			}
			client := githubapi.NewClient(githubapi.TokenFromEnv())
			if strings.TrimSpace(restURL) != "" {
				client.RESTBase = restURL
			}
			result, err := feedback.Process(cmd.Context(), client, event, feedback.Options{
				StateDir: stateDir, IssueRepository: issueRepository, IssueOwner: issueOwner,
				CreateIssue: createIssue, Acknowledge: acknowledge,
				TrustedRootLogins:           trustedRootLogin,
				AllowPrivateCrossRepository: allowPrivateCrossRepository,
			})
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored %s feedback at %s\n", result.Record.Classification, result.RecordPath)
			if result.Issue.HTMLURL != "" {
				verb := "Created"
				if result.IssueReused {
					verb = "Reused"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s improvement issue %s\n", verb, result.Issue.HTMLURL)
			}
			if result.Acknowledged {
				fmt.Fprintln(cmd.OutOrStdout(), "Acknowledged the feedback in the pull-request thread")
			}
			return nil
		},
	}
	if value, ok := githubapi.LookupEnv("GITHUB_EVENT_PATH"); ok {
		eventPath = value
	}
	defaultStateDir := ".adversary-feedback"
	if value, ok := githubapi.LookupEnv("RUNNER_TEMP"); ok && strings.TrimSpace(value) != "" {
		defaultStateDir = filepath.Join(value, "adversary-feedback")
	}
	cmd.Flags().StringVar(&eventPath, "event-path", eventPath, "GitHub webhook event JSON path (default GITHUB_EVENT_PATH)")
	cmd.Flags().StringVar(&stateDir, "state-dir", defaultStateDir, "directory for durable feedback records (defaults under RUNNER_TEMP in Actions)")
	cmd.Flags().StringVar(&issueRepository, "issue-repository", "", "owning adversary issue repository (owner/name; inferred for official packages)")
	cmd.Flags().StringVar(&issueOwner, "issue-owner", "adversarylabs", "default owner for inferred official adversary repositories")
	cmd.Flags().BoolVar(&createIssue, "create-issue", true, "open a deduplicated improvement issue for trusted substantive rebuttals")
	cmd.Flags().BoolVar(&acknowledge, "acknowledge", true, "reply after feedback is durably recorded and handed off")
	cmd.Flags().StringSliceVar(&trustedRootLogin, "trusted-root-login", nil, "additional non-bot login allowed to own marked findings")
	cmd.Flags().BoolVar(&allowPrivateCrossRepository, "allow-private-cross-repository-feedback", false, "allow copying private PR feedback into a different issue repository")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&restURL, "github-rest-url", "", "GitHub REST base URL override")
	return cmd
}
