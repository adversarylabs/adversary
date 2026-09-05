package cmd

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"strings"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/review"
)

// peelPRURL extracts at most one GitHub PR URL from args; remaining are adversary refs.
func peelPRURL(args []string) (pr *githubapi.PRRef, rest []string, err error) {
	var urls []string
	for _, a := range args {
		if _, ok := githubapi.ParseGitHubPRURL(a); ok {
			urls = append(urls, a)
		} else {
			rest = append(rest, a)
		}
	}
	if len(urls) > 1 {
		return nil, nil, fmt.Errorf("only one GitHub pull request URL is allowed")
	}
	if len(urls) == 1 {
		ref, _ := githubapi.ParseGitHubPRURL(urls[0])
		pr = &ref
	}
	return pr, rest, nil
}

// resolvePRRunContext fills path/base/head and github pr/repo from a PR URL or flags.
func resolvePRRunContext(ctx context.Context, opts *runOptions, progress io.Writer) error {
	if opts.prURL != nil {
		if opts.githubPR != 0 && opts.githubPR != opts.prURL.Number {
			return fmt.Errorf("--github-pr %d disagrees with PR URL number %d", opts.githubPR, opts.prURL.Number)
		}
		if opts.githubRepo != "" {
			want := opts.prURL.Owner + "/" + opts.prURL.Repo
			if !strings.EqualFold(opts.githubRepo, want) {
				return fmt.Errorf("--github-repo %q disagrees with PR URL %q", opts.githubRepo, want)
			}
		}
		opts.githubPR = opts.prURL.Number
		opts.githubRepo = opts.prURL.Owner + "/" + opts.prURL.Repo
	}

	if opts.prURL == nil && !opts.githubReview {
		return nil
	}

	needMeta := opts.prURL != nil || (opts.githubReview && opts.githubPR > 0 && opts.githubRepo != "")
	if !needMeta {
		return nil
	}

	owner, repo := opts.githubRepoOwner()
	if owner == "" || repo == "" || opts.githubPR <= 0 {
		if opts.prURL != nil {
			return fmt.Errorf("internal: PR URL missing owner/repo/number")
		}
		return nil
	}

	token := githubapi.TokenFromEnv()
	client := githubapi.NewClient(token)
	if opts.githubRESTURL != "" {
		client.RESTBase = opts.githubRESTURL
	}
	if opts.githubAPIURL != "" {
		client.GQLURL = opts.githubAPIURL
	}

	// PR URL path: prepare workspace (fetch/clone). Review-only flags: just metadata for base/head.
	if opts.prURL != nil {
		ws, err := githubreview.PreparePRWorkspace(ctx, client, owner, repo, opts.githubPR, opts.path, opts.base, opts.head, progress)
		if err != nil {
			kind := "network"
			if token == "" {
				kind = "auth"
			}
			return &application.Error{Operation: "resolve-pr", Kind: kind, Err: fmt.Errorf("fetch PR metadata: %w", err)}
		}
		opts.base = ws.BaseSHA
		opts.head = ws.HeadSHA
		opts.path = ws.Path
		opts.tempPRDir = ws.TempDir
		opts.worktreeRoot = ws.WorktreeRoot
		opts.resolvedHeadSHA = ws.HeadSHA
		return nil
	}

	// No URL: still fill base/head from API when posting with explicit pr/repo.
	pr, err := client.GetPullRequest(ctx, owner, repo, opts.githubPR)
	if err != nil {
		return &application.Error{Operation: "resolve-pr", Kind: "network", Err: fmt.Errorf("fetch PR metadata: %w", err)}
	}
	baseSHA := strings.TrimSpace(pr.Base.SHA)
	headSHA := strings.TrimSpace(pr.Head.SHA)
	if opts.base == "" {
		opts.base = baseSHA
	}
	if opts.head == "" {
		opts.head = headSHA
	}
	opts.resolvedHeadSHA = headSHA
	if progress != nil {
		fmt.Fprintf(progress, "Resolved PR %s/%s#%d → base %s… head %s…\n",
			owner, repo, opts.githubPR, shortSHA(baseSHA), shortSHA(headSHA))
	}
	return nil
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func (o *runOptions) githubRepoOwner() (owner, repo string) {
	parts := strings.SplitN(strings.TrimSpace(o.githubRepo), "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func maybeGitHubReview(ctx context.Context, opts *runOptions, envelopes []githubreview.NamedEnvelope, progress io.Writer) error {
	if !opts.githubReview {
		return nil
	}
	if opts.shell {
		return fmt.Errorf("--github-review cannot be combined with --shell")
	}

	owner, repo := opts.githubRepoOwner()
	if owner == "" || repo == "" || opts.githubPR <= 0 {
		// Actions auto-detect via githubapi token env helpers (no os in cmd).
		repoEnv, prN := githubreview.ActionsContext(githubapi.LookupEnv)
		if (owner == "" || repo == "") && repoEnv != "" {
			opts.githubRepo = repoEnv
			owner, repo = opts.githubRepoOwner()
		}
		if opts.githubPR <= 0 && prN > 0 {
			opts.githubPR = prN
		}
		owner, repo = opts.githubRepoOwner()
	}
	if owner == "" || repo == "" || opts.githubPR <= 0 {
		return &application.Error{
			Operation: "github-review",
			Kind:      "usage",
			Err:       fmt.Errorf("--github-review requires --github-pr and --github-repo, a PR URL, or Actions pull_request context"),
		}
	}

	// Prefer package agent/voice.md (adversary identity), then target --path.
	voiceRoots := append([]string{}, opts.adversaryPackageRoots...)
	voiceRoots = append(voiceRoots, opts.path)
	voicePrompt, voiceInfo := githubreview.ResolveVoice(voiceRoots...)

	plan := githubreview.ProjectFindings(envelopes, githubreview.ProjectOptions{
		Repository:  owner + "/" + repo,
		PullRequest: opts.githubPR,
		MinSeverity: opts.githubMinSeverity,
		Voice:       voiceInfo,
		OmitSummary: !opts.githubIncludeSummary,
	})

	// Default voice rewrite: try model provider; template remains on failure/missing creds.
	// BuildRewritePrompt (inside EnhanceBodies) wraps agent/voice.md so Example maintainer
	// comments banks are used as few-shot style when generating comment text.
	if provider, err := modelreview.ProviderFromConfig(modelreview.Config{
		Provider: opts.modelProvider,
		Model:    opts.model,
	}, githubapi.LookupEnv, nil); err == nil && provider != nil {
		githubreview.EnhanceBodies(ctx, &plan, githubreview.EnhanceOptions{
			Provider:    provider,
			VoicePrompt: voicePrompt,
		})
		githubreview.EnhanceSummary(ctx, &plan, githubreview.EnhanceOptions{Provider: provider})
	}
	// Execution status is host-authored, not model-rewritten or suppressed by
	// --github-include-summary=false. Findings still use normal inline placement.
	if len(opts.githubRunFailures) > 0 {
		const maxFailures = 20
		failures := opts.githubRunFailures
		if len(failures) > maxFailures {
			failures = failures[:maxFailures]
		}
		notice := "### Partial Adversary review\n\nThis review did not complete because one or more review jobs failed. Any findings are partial; an absence of findings does not mean the change passed review.\n\nFailed review jobs:\n\n" + strings.Join(failures, "\n")
		if remaining := len(opts.githubRunFailures) - len(failures); remaining > 0 {
			notice += fmt.Sprintf("\n- %d additional failed jobs.", remaining)
		}
		notice += "\n\nSee the CI logs for full diagnostics. Fix the execution failure and rerun the review."
		if strings.TrimSpace(plan.ReviewBody) != "" {
			notice += "\n\n---\n\n" + plan.ReviewBody
		}
		plan.ReviewBody = notice
	}
	logVoiceSource(progress, voiceInfo)

	token := githubapi.TokenFromEnv()
	client := githubapi.NewClient(token)
	if opts.githubRESTURL != "" {
		client.RESTBase = opts.githubRESTURL
	}
	if opts.githubAPIURL != "" {
		client.GQLURL = opts.githubAPIURL
	}

	if opts.githubDryRun {
		if token != "" {
			files, err := client.ListPullRequestFiles(ctx, owner, repo, opts.githubPR)
			if err == nil {
				head := opts.resolvedHeadSHA
				if head == "" {
					if pr, e := client.GetPullRequest(ctx, owner, repo, opts.githubPR); e == nil {
						head = pr.Head.SHA
					}
				}
				githubreview.ApplyPlacement(&plan, files, head)
			} else {
				githubreview.MarkDiffNotFetched(&plan)
			}
		} else {
			githubreview.MarkDiffNotFetched(&plan)
		}
		fmt.Fprintf(progress, "GitHub review dry-run: %d comment(s) planned (%d inline, %d body, %d skipped)\n",
			plan.Summary.Comments, plan.Summary.Inline, plan.Summary.ReviewBody, plan.Summary.Skipped)
		// Voice source already logged once above (shared with non-dry-run path).
		if opts.githubPlanFile != "" {
			if err := githubreview.WritePlanFile(opts.githubPlanFile, plan); err != nil {
				return err
			}
			fmt.Fprintf(progress, "Wrote plan to %s\n", opts.githubPlanFile)
		}
		return nil
	}

	if token == "" {
		return &application.Error{Operation: "github-review", Kind: "auth", Err: fmt.Errorf("GitHub token required: set ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")}
	}
	if opts.githubPlanFile != "" {
		if files, err := client.ListPullRequestFiles(ctx, owner, repo, opts.githubPR); err == nil {
			head := opts.resolvedHeadSHA
			if head == "" {
				if pr, e := client.GetPullRequest(ctx, owner, repo, opts.githubPR); e == nil {
					head = pr.Head.SHA
				}
			}
			githubreview.ApplyPlacement(&plan, files, head)
		}
		if err := githubreview.WritePlanFile(opts.githubPlanFile, plan); err != nil {
			return err
		}
	}

	_, err := githubreview.Post(ctx, plan, githubreview.PostOptions{
		Client: client,
		Owner:  owner,
		Repo:   repo,
		Number: opts.githubPR,
		Submit: opts.githubSubmit,
		Progress: func(s string) {
			fmt.Fprintln(progress, s)
		},
	})
	return err
}

// recordGitHubRunFailure captures failures independently of review envelopes:
// failed jobs may never emit one, and findings exits are successful reviews.
func (o *runOptions) recordGitHubRunFailure(ref, scope string, err error, stderr string) {
	var findings *internaladversary.FindingsError
	if !o.githubReview || err == nil || errors.As(err, &findings) || errors.Is(err, context.Canceled) {
		return
	}
	message := firstInterestingErrorLine(stderr)
	if message == "" {
		message = err.Error()
	}
	label := ref
	if scope != "" {
		label += " [" + scope + "]"
	}
	// Child errors can contain request diagnostics. Redact known credentials
	// before truncation so even a key straddling the limit cannot leak to a PR.
	for _, key := range []string{
		modelreview.OpenAIKeyEnv, modelreview.AnthropicKeyEnv,
		modelreview.FireworksKeyEnv, modelreview.CamelKeyEnv,
		"ADVERSARY_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "ADVERSARY_TOKEN",
	} {
		if secret, ok := githubapi.LookupEnv(key); ok && secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
			label = strings.ReplaceAll(label, secret, "[redacted]")
		}
	}
	label = html.EscapeString(truncateRunes(strings.Join(strings.Fields(label), " "), 160))
	message = html.EscapeString(truncateRunes(strings.Join(strings.Fields(message), " "), 500))
	o.githubRunFailures = append(o.githubRunFailures, "- <code>"+label+"</code>: <code>"+message+"</code>")
}

func logVoiceSource(progress io.Writer, voiceInfo githubreview.VoiceInfo) {
	if progress == nil {
		return
	}
	switch {
	case voiceInfo.ExampleBank && voiceInfo.Path != "":
		fmt.Fprintf(progress, "Voice: %s (%s, with example bank)\n", voiceInfo.Source, voiceInfo.Path)
	case voiceInfo.Path != "":
		fmt.Fprintf(progress, "Voice: %s (%s)\n", voiceInfo.Source, voiceInfo.Path)
	default:
		fmt.Fprintf(progress, "Voice: %s\n", voiceInfo.Source)
	}
}

// collectEnvelope adapts OnEnvelope storage.
func collectEnvelope(envelopes *[]githubreview.NamedEnvelope, ref string) func(any) {
	return func(v any) {
		env, ok := v.(review.RunEnvelope)
		if !ok {
			return
		}
		*envelopes = append(*envelopes, githubreview.NamedEnvelope{Adversary: ref, Envelope: env})
	}
}
