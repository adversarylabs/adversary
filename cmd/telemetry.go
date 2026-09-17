package cmd

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/internal/telemetry"
	"github.com/adversarylabs/adversary/internal/version"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/review"
)

// Constrained forms only — never send free text, emails, or flags as version.
var cliVersionRE = regexp.MustCompile(
	`^(dev|unknown|\d{4}\.\d{1,2}\.\d{1,2}(?:-[0-9A-Za-z.]+)?|\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$`,
)

func sanitizeCLIVersion(value string) string {
	v := strings.TrimSpace(value)
	if v == "" || !cliVersionRE.MatchString(v) {
		return "unknown"
	}
	return v
}

var fullGitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$`)

// withRunSourceContext records only the bounded source-control identity needed
// to group dashboard activity. It never uploads a repository URL or local path.
func withRunSourceContext(ctx context.Context, app *application.App, report adversarylabs.RunUsageReport, opts *runOptions) adversarylabs.RunUsageReport {
	if opts == nil || report.TelemetryDisabled || telemetry.Disabled() {
		return report
	}
	report.PullRequest = opts.githubPR
	if fullGitSHA.MatchString(strings.TrimSpace(opts.resolvedHeadSHA)) {
		report.GitSHA = strings.ToLower(strings.TrimSpace(opts.resolvedHeadSHA))
	}
	path := strings.TrimSpace(opts.path)
	if path == "" {
		path = "."
	}
	if report.GitSHA == "" {
		if source, ok := app.Dependencies().Runtime.(application.RunSourceIdentityProvider); ok {
			identity, err := source.RunSourceIdentity(ctx, path)
			sha := strings.TrimSpace(identity.SHA)
			if fullGitSHA.MatchString(sha) {
				report.GitSHA = strings.ToLower(sha)
			}
			ref := strings.TrimSpace(identity.Ref)
			if err == nil && ref != "" && len(ref) <= 256 && !strings.ContainsAny(ref, "\r\n") {
				report.GitRef = ref
			}
		}
	}
	return report
}

const telemetryTimeout = 2 * time.Second

// reportPull records a repository pull counter best-effort.
func reportPull(ctx context.Context, app *application.App, apiURL, profile, reference, digest string) {
	if telemetry.Disabled() || reference == "" {
		return
	}
	deps := app.Dependencies()
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	if err != nil || !ok || auth.Token == "" {
		return
	}
	client := deps.API.New(apiURL)
	app.StartBackground(func() {
		metricCtx, cancel := context.WithTimeout(ctx, telemetryTimeout)
		defer cancel()
		_ = client.RecordPull(metricCtx, auth.Token, reference, digest)
	})
}

// reportRunUsage records sanitized run telemetry with aggregate outcomes. No
// finding content, user, flags, paths, repository identity, or model inputs.
func reportRunUsage(ctx context.Context, app *application.App, report adversarylabs.RunUsageReport, upload func(context.Context, adversarylabs.RunUsageReport)) {
	if report.TelemetryDisabled || telemetry.Disabled() {
		return
	}
	selection := telemetry.SanitizeAdversarySelection(report.Adversaries)
	if len(selection) == 0 {
		return
	}
	report.Adversaries = selection
	sanitizedResults := make([]adversarylabs.RunUsageAdversaryResult, 0, len(report.Results))
	for _, result := range report.Results {
		result.Adversary = telemetry.SanitizeAdversaryRef(result.Adversary)
		if result.Adversary == "" {
			continue
		}
		sanitizedResults = append(sanitizedResults, result)
	}
	report.Results = sanitizedResults
	ended := time.Now()
	started := ended.Add(-time.Duration(report.DurationMS) * time.Millisecond)
	report = telemetry.BuildTrace(report, started, ended)
	cliVersion := sanitizeCLIVersion(version.Version)
	otlp, err := telemetry.OTLPJSON(report, cliVersion)
	if err == nil && report.TelemetryFile != "" {
		_ = telemetry.AppendOTLPFile(report.TelemetryFile, otlp)
	}
	if err == nil {
		app.StartFinalization(ctx, 10*time.Second, func(metricCtx context.Context) {
			_ = telemetry.ExportOTLPHTTP(metricCtx, otlp)
		})
	}
	if upload != nil {
		app.StartFinalization(ctx, telemetryTimeout, func(metricCtx context.Context) { upload(metricCtx, report) })
	}
}

func runUsageResult(ref string, runErr error, elapsed time.Duration, envelope *review.RunEnvelope) adversarylabs.RunUsageAdversaryResult {
	ended := time.Now()
	result := adversarylabs.RunUsageAdversaryResult{
		Adversary:         ref,
		Status:            "completed",
		DurationMS:        elapsed.Milliseconds(),
		StartedAtUnixNano: strconv.FormatInt(ended.Add(-elapsed).UnixNano(), 10),
		EndedAtUnixNano:   strconv.FormatInt(ended.UnixNano(), 10),
	}
	var findingsErr *internaladversary.FindingsError
	switch {
	case runErr != nil && !errors.As(runErr, &findingsErr):
		result.Status = "failed"
	case errors.As(runErr, &findingsErr):
		result.Status = "findings"
	}
	if envelope == nil {
		return result
	}
	// The runner emits a protocol-valid envelope when an invoked adversary opts
	// out because the resolved review scope does not match. Preserve that
	// invocation in telemetry without counting it as a performed code review.
	if reviewWasSkipped(envelope.Result) {
		result.Status = "skipped"
		return result
	}
	if envelope.Result.Timing != nil && envelope.Result.Timing.TotalMS > 0 {
		result.DurationMS = int64(envelope.Result.Timing.TotalMS)
	}
	for _, finding := range envelope.Result.Findings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			result.CriticalCount++
		case "high":
			result.HighCount++
		case "medium":
			result.MediumCount++
		case "low":
			result.LowCount++
		case "info":
			result.InfoCount++
		}
	}
	if len(envelope.Result.Findings) > 0 && result.Status != "failed" {
		result.Status = "findings"
	}
	return result
}

func findRunEnvelope(envelopes []githubreview.NamedEnvelope, ref string, start int) *review.RunEnvelope {
	if start < 0 || start > len(envelopes) {
		start = 0
	}
	for i := len(envelopes) - 1; i >= start; i-- {
		if envelopes[i].Adversary == ref {
			envelope := envelopes[i].Envelope
			return &envelope
		}
	}
	return nil
}

// beginRunUsage creates the run before execution, then renews its lease until
// finish or cancellation. Requests are bounded and best-effort like final telemetry.
// A killed process cannot renew the lease; the server records it as incomplete.
func beginRunUsage(ctx context.Context, app *application.App, apiURL, profile string, initial adversarylabs.RunUsageReport) func(adversarylabs.RunUsageReport) {
	return beginRunUsageEvery(ctx, app, apiURL, profile, initial, 20*time.Second)
}

func beginRunUsageEvery(ctx context.Context, app *application.App, apiURL, profile string, initial adversarylabs.RunUsageReport, interval time.Duration) func(adversarylabs.RunUsageReport) {
	if initial.TelemetryDisabled || telemetry.Disabled() {
		return func(adversarylabs.RunUsageReport) {}
	}
	started := time.Now()
	initial.TraceID = telemetry.NewTraceID()
	initial.Adversaries = telemetry.SanitizeAdversarySelection(initial.Adversaries)
	initial.Action = "start"
	deps := app.Dependencies()
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	stop := func() {}
	var upload func(context.Context, adversarylabs.RunUsageReport)
	if err == nil && ok && auth.Token != "" && len(initial.Adversaries) > 0 {
		client := deps.API.New(apiURL)
		send := func(parent context.Context, report adversarylabs.RunUsageReport) {
			metricCtx, cancel := context.WithTimeout(parent, telemetryTimeout)
			defer cancel()
			_ = client.RecordUsage(metricCtx, auth.Token, "run", sanitizeCLIVersion(version.Version), report)
		}
		upload = send
		send(ctx, initial)
		heartbeatCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			heartbeat := initial
			heartbeat.Action = "heartbeat"
			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-ticker.C:
					send(heartbeatCtx, heartbeat)
				}
			}
		}()
		stop = func() { cancel(); <-done }
	}
	var once sync.Once
	return func(report adversarylabs.RunUsageReport) {
		once.Do(func() {
			stop()
			report.TraceID = initial.TraceID
			report.Action = "finish"
			report.DurationMS = time.Since(started).Milliseconds()
			if len(report.Adversaries) == 0 {
				report.Adversaries = initial.Adversaries
			}
			if ctx.Err() != nil {
				report.Outcome = "canceled"
			}
			if report.Outcome == "" {
				report.Outcome = "failed"
			}
			// A canceled command still needs to deliver its final state.
			reportRunUsage(ctx, app, report, upload)
		})
	}
}
