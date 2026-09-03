package cmd

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
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
func reportRunUsage(ctx context.Context, app *application.App, apiURL, profile string, report adversarylabs.RunUsageReport) {
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
		app.StartBackground(func() {
			metricCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = telemetry.ExportOTLPHTTP(metricCtx, otlp)
		})
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
		_ = client.RecordUsage(metricCtx, auth.Token, "run", cliVersion, report)
	})
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
