package cmd

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/telemetry"
	"github.com/adversarylabs/adversary/internal/version"
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

// reportRunUsage records sanitized run telemetry: CLI version + adversary selection.
// No user, flags, paths, or repo identity.
func reportRunUsage(ctx context.Context, app *application.App, apiURL, profile string, adversaries []string) {
	if telemetry.Disabled() {
		return
	}
	selection := telemetry.SanitizeAdversarySelection(adversaries)
	if len(selection) == 0 {
		return
	}
	deps := app.Dependencies()
	auth, ok, err := scopedAuth(deps.Auth, apiURL, profile, deps.RegistryHost)
	if err != nil || !ok || auth.Token == "" {
		return
	}
	cliVersion := sanitizeCLIVersion(version.Version)
	client := deps.API.New(apiURL)
	app.StartBackground(func() {
		metricCtx, cancel := context.WithTimeout(ctx, telemetryTimeout)
		defer cancel()
		_ = client.RecordUsage(metricCtx, auth.Token, "run", cliVersion, selection)
	})
}
