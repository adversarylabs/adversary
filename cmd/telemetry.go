package cmd

import (
	"context"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/telemetry"
	"github.com/adversarylabs/adversary/internal/version"
)

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
	cliVersion := strings.TrimSpace(version.Version)
	if cliVersion == "" {
		cliVersion = "unknown"
	}
	client := deps.API.New(apiURL)
	app.StartBackground(func() {
		metricCtx, cancel := context.WithTimeout(ctx, telemetryTimeout)
		defer cancel()
		_ = client.RecordUsage(metricCtx, auth.Token, "run", cliVersion, selection)
	})
}
