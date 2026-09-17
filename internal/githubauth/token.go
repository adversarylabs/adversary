package githubauth

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// RequireToken returns an explicit environment token or the active gh login token.
func RequireToken() (string, error) {
	return requireToken(githubapi.TokenFromEnv, tokenFromGH)
}

func requireToken(envToken func() string, ghToken func() (string, error)) (string, error) {
	if token := strings.TrimSpace(envToken()); token != "" {
		return token, nil
	}
	if token, err := ghToken(); err == nil {
		if token = strings.TrimSpace(token); token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("GitHub token required: run gh auth login or set ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")
}

func tokenFromGH() (string, error) {
	path, err := exec.LookPath("gh")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "auth", "token").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
