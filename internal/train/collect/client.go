package collect

import (
	"context"
	"fmt"
	"sync"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

var (
	defaultClientMu sync.Mutex
	defaultClient   *githubapi.Client
)

// SetDefaultClient injects a client for tests.
func SetDefaultClient(c *githubapi.Client) {
	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()
	defaultClient = c
}

// DefaultClient returns the process client (token from env).
func DefaultClient() (*githubapi.Client, error) {
	defaultClientMu.Lock()
	defer defaultClientMu.Unlock()
	if defaultClient != nil {
		return defaultClient, nil
	}
	token, err := githubapi.RequireToken()
	if err != nil {
		return nil, err
	}
	return githubapi.NewClient(token), nil
}

// clientFor returns an injected or env-backed client.
func clientFor(ctx context.Context) (*githubapi.Client, error) {
	_ = ctx
	return DefaultClient()
}

// ErrNoToken is returned when no GitHub token is configured.
var ErrNoToken = fmt.Errorf("GitHub token required: set ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")
