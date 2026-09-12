package collect

import (
	"context"
	"errors"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// RateLimitError is an alias for githubapi.RateLimitError for package consumers.
type RateLimitError = githubapi.RateLimitError

// IsRateLimit reports whether err is a rate-limit failure.
func IsRateLimit(err error) bool {
	return githubapi.IsRateLimit(err)
}

func WaitForRateLimit(ctx context.Context, err error) error {
	return githubapi.WaitForRateLimit(ctx, err)
}

func RateLimitReset(err error) time.Time {
	var typed *githubapi.RateLimitError
	if errors.As(err, &typed) && typed != nil {
		return typed.ResetAt
	}
	if reset, active := githubapi.ActiveRateLimit(); active {
		return reset
	}
	return time.Time{}
}
