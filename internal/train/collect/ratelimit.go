package collect

import (
	"github.com/adversarylabs/adversary/internal/githubapi"
)

// RateLimitError is an alias for githubapi.RateLimitError for package consumers.
type RateLimitError = githubapi.RateLimitError

// IsRateLimit reports whether err is a rate-limit failure.
func IsRateLimit(err error) bool {
	return githubapi.IsRateLimit(err)
}
