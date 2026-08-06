package collect

import (
	"errors"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

func TestIsRateLimit(t *testing.T) {
	rl := &githubapi.RateLimitError{Message: "API rate limit exceeded"}
	if !IsRateLimit(rl) {
		t.Fatal("typed")
	}
	err := errors.New("outer: " + rl.Error())
	if !IsRateLimit(err) {
		t.Fatal("text detect")
	}
	if IsRateLimit(errors.New("no PRs found")) {
		t.Fatal("false positive")
	}
	if !strings.Contains(rl.Error(), "rate limit") {
		t.Fatalf("%s", rl.Error())
	}
}
