package collect

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseRateLimit(t *testing.T) {
	body := []byte(`{"message":"API rate limit exceeded for user ID 173451.","documentation_url":"https://docs.github.com"}`)
	rl := parseRateLimit(body)
	if rl == nil {
		t.Fatal("expected rate limit")
	}
	if !IsRateLimit(rl) {
		t.Fatal("IsRateLimit")
	}
	if !strings.Contains(rl.Error(), "rate limit") {
		t.Fatalf("%s", rl.Error())
	}
}

func TestParseRateLimitWithResetHeader(t *testing.T) {
	sec := time.Now().Add(10 * time.Minute).Unix()
	body := []byte(fmt.Sprintf("HTTP/1.1 403\r\nX-RateLimit-Reset: %d\r\n\r\nAPI rate limit exceeded", sec))
	rl := parseRateLimit(body)
	if rl == nil || rl.ResetAt.IsZero() {
		t.Fatalf("%+v", rl)
	}
}

func TestIsRateLimitWrapped(t *testing.T) {
	rl := &RateLimitError{Message: "API rate limit exceeded"}
	err := errors.New("outer: " + rl.Error())
	if !IsRateLimit(err) {
		t.Fatal("text detect")
	}
	if !IsRateLimit(rl) {
		t.Fatal("typed")
	}
	if IsRateLimit(errors.New("no PRs found")) {
		t.Fatal("false positive")
	}
}
