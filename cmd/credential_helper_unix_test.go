//go:build !windows

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
)

func helperFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCredentialHelperRunnerUsesCapturedPathAndEnvironment(t *testing.T) {
	path := helperFixture(t, `read input; printf '%s:%s' "$MARKER" "$input"`)
	environment := internaladversary.NewProcessEnvironment([]string{"PATH=/captured", "MARKER=captured"}, false)
	lookedUp := ""
	run := newCredentialHelperRunner(environment, func(name string) (string, error) { lookedUp = name; return path, nil })
	t.Setenv("PATH", t.TempDir())
	t.Setenv("MARKER", "poison")
	out, err := run(context.Background(), "docker-credential-fixture", "registry.example\n")
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "docker-credential-fixture" || string(out) != "captured:registry.example" {
		t.Fatalf("lookup=%q output=%q", lookedUp, out)
	}
}

func TestCredentialHelperRunnerCancellationAndBounds(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"stdout overflow": {`head -c 1048577 /dev/zero`, "exceeds"},
		"stderr overflow": {`head -c 2097152 /dev/zero >&2; printf ok`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := helperFixture(t, tc.body)
			run := newCredentialHelperRunner(internaladversary.NewProcessEnvironment(nil, false), func(string) (string, error) { return path, nil })
			out, err := run(context.Background(), "helper", "input\n")
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("output=%d error=%v", len(out), err)
			}
			if tc.want == "" && (err != nil || string(out) != "ok") {
				t.Fatalf("output=%q error=%v", out, err)
			}
		})
	}
	// Keep a descendant alive with the captured stdout pipe open. WaitDelay must
	// still bound cancellation after the direct shell process is killed.
	path := helperFixture(t, `sleep 10 & wait`)
	run := newCredentialHelperRunner(internaladversary.NewProcessEnvironment(nil, false), func(string) (string, error) { return path, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := run(ctx, "helper", "input\n")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("canceled helper did not terminate promptly")
	}
}

func TestCredentialHelperRunnerNonzeroErrorRedactsInput(t *testing.T) {
	path := helperFixture(t, `read secret; printf '%s' "$secret" >&2; exit 7`)
	run := newCredentialHelperRunner(internaladversary.NewProcessEnvironment(nil, false), func(string) (string, error) { return path, nil })
	_, err := run(context.Background(), "helper", "super-secret\n")
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error=%v", err)
	}
}
