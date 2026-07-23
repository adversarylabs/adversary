package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestWritePullTextIncludesOnlyNonEmptyTag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tag     string
		wantTag bool
	}{
		{name: "tagged reference", tag: "v1", wantTag: true},
		{name: "digest reference", wantTag: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := writePullText(&output, pullDTO{Name: "acme/reviewer", Version: "1.2.3", Tag: tc.tag, CanonicalReference: "ghcr.io/acme/reviewer", Digest: "sha256:abc"})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(output.String(), "\nTag:"); got != tc.wantTag {
				t.Fatalf("output = %q, contains tag=%t", output.String(), got)
			}
			for _, want := range []string{"Installed: acme/reviewer", "Version: 1.2.3", "Canonical reference: ghcr.io/acme/reviewer", "Digest: sha256:abc"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("output missing %q: %q", want, output.String())
				}
			}
		})
	}
}

type failingPullWriter struct{}

func (failingPullWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWritePullTextPropagatesWriterFailure(t *testing.T) {
	if err := writePullText(failingPullWriter{}, pullDTO{}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("error = %v", err)
	}
}

type pullMetricCall struct {
	token, reference, digest string
}

type blockingPullAPI struct {
	adversarylabs.Client
	calls   chan pullMetricCall
	release <-chan struct{}
	done    chan<- struct{}
}

func (c *blockingPullAPI) RecordPull(ctx context.Context, token, reference, digest string) error {
	c.calls <- pullMetricCall{token: token, reference: reference, digest: digest}
	defer close(c.done)
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type pullMetricAPIFactory struct {
	identity string
	client   application.APIClient
}

func (f pullMetricAPIFactory) BindingIdentity() string          { return f.identity }
func (f pullMetricAPIFactory) New(string) application.APIClient { return f.client }

func TestReportPullDoesNotWaitForMetricRequest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	apiURL := "https://api.example.test"
	if err := store.SetAuth(adversarylabs.AuthKey(apiURL, "work"), adversarylabs.Auth{Token: "pull-token"}); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	done := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	calls := make(chan pullMetricCall, 1)
	base.API = pullMetricAPIFactory{
		identity: store.Path,
		client:   &blockingPullAPI{calls: calls, release: release, done: done},
	}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	returned := make(chan struct{})
	go func() {
		reportPull(t.Context(), app, apiURL, "work", "adversarylabs/reviewer", "sha256:abc")
		close(returned)
	}()

	select {
	case call := <-calls:
		if call != (pullMetricCall{token: "pull-token", reference: "adversarylabs/reviewer", digest: "sha256:abc"}) {
			t.Fatalf("call = %#v", call)
		}
	case <-time.After(time.Second):
		t.Fatal("metric request did not start")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("reportPull waited for the metric request")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metric request did not finish after release")
	}
}
