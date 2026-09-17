package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type runLifecycleAPI struct {
	adversarylabs.Client
	calls chan adversarylabs.RunUsageReport
}

func (c *runLifecycleAPI) RecordUsage(ctx context.Context, _, _, _ string, report adversarylabs.RunUsageReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.calls <- report
	return nil
}

func TestRunLifecycle(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "cancel"}[canceled], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
			store := deps.Auth.(processAuthStore).ConfigStore
			const apiURL = "https://api.example.test"
			if err := store.SetAuth(adversarylabs.AuthKey(apiURL, "work"), adversarylabs.Auth{Token: "test-token"}); err != nil {
				t.Fatal(err)
			}
			api := &runLifecycleAPI{calls: make(chan adversarylabs.RunUsageReport, 100)}
			deps.API = pullMetricAPIFactory{identity: store.Path, client: api}
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			finish := beginRunUsageEvery(ctx, app, apiURL, "work", adversarylabs.RunUsageReport{Adversaries: []string{"./private"}}, 5*time.Millisecond)
			start := <-api.calls
			if start.Action != "start" || len(start.TraceID) != 32 || start.Adversaries[0] != "local" {
				t.Fatalf("start: %+v", start)
			}
			select {
			case heartbeat := <-api.calls:
				if heartbeat.Action != "heartbeat" || heartbeat.TraceID != start.TraceID {
					t.Fatalf("heartbeat: %+v", heartbeat)
				}
			case <-time.After(time.Second):
				t.Fatal("no heartbeat")
			}
			if canceled {
				cancel()
			}
			finish(adversarylabs.RunUsageReport{Outcome: "completed"})
			finish(adversarylabs.RunUsageReport{Outcome: "failed"}) // duplicate cleanup cannot send a second finish
			waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
			defer waitCancel()
			app.WaitBackground(waitCtx)
			var final adversarylabs.RunUsageReport
			for len(api.calls) > 0 {
				final = <-api.calls
			}
			want := "completed"
			if canceled {
				want = "canceled"
			}
			if final.Action != "finish" || final.Outcome != want || final.TraceID != start.TraceID || len(final.Spans) == 0 {
				t.Fatalf("finish: %+v", final)
			}
			time.Sleep(15 * time.Millisecond)
			if len(api.calls) != 0 {
				t.Fatal("heartbeat continued after finish")
			}
		})
	}
}
