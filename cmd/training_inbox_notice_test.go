package cmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	traininbox "github.com/adversarylabs/adversary/internal/train/inbox"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type trainingNoticeTTY struct{}

func (trainingNoticeTTY) Interactive(io.Reader) bool { return true }
func (trainingNoticeTTY) ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error) {
	return nil, nil
}

func TestTrainingInboxNoticeSummarizesRegisteredCatalogs(t *testing.T) {
	dataRoot := t.TempDir()
	catalog := t.TempDir()
	config := filepath.Join(catalog, "adversary.train.yaml")
	state := filepath.Join(catalog, ".adversary-train")
	if err := traininbox.Register(dataRoot, config, state); err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(state, results.Result{ID: "one", Status: results.StatusNew, Kind: results.KindHuman}); err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(state, results.Result{ID: "two", Status: results.StatusAccepted, Kind: results.KindHuman}); err != nil {
		t.Fatal(err)
	}

	notice := trainingInboxNotice(dataRoot)
	for _, want := range []string{"1 result(s)", "1 catalog(s)", "adversary catalog train review"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("notice=%q missing %q", notice, want)
		}
	}
}

func TestInteractiveCommandsShowInboxNoticeButJSONStaysQuiet(t *testing.T) {
	dataRoot := t.TempDir()
	t.Setenv("ADVERSARY_DATA_DIR", dataRoot)
	catalog := t.TempDir()
	config := filepath.Join(catalog, "adversary.train.yaml")
	state := filepath.Join(catalog, ".adversary-train")
	if err := traininbox.Register(dataRoot, config, state); err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(state, results.Result{ID: "one", Status: results.StatusNew, Kind: results.KindHuman}); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		var stdout, stderr bytes.Buffer
		deps := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
		deps.TTY = trainingNoticeTTY{}
		app, err := application.New(deps)
		if err != nil {
			t.Fatal(err)
		}
		command := NewRootCommandWithApp(app)
		command.SetArgs(args)
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		return stderr.String()
	}

	if stderr := run("version"); !strings.Contains(stderr, "Training inbox: 1 result(s)") {
		t.Fatalf("interactive stderr=%q", stderr)
	}
	if stderr := run("version", "--format", "json"); strings.Contains(stderr, "Training inbox") {
		t.Fatalf("JSON stderr was polluted: %q", stderr)
	}
}
