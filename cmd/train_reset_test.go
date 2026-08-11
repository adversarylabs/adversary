package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	trainstate "github.com/adversarylabs/adversary/internal/train/state"
	"github.com/adversarylabs/adversary/internal/train/workspace"
)

func TestTrainResetClearsDiscoveryAndCatalogCursor(t *testing.T) {
	root := t.TempDir()
	config := "version: 1\nadversaries:\n  path: .\nsources:\n  repos:\n    - public/example\n"
	if err := os.WriteFile(filepath.Join(root, workspace.DefaultConfigName), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	stateRoot := filepath.Join(root, workspace.DefaultStateDir)
	discoveryDir := filepath.Join(stateRoot, "state", "discovery")
	if err := os.MkdirAll(discoveryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(discoveryDir, "public__example.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := trainstate.TakeCatalogWindow(stateRoot, "lang/typescript", 10, 3); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	command := newTrainResetCommand(nil)
	command.SetOut(&stdout)
	command.SetErr(&stdout)
	command.SetArgs([]string{"--path", root})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(discoveryDir); !os.IsNotExist(err) {
		t.Fatalf("discovery directory still exists after reset: %v", err)
	}
	if _, err := os.Stat(trainstate.CatalogCursorPath(stateRoot)); !os.IsNotExist(err) {
		t.Fatalf("catalog cursor still exists after reset: %v", err)
	}
	if !strings.Contains(stdout.String(), "cleared 2 discovery file(s)") {
		t.Fatalf("reset output = %q", stdout.String())
	}
}
