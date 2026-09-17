package inbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/results"
)

func TestRegisterAndListPendingCatalogs(t *testing.T) {
	dataRoot := t.TempDir()
	catalog := t.TempDir()
	configPath := filepath.Join(catalog, "adversary.train.yaml")
	if err := os.WriteFile(configPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(catalog, ".adversary-train")
	if err := Register(dataRoot, configPath, stateRoot); err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(stateRoot, results.Result{ID: "candidate-1", Status: results.StatusNew, Kind: results.KindHuman}); err != nil {
		t.Fatal(err)
	}

	catalogs, err := Pending(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalogs) != 1 || catalogs[0].Pending != 1 || catalogs[0].ConfigPath != configPath {
		t.Fatalf("catalogs=%+v", catalogs)
	}
	if mode := fileMode(t, registryPath(dataRoot)); mode.Perm() != 0o600 {
		t.Fatalf("registry mode=%o", mode.Perm())
	}
}

func TestPendingIgnoresAcceptedResults(t *testing.T) {
	dataRoot := t.TempDir()
	catalog := t.TempDir()
	configPath := filepath.Join(catalog, "adversary.train.yaml")
	stateRoot := filepath.Join(catalog, ".adversary-train")
	if err := Register(dataRoot, configPath, stateRoot); err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(stateRoot, results.Result{ID: "candidate-1", Status: results.StatusAccepted, Kind: results.KindHuman}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := Pending(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalogs) != 0 {
		t.Fatalf("catalogs=%+v", catalogs)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
