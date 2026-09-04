package repoindex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestV2GoAndTypeScriptGraphQueries(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	write(t, root, "service/service.go", `package service

type Store interface { Get() string }

func Load() string { return "ok" }

func Handle() string { return Load() }
`)
	write(t, root, "service/service_test.go", `package service

func TestHandle() { _ = Handle() }
`)
	write(t, root, "web/util.ts", `export function parse(value: string): number { return value.length }
`)
	write(t, root, "web/main.ts", `import { parse } from "./util";
export function boot(): number { return parse("ready") }
`)
	write(t, root, "web/main.test.ts", `import { boot } from "./main";
boot();
`)

	fingerprint, err := V2Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "graph")
	meta, err := BuildV2(root, dir, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if meta.FileCount != 5 || meta.SymbolCount < 6 || meta.EdgeCount == 0 || meta.TestLinkCount != 2 {
		t.Fatalf("unexpected metadata: %#v", meta)
	}
	graph, err := OpenV2(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()

	loads, err := graph.Symbols(V2SymbolQuery{Name: "Load", Limit: 10})
	if err != nil || len(loads.Items) != 1 {
		t.Fatalf("Load symbols=%#v err=%v", loads, err)
	}
	callers, err := graph.Callers(V2RelationQuery{SymbolID: loads.Items[0].ID, Limit: 10})
	if err != nil || len(callers.Items) == 0 {
		t.Fatalf("Load callers=%#v err=%v", callers, err)
	}
	if callers.Items[0].FromSymbolID == nil {
		t.Fatalf("caller lacks source symbol: %#v", callers.Items[0])
	}

	parseSymbols, err := graph.Symbols(V2SymbolQuery{Name: "parse", Limit: 10})
	if err != nil || len(parseSymbols.Items) != 1 {
		t.Fatalf("parse symbols=%#v err=%v", parseSymbols, err)
	}
	tsCallers, err := graph.Callers(V2RelationQuery{SymbolID: parseSymbols.Items[0].ID, Limit: 10})
	if err != nil || len(tsCallers.Items) == 0 {
		t.Fatalf("parse callers=%#v err=%v", tsCallers, err)
	}
	imports, err := graph.ImportsOf("web/main.ts", "", 10)
	if err != nil || len(imports.Items) != 1 || imports.Items[0].ToPath != "web/util.ts" {
		t.Fatalf("imports=%#v err=%v", imports, err)
	}
	tests, err := graph.RelatedTests("service/service.go", 0, "", 10)
	if err != nil || len(tests.Items) != 1 || tests.Items[0].TestPath != "service/service_test.go" {
		t.Fatalf("tests=%#v err=%v", tests, err)
	}
	if _, err := graph.Symbols(V2SymbolQuery{Path: "../escape.go"}); err == nil {
		t.Fatal("path traversal must be rejected")
	}
	first, err := graph.Files(V2FileQuery{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	second, err := graph.Files(V2FileQuery{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Items) == 0 || second.Items[0].ID <= first.Items[1].ID {
		t.Fatalf("second page=%#v err=%v", second, err)
	}
}

func TestEnsureV2CacheDirtyFingerprintAndPublicationRecovery(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	write(t, root, "main.go", "package main\n\nfunc main() {}\n")
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	first, err := EnsureV2(root, ModeAuto, nil)
	if err != nil || first == nil || !first.Meta.Rebuilt {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := EnsureV2(root, ModeAuto, nil)
	if err != nil || second.Meta.Rebuilt {
		t.Fatalf("second=%#v err=%v", second, err)
	}

	previous := first.Dir + ".previous"
	if err := os.Rename(first.Dir, previous); err != nil {
		t.Fatal(err)
	}
	recovered, err := EnsureV2(root, ModeAuto, nil)
	if err != nil || recovered.Meta.Rebuilt {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatalf("stale previous directory remains: %v", err)
	}

	write(t, root, "main.go", "package main\n\nfunc main() { println(1) }\n")
	dirty, err := EnsureV2(root, ModeAuto, nil)
	if err != nil || !dirty.Meta.Rebuilt || dirty.Meta.Fingerprint == first.Meta.Fingerprint {
		t.Fatalf("dirty=%#v err=%v", dirty, err)
	}
}

func TestEnsureV2SharesCacheAcrossIdenticalWorktrees(t *testing.T) {
	root := t.TempDir()
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "t@example.com")
	run(t, root, "git", "config", "user.name", "t")
	write(t, root, "main.go", "package main\n\nfunc main() {}\n")
	run(t, root, "git", "add", ".")
	run(t, root, "git", "commit", "-m", "init")

	clone := filepath.Join(t.TempDir(), "clone")
	run(t, "", "git", "clone", "--quiet", root, clone)
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	first, err := EnsureV2(root, ModeAuto, nil)
	if err != nil || first == nil || !first.Meta.Rebuilt {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := EnsureV2(clone, ModeAuto, nil)
	if err != nil || second == nil {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	if second.Meta.Rebuilt {
		t.Fatal("expected identical worktree at a different path to reuse graph cache")
	}
	if first.Dir != second.Dir {
		t.Fatalf("cache directories differ: %s vs %s", first.Dir, second.Dir)
	}
}

func TestV2ParseFailureIsRecordedWithoutPoisoningGraph(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n")
	write(t, root, "good.go", "package app\n\nfunc Good() {}\n")
	write(t, root, "broken.go", "package app\n\nfunc Broken( {\n")
	fingerprint, err := V2Fingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "graph")
	meta, err := BuildV2(root, dir, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.ParseFailures) != 1 || meta.ParseFailures[0].Path != "broken.go" {
		t.Fatalf("diagnostics=%#v", meta.ParseFailures)
	}
	graph, err := OpenV2(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer graph.Close()
	symbols, err := graph.Symbols(V2SymbolQuery{Name: "Good"})
	if err != nil || len(symbols.Items) != 1 {
		t.Fatalf("symbols=%#v err=%v", symbols, err)
	}
}
