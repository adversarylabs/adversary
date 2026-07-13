package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
)

func TestCreateRejectsSymlink(t *testing.T) {
	dir := testProject(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "outside-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted symlink")
	}
}

func TestCreateRejectsSymlinkSwap(t *testing.T) {
	dir := testProject(t)
	target := filepath.Join(dir, "dist", "index.js")
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("outside-secret"), 0644); err != nil {
		t.Fatal(err)
	}
	beforePackOpen = func(rel string) {
		if rel == "dist/index.js" {
			beforePackOpen = nil
			_ = os.Remove(target)
			_ = os.Symlink(outside, target)
		}
	}
	t.Cleanup(func() { beforePackOpen = nil })
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted symlink swap")
	}
}

func TestCreateRejectsManifestSymlinkSwap(t *testing.T) {
	dir := testProject(t)
	target := filepath.Join(dir, "adversary.yaml")
	outside := filepath.Join(t.TempDir(), "adversary.yaml")
	if err := os.WriteFile(outside, []byte("name: outside/secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	beforeManifestRead = func() { beforeManifestRead = nil; _ = os.Remove(target); _ = os.Symlink(outside, target) }
	t.Cleanup(func() { beforeManifestRead = nil })
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted manifest symlink swap")
	}
}

func TestCreatePreservesExecutableMode(t *testing.T) {
	dir := testProject(t)
	path := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	layer := readArtifactLayer(t, artifact)
	gz, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "run.sh" {
			if h.Mode != 0755 {
				t.Fatalf("mode=%o", h.Mode)
			}
			return
		}
	}
}

func TestCreateNormalizesAnyExecutableModeInInventoryAndTar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes unavailable")
	}
	dir := testProject(t)
	if got := normalizedFileMode(0100); got != 0755 {
		t.Fatalf("0100 normalized to %#o", got)
	}
	for name, mode := range map[string]os.FileMode{"owner-all.sh": 0700, "owner-exec.sh": 0500} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	for _, file := range artifact.Files {
		if file.Path == "owner-all.sh" || file.Path == "owner-exec.sh" {
			if file.Mode != 0755 {
				t.Fatalf("inventory %s mode=%#o", file.Path, file.Mode)
			}
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(readArtifactLayer(t, artifact)))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "owner-all.sh" || h.Name == "owner-exec.sh" {
			seen++
			if h.Mode != 0755 {
				t.Fatalf("tar %s mode=%#o", h.Name, h.Mode)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("seen executable headers=%d", seen)
	}
}

func TestCreateIsDeterministic(t *testing.T) {
	dir := testProject(t)
	first, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestDigest != second.ManifestDigest {
		t.Fatalf("digest mismatch: %s != %s", first.ManifestDigest, second.ManifestDigest)
	}
	if string(readArtifactLayer(t, first)) != string(readArtifactLayer(t, second)) {
		t.Fatal("layer is not deterministic")
	}
}

func readArtifactLayer(t *testing.T, artifact Artifact) []byte {
	t.Helper()
	r, err := artifact.LayerSource.Open()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCreateStoresRuntimeRequirement(t *testing.T) {
	dir := testProject(t)
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.RuntimeName != "node" || artifact.RuntimeVersion != "22" {
		t.Fatalf("runtime requirement = %s@%s", artifact.RuntimeName, artifact.RuntimeVersion)
	}
	if artifact.OCIManifest.Annotations["ai.adversary.runtime.name"] != "node" {
		t.Fatalf("runtime name annotation missing: %#v", artifact.OCIManifest.Annotations)
	}
	if artifact.OCIManifest.Annotations["ai.adversary.runtime.version"] != "22" {
		t.Fatalf("runtime version annotation missing: %#v", artifact.OCIManifest.Annotations)
	}
}

func TestCreateStoresAdversaryManifestOutsideImageLayer(t *testing.T) {
	dir := testProject(t)
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.AdversaryManifest) != string(manifestBytes) {
		t.Fatal("adversary manifest bytes were not preserved exactly")
	}
	if artifact.AdversaryManifestDigest == "" {
		t.Fatal("adversary manifest digest missing")
	}
	for _, file := range artifact.Files {
		if file.Path == "adversary.yaml" {
			t.Fatal("adversary.yaml must not be included in the runnable image layer")
		}
	}
}

func TestCreateNameOverride(t *testing.T) {
	dir := testProject(t)
	artifact, err := Create(context.Background(), Options{Dir: dir, NameOverride: "ghcr.io/acme/security-reviewer", ParseReference: oci.ParseReference})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Name != "ghcr.io/acme/security-reviewer" {
		t.Fatalf("Name = %q", artifact.Name)
	}
	if artifact.ManifestName != "local/security-reviewer" {
		t.Fatalf("ManifestName = %q", artifact.ManifestName)
	}
}

func TestCreateNameOverrideRejectsTag(t *testing.T) {
	dir := testProject(t)
	_, err := Create(context.Background(), Options{Dir: dir, NameOverride: "ghcr.io/acme/security-reviewer:dev", ParseReference: oci.ParseReference})
	if err == nil {
		t.Fatal("expected tag rejection")
	}
	if !strings.Contains(err.Error(), "must not include a tag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultIgnoreRules(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "node_modules/pkg/index.js", "ignored")
	writeFile(t, dir, ".git/config", "ignored")
	writeFile(t, dir, ".env", "ignored")
	writeFile(t, dir, ".env.local", "ignored")
	writeFile(t, dir, ".DS_Store", "ignored")
	writeFile(t, dir, "coverage/out.json", "ignored")
	writeFile(t, dir, "tmp/file", "ignored")
	writeFile(t, dir, ".cache/file", "ignored")
	writeFile(t, dir, "Dockerfile", "ignored")

	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Files {
		switch file.Path {
		case "node_modules/pkg/index.js", ".git/config", ".env", ".env.local", ".DS_Store", "coverage/out.json", "tmp/file", ".cache/file", "Dockerfile":
			t.Fatalf("ignored file included: %s", file.Path)
		}
	}
}

func TestAdversaryIgnore(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, ".adversaryignore", "secrets/\n*.log\n")
	writeFile(t, dir, "secrets/token.txt", "ignored")
	writeFile(t, dir, "debug.log", "ignored")

	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Files {
		if file.Path == "secrets/token.txt" || file.Path == "debug.log" {
			t.Fatalf("ignored file included: %s", file.Path)
		}
	}
}

func TestCreateRejectsImplicitStaleDistWhenNPMMissing(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	var stderr strings.Builder
	_, err := Create(context.Background(), Options{Dir: dir, Build: true, Stderr: &stderr, BuildProject: BuildProject})
	if err == nil || !strings.Contains(err.Error(), "explicitly allow stale dist") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildProjectExplicitlyAllowsStaleDist(t *testing.T) {
	dir := testProject(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	var stderr strings.Builder
	err := BuildProject(context.Background(), BuildOptions{Dir: dir, AllowStaleDist: true, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "explicit stale-dist policy") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestBuildProjectParsesBuildScriptStrictly(t *testing.T) {
	for name, packageJSON := range map[string]string{
		"invalid json": `{`,
		"non-string":   `{"scripts":{"build":true}}`,
		"empty":        `{"scripts":{"build":"  "}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "package.json", packageJSON)
			if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"description":"the word build is not a script"}`)
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir, Builder: "local"}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildProjectValidatesBeforeFilesystemAccess(t *testing.T) {
	if err := BuildProject(context.Background(), BuildOptions{Dir: filepath.Join(t.TempDir(), "missing"), Builder: "spaceship"}); err == nil || !strings.Contains(err.Error(), "unsupported builder") {
		t.Fatalf("error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := BuildProject(ctx, BuildOptions{Dir: filepath.Join(t.TempDir(), "missing")}); err == nil || !strings.Contains(err.Error(), "canceled before filesystem") {
		t.Fatalf("error = %v", err)
	}
}

func TestMissingAndNoBuildProjectsDoNotCreateLockMetadata(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	missing := filepath.Join(t.TempDir(), "missing")
	err := BuildProject(context.Background(), BuildOptions{Dir: missing, BuildStateDir: state})
	if err == nil || !strings.Contains(err.Error(), "project directory") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing project created state: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"test":"true"}}`)
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir, BuildStateDir: state}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entryNames(before), entryNames(after)) {
		t.Fatalf("no-build project changed: before=%v after=%v", entryNames(before), entryNames(after))
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-build project created state: %v", err)
	}
}

func TestProjectSymlinkRejectedBeforeStateMutation(t *testing.T) {
	real := testProject(t)
	link := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	state := filepath.Join(t.TempDir(), "state")
	if err := BuildProject(context.Background(), BuildOptions{Dir: link, BuildStateDir: state}); err == nil {
		t.Fatal("accepted project symlink")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink project created state: %v", err)
	}
}

func TestBuildStateRootRejectsSymlinkAndEnforcesPrivateMode(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ensureBuildStateRoot(link); err == nil {
		t.Fatal("accepted symlink state root")
	}
	root := filepath.Join(parent, "private")
	got, err := ensureBuildStateRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestBuildStateRootCannotBeInsideProject(t *testing.T) {
	dir := testProject(t)
	state := filepath.Join(dir, ".state")
	err := BuildProject(context.Background(), BuildOptions{Dir: dir, BuildStateDir: state})
	if err == nil || !strings.Contains(err.Error(), "outside the project") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("in-project state was created: %v", err)
	}
}

func TestLocalBuildIsStagedAndPublishesDist(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	npm := filepath.Join(bin, "npm")
	if err := os.WriteFile(npm, []byte("#!/bin/sh\nprintf mutated > source-marker\nrm -rf dist\nmkdir dist\nprintf built > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFakeNode22(t, bin)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "built" {
		t.Fatalf("dist = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "source-marker")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("build mutated source: %v", err)
	}
}

func TestLocalBuildFailurePreservesOriginalDist(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	npm := filepath.Join(bin, "npm")
	if err := os.WriteFile(npm, []byte("#!/bin/sh\nrm -rf dist\nmkdir dist\nprintf partial > dist/index.js\nexit 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFakeNode22(t, bin)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err == nil {
		t.Fatal("expected failure")
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("original dist changed: %q", got)
	}
}

func TestLocalBuildCancellationPreservesOriginalDist(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	npm := filepath.Join(bin, "npm")
	if err := os.WriteFile(npm, []byte("#!/bin/sh\nrm -rf dist\nmkdir dist\nprintf partial > dist/index.js\nsleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFakeNode22(t, bin)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := BuildProject(ctx, BuildOptions{Dir: dir}); err == nil {
		t.Fatal("expected cancellation")
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("original dist changed: %q", got)
	}
}

func TestCancellationAtPublicationBoundaryPreservesDist(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf new > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	beforeDistPublish = cancel
	t.Cleanup(func() { beforeDistPublish = nil })
	err := BuildProject(ctx, BuildOptions{Dir: dir})
	if err == nil || !strings.Contains(err.Error(), "canceled before dist publication") {
		t.Fatalf("error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("original dist changed: %q", got)
	}
	assertNoBuildDebris(t, dir)
}

func TestPublicationFailureAfterEachRenameRestoresDist(t *testing.T) {
	for _, step := range []string{"backup-moved", "published-rename"} {
		t.Run(step, func(t *testing.T) {
			dir := testProject(t)
			if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			writeFakeNode22(t, bin)
			if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf new > dist/index.js\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			afterDistRename = func(got string) error {
				if got == step {
					return errors.New("injected publication failure")
				}
				return nil
			}
			t.Cleanup(func() { afterDistRename = nil })
			if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err == nil {
				t.Fatal("expected failure")
			}
			got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "console.log('ok')\n" {
				t.Fatalf("original dist changed: %q", got)
			}
			assertNoBuildDebris(t, dir)
		})
	}
}

func TestPublishedJournalFsyncAmbiguityReturnsSuccess(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf committed > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	attempts := 0
	directorySyncHook = func(phase string, attempt int) error {
		if phase == "state-published" {
			attempts++
			if attempt == 1 {
				return errors.New("injected directory fsync ambiguity")
			}
		}
		return nil
	}
	t.Cleanup(func() { directorySyncHook = nil })
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err != nil {
		t.Fatalf("committed publication reported failure: %v", err)
	}
	if attempts < 2 {
		t.Fatalf("state directory sync attempts = %d, want retry", attempts)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist/index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "committed" {
		t.Fatalf("dist = %q", got)
	}
}

func TestPublishedJournalPermanentSyncFailureRollsBack(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf uncommitted > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	failed := false
	directorySyncHook = func(phase string, attempt int) error {
		if phase == "state-published" {
			failed = true
		}
		if failed && strings.HasPrefix(phase, "state-") {
			return errors.New("injected directory fsync ambiguity")
		}
		return nil
	}
	t.Cleanup(func() { directorySyncHook = nil })
	err := BuildProject(context.Background(), BuildOptions{Dir: dir})
	var durability *PublicationDurabilityError
	if !errors.As(err, &durability) {
		t.Fatalf("error = %v, want PublicationDurabilityError", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist/index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("dist was not rolled back: %q", got)
	}
	assertNoBuildDebris(t, dir)
}

func TestStaleBackupMovedJournalPreservesAlreadyRestoredDist(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	stateBase := filepath.Join(t.TempDir(), "state")
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf uncommitted > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	failed := false
	directorySyncHook = func(phase string, attempt int) error {
		if phase == "state-published" {
			failed = true
		}
		if failed && strings.HasPrefix(phase, "state-") {
			return errors.New("persistent external sync failure")
		}
		return nil
	}
	err := BuildProject(context.Background(), BuildOptions{Dir: dir, BuildStateDir: stateBase})
	var durability *PublicationDurabilityError
	if !errors.As(err, &durability) {
		t.Fatalf("error = %v", err)
	}
	directorySyncHook = nil
	t.Cleanup(func() { directorySyncHook = nil })
	canonical := mustCanonicalProject(t, dir)
	base, err := ensureBuildStateRoot(stateBase)
	if err != nil {
		t.Fatal(err)
	}
	state, err := openProjectBuildState(base, canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	project, err := os.OpenRoot(canonical)
	if err != nil {
		t.Fatal(err)
	}
	defer project.Close()
	stale := buildJournal{Project: projectCorrelation(project), State: "backup-moved", Stage: ".dist-adversary-stage-33333333333333333333333333333333", Backup: ".dist-adversary-backup-44444444444444444444444444444444", HadDist: true}
	if err := writeBuildJournal(state, stale); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "package.json", `{"scripts":{"test":"true"}}`)
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir, BuildStateDir: stateBase}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist/index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("stale recovery deleted/replaced restored dist: %q", got)
	}
	if _, err := state.Lstat(buildJournalName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale journal remains: %v", err)
	}
}

func TestRepositoryPreseedNamesAreNeverTrustedOrDeleted(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, ".adversary-build-journal.json", "hostile")
	writeFile(t, dir, ".dist-adversary-stage-user/keep", "stage")
	writeFile(t, dir, ".dist-adversary-backup-user/keep", "backup")
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nrm -rf dist; mkdir dist; printf built > dist/index.js\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{".adversary-build-journal.json": "hostile", ".dist-adversary-stage-user/keep": "stage", ".dist-adversary-backup-user/keep": "backup"} {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q", path, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".publication-locks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repository lock metadata exists: %v", err)
	}
}

func TestStartupRecoveryRestoresStrandedBackup(t *testing.T) {
	dir := testProject(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	state, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	backup := ".dist-adversary-backup-0123456789abcdef0123456789abcdef"
	stage := ".dist-adversary-stage-0123456789abcdef0123456789abcdef"
	if err := root.Rename("dist", backup); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildJournal(state, buildJournal{Project: projectCorrelation(root), State: "backup-moved", Stage: stage, Backup: backup, HadDist: true}); err != nil {
		t.Fatal(err)
	}
	if err := recoverDistPublication(state, root); err != nil {
		t.Fatal(err)
	}
	got, err := root.ReadFile("dist/index.js")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "console.log('ok')\n" {
		t.Fatalf("restored dist = %q", got)
	}
	if _, err := state.Lstat(buildJournalName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external journal remains: %v", err)
	}
	assertNoBuildDebris(t, dir)
}

func TestStartupRecoveryPrecedesPackageIntentParsing(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate    func(*testing.T, string)
		wantError string
	}{
		"missing package": {func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "package.json")); err != nil {
				t.Fatal(err)
			}
		}, ""},
		"malformed package": {func(t *testing.T, dir string) { writeFile(t, dir, "package.json", "{") }, "parse package.json"},
		"no build script":   {func(t *testing.T, dir string) { writeFile(t, dir, "package.json", `{"scripts":{"test":"true"}}`) }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := testProject(t)
			stateBase := filepath.Join(t.TempDir(), "state")
			base, err := ensureBuildStateRoot(stateBase)
			if err != nil {
				t.Fatal(err)
			}
			state, err := openProjectBuildState(base, mustCanonicalProject(t, dir))
			if err != nil {
				t.Fatal(err)
			}
			project, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			backup := ".dist-adversary-backup-11111111111111111111111111111111"
			stage := ".dist-adversary-stage-22222222222222222222222222222222"
			if err := project.Rename("dist", backup); err != nil {
				t.Fatal(err)
			}
			if err := project.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeBuildJournal(state, buildJournal{Project: projectCorrelation(project), State: "backup-moved", Stage: stage, Backup: backup, HadDist: true}); err != nil {
				t.Fatal(err)
			}
			state.Close()
			project.Close()
			tt.mutate(t, dir)
			err = BuildProject(context.Background(), BuildOptions{Dir: dir, BuildStateDir: stateBase})
			if tt.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("error = %v", err)
			}
			got, readErr := os.ReadFile(filepath.Join(dir, "dist/index.js"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != "console.log('ok')\n" {
				t.Fatalf("dist not recovered: %q", got)
			}
		})
	}
}

func mustCanonicalProject(t *testing.T, dir string) string {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestBuildLockSerializesConcurrentBuilds(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	sentinel := filepath.Join(t.TempDir(), "active")
	overlap := filepath.Join(t.TempDir(), "overlap")
	script := "#!/bin/sh\nif ! mkdir \"$BUILD_SENTINEL\" 2>/dev/null; then printf overlap > \"$BUILD_OVERLAP\"; exit 9; fi\nsleep 0.2\nrm -rf dist; mkdir dist; printf built > dist/index.js\nrmdir \"$BUILD_SENTINEL\"\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BUILD_SENTINEL", sentinel)
	t.Setenv("BUILD_OVERLAP", overlap)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs <- BuildProject(context.Background(), BuildOptions{Dir: dir}) }()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(overlap); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("builds overlapped: %v", err)
	}
	assertNoBuildDebris(t, dir)
}

func TestBuildLockSerializesProcesses(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	sentinel := filepath.Join(t.TempDir(), "active")
	overlap := filepath.Join(t.TempDir(), "overlap")
	script := "#!/bin/sh\nif ! mkdir \"$BUILD_SENTINEL\" 2>/dev/null; then printf overlap > \"$BUILD_OVERLAP\"; exit 9; fi\nsleep 0.2\nrm -rf dist; mkdir dist; printf built > dist/index.js\nrmdir \"$BUILD_SENTINEL\"\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "ADVERSARY_BUILD_HELPER="+dir, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "BUILD_SENTINEL="+sentinel, "BUILD_OVERLAP="+overlap)
	commands := []*exec.Cmd{exec.Command(os.Args[0], "-test.run=^TestBuildLockCrossProcessHelper$"), exec.Command(os.Args[0], "-test.run=^TestBuildLockCrossProcessHelper$")}
	outputs := make([]bytes.Buffer, len(commands))
	for i, cmd := range commands {
		cmd.Env = env
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("helper failed: %v\n%s", err, outputs[i].String())
		}
	}
	if _, err := os.Stat(overlap); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("process builds overlapped: %v", err)
	}
	assertNoBuildDebris(t, dir)
}

func TestBuildLockCrossProcessHelper(t *testing.T) {
	dir := os.Getenv("ADVERSARY_BUILD_HELPER")
	if dir == "" {
		return
	}
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildSnapshotDoesNotExposeSourceNodeModules(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "node_modules/pkg/data", "original")
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	script := "#!/bin/sh\nprintf malicious > node_modules/pkg/data\nrm -rf dist; mkdir dist; printf built > dist/index.js\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "node_modules/pkg/data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("source dependency mutated: %q", got)
	}
}

func TestBuildSnapshotRejectsSymlinkSwapWithoutReadingOutside(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "node_modules/pkg/data", "inside")
	bin := t.TempDir()
	writeFakeNode22(t, bin)
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret-outside"), 0644); err != nil {
		t.Fatal(err)
	}
	beforeBuildSnapshotOpen = func(rel string) {
		if rel == "node_modules/pkg/data" {
			_ = os.Remove(filepath.Join(dir, filepath.FromSlash(rel)))
			_ = os.Symlink(outside, filepath.Join(dir, filepath.FromSlash(rel)))
		}
	}
	t.Cleanup(func() { beforeBuildSnapshotOpen = nil })
	err := BuildProject(context.Background(), BuildOptions{Dir: dir})
	if err == nil {
		t.Fatal("expected symlink-swap rejection")
	}
	if strings.Contains(err.Error(), "secret-outside") {
		t.Fatalf("outside content leaked: %v", err)
	}
	assertNoBuildDebris(t, dir)
}

func assertNoBuildDebris(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".dist-adversary-") || entry.Name() == buildJournalName {
			t.Fatalf("stranded build state: %s", entry.Name())
		}
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	return names
}

func TestDockerBuildRequiresLockfileBeforeDockerOrNodeModules(t *testing.T) {
	dir := testProject(t)
	t.Setenv("PATH", t.TempDir())
	err := BuildProject(context.Background(), BuildOptions{Dir: dir, Builder: "docker"})
	if err == nil || !strings.Contains(err.Error(), "requires package-lock.json") {
		t.Fatalf("error = %v", err)
	}
}

func TestDockerBuildDoesNotRequireHostNodeModules(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "package-lock.json", `{"lockfileVersion":3}`)
	bin := t.TempDir()
	docker := filepath.Join(bin, "docker")
	script := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in type=local,dest=*) out="${arg#type=local,dest=}";; esac
done
mkdir -p "$out/dist"
printf docker-built > "$out/dist/index.js"
`
	if err := os.WriteFile(docker, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := BuildProject(context.Background(), BuildOptions{Dir: dir, Builder: "docker"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "docker-built" {
		t.Fatalf("dist = %q", got)
	}
}

func TestDockerBuildfilePinsNodeAndUsesNPMCI(t *testing.T) {
	got := dockerBuildfile()
	for _, want := range []string{"node:22.14.0-alpine3.21@sha256:", "RUN npm ci"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Dockerfile missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "npm install") {
		t.Fatalf("Dockerfile permits unlocked install:\n%s", got)
	}
	if nodeBuilderImage != "node:22.14.0-alpine3.21@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944" ||
		nodeBuilderAMD64Manifest != "sha256:01393fe5a51489b63da0ab51aa8e0a7ff9990132917cf20cfc3d46f5e36c0e48" ||
		nodeBuilderARM64Manifest != "sha256:4a78eedb5c49d58c0c0b610ebc48f4ac397358604daac64e8dec1baecde2a31b" {
		t.Fatal("verified Node builder digest/platform evidence changed")
	}
}

func TestLocalBuildRejectsMismatchedNodeVersion(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\nprintf 'v20.19.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	err := BuildProject(context.Background(), BuildOptions{Dir: dir})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v", err)
	}
}

func writeFakeNode22(t *testing.T, bin string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\nprintf 'v22.14.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRejectsUnsupportedBuilder(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{Dir: dir, Build: true, Builder: "spaceship", BuildProject: BuildProject})
	if err == nil {
		t.Fatal("expected unsupported builder error")
	}
	if !strings.Contains(err.Error(), "unsupported builder") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateFailsForMissingManifest(t *testing.T) {
	_, err := Create(context.Background(), Options{Dir: t.TempDir()})
	if err == nil {
		t.Fatal("expected missing manifest error")
	}
}

func TestCreateFailsForInvalidManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "adversary.yaml", "version: 0.1.0\n")
	_, err := Create(context.Background(), Options{Dir: dir})
	if err == nil {
		t.Fatal("expected invalid manifest error")
	}
}

func testProject(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	dir := t.TempDir()
	writeFile(t, dir, "adversary.yaml", `name: local/security-reviewer
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
permissions:
  network: false
`)
	writeFile(t, dir, "README.md", "# Security Reviewer\n")
	writeFile(t, dir, "LICENSE", "MIT\n")
	writeFile(t, dir, "package.json", `{"scripts":{"build":"tsc -p tsconfig.json"}}`)
	writeFile(t, dir, "dist/index.js", "console.log('ok')\n")
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
