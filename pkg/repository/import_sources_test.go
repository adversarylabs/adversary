package repository

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/adversarylabs/adversary/internal/rootreplace"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

func mutateSourceMetadata(t *testing.T, in SourceImport, mutateConfig func(map[string]any), mutateAnnotations func(map[string]string)) SourceImport {
	t.Helper()
	var manifest oci.Manifest
	manifestData, err := readSourceLimited(in.Manifest, 4<<20)
	if err != nil || json.Unmarshal(manifestData, &manifest) != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var configIndex int
	for i := range in.Blobs {
		if in.Blobs[i].Descriptor.MediaType == oci.EmptyConfigMediaType {
			configIndex = i
		}
	}
	configData, err := readSourceLimited(in.Blobs[configIndex].Source, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatal(err)
	}
	if mutateConfig != nil {
		mutateConfig(config)
	}
	configData, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configSource := blobsource.Bytes(configData)
	configBlob, err := oci.NewSourceBlob(oci.Descriptor{MediaType: oci.EmptyConfigMediaType, Digest: configSource.Digest(), Size: configSource.Size()}, configSource)
	if err != nil {
		t.Fatal(err)
	}
	in.Blobs[configIndex] = configBlob
	if mutateAnnotations != nil {
		mutateAnnotations(manifest.Annotations)
	}
	manifestData, _, _, err = oci.NewManifest(configData, manifest.Layers[0], manifest.Annotations)
	if err != nil {
		t.Fatal(err)
	}
	in.Manifest = blobsource.Bytes(manifestData)
	return in
}

func assertImportValidationLeftNoState(t *testing.T, repo Repository, in SourceImport) {
	t.Helper()
	for _, dir := range []string{"records", "refs", "materialized", "manifests", "blobs", "adversary-manifests"} {
		entries, err := os.ReadDir(filepath.Join(repo.Root, dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("validation failure left %s entries: %v", dir, entries)
		}
	}
	if _, err := repo.Resolve(in.Name); err == nil {
		t.Fatal("validation failure committed a resolvable alias")
	}
}

func TestImportSourcesRejectsMetadataAndInventoryConflictsBeforePublication(t *testing.T) {
	tests := []struct {
		name        string
		config      func(map[string]any)
		annotations func(map[string]string)
		adversary   []byte
	}{
		{"creation timestamp", func(c map[string]any) { c["created"] = "now" }, nil, nil},
		{"full name", func(c map[string]any) { c["full_name"] = "other/tool" }, nil, nil},
		{"runtime name", func(c map[string]any) { c["runtime_name"] = "process" }, nil, nil},
		{"runtime version", func(c map[string]any) { c["runtime_version"] = "20" }, nil, nil},
		{"runtime image", func(c map[string]any) { c["runtime_image"] = "example.invalid/tool:1" }, nil, nil},
		{"entrypoint", func(c map[string]any) { c["entrypoint"] = []any{"other.js"} }, nil, nil},
		{"missing empty annotation", nil, func(a map[string]string) { delete(a, "ai.adversary.runtime.image") }, nil},
		{"attached runtime", nil, nil, []byte("name: local/test\nversion: 1.0.0\nruntime:\n  name: node\n  version: \"20\"\n  command: [dist/index.js]\n")},
		{"missing file", func(c map[string]any) { files := c["files"].([]any); c["files"] = files[1:] }, nil, nil},
		{"extra file", func(c map[string]any) {
			files := c["files"].([]any)
			c["files"] = append(files, map[string]any{"path": "zz-extra", "size": float64(1), "sha256": strings.Repeat("0", 64), "mode": float64(0644)})
		}, nil, nil},
		{"size", func(c map[string]any) { c["files"].([]any)[0].(map[string]any)["size"] = float64(999) }, nil, nil},
		{"mode", func(c map[string]any) {
			file := c["files"].([]any)[0].(map[string]any)
			if file["mode"].(float64) == float64(0644) {
				file["mode"] = float64(0755)
			} else {
				file["mode"] = float64(0644)
			}
		}, nil, nil},
		{"hash", func(c map[string]any) { c["files"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64) }, nil, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, in := sourceFixture(t)
			defer a.Close()
			in = mutateSourceMetadata(t, in, test.config, test.annotations)
			if test.adversary != nil {
				in.AdversaryManifest = blobsource.Bytes(test.adversary)
			}
			repo := newSourceRepository(t)
			if _, err := repo.ImportSources(in); err == nil {
				t.Fatal("conflicting artifact accepted")
			}
			assertImportValidationLeftNoState(t, repo, in)
		})
	}
}

func maliciousLayer(t *testing.T, entries []tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for i := range entries {
		header := entries[i]
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte{'x'}, int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func appendLayerFile(t *testing.T, source blobsource.Source, name string, content []byte) []byte {
	t.Helper()
	reader, err := source.Open()
	if err != nil {
		t.Fatal(err)
	}
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzReader)
	var output bytes.Buffer
	gzWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzWriter)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		copyHeader := *header
		if err := tarWriter.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tarWriter, tarReader); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzReader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func replaceImportLayer(t *testing.T, in SourceImport, layerData []byte) SourceImport {
	t.Helper()
	var manifest oci.Manifest
	manifestData, err := readSourceLimited(in.Manifest, 4<<20)
	if err != nil || json.Unmarshal(manifestData, &manifest) != nil {
		t.Fatalf("read manifest: %v", err)
	}
	layerSource := blobsource.Bytes(layerData)
	layerBlob, err := oci.NewSourceBlob(oci.Descriptor{MediaType: oci.PackageLayerMediaType, Digest: layerSource.Digest(), Size: layerSource.Size()}, layerSource)
	if err != nil {
		t.Fatal(err)
	}
	var configData []byte
	for i := range in.Blobs {
		if in.Blobs[i].Descriptor.MediaType == oci.PackageLayerMediaType {
			in.Blobs[i] = layerBlob
		}
		if in.Blobs[i].Descriptor.MediaType == oci.EmptyConfigMediaType {
			configData, err = readSourceLimited(in.Blobs[i].Source, 1<<20)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	manifestData, _, _, err = oci.NewManifest(configData, layerBlob.Descriptor, manifest.Annotations)
	if err != nil {
		t.Fatal(err)
	}
	in.Manifest = blobsource.Bytes(manifestData)
	return in
}

func TestLayerBackedAdversaryManifestIsValidatedPromotedAndReopened(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	var layerSource blobsource.Source
	for _, blob := range in.Blobs {
		if blob.Descriptor.MediaType == oci.PackageLayerMediaType {
			layerSource = blob.Source
		}
	}
	layerData := appendLayerFile(t, layerSource, "adversary.yaml", a.AdversaryManifest)
	digest := sha256.Sum256(a.AdversaryManifest)
	in = mutateSourceMetadata(t, in, func(config map[string]any) {
		files := append(config["files"].([]any), map[string]any{"path": "adversary.yaml", "size": float64(len(a.AdversaryManifest)), "sha256": fmt.Sprintf("%x", digest), "mode": float64(0644)})
		sort.Slice(files, func(i, j int) bool {
			return files[i].(map[string]any)["path"].(string) < files[j].(map[string]any)["path"].(string)
		})
		config["files"] = files
	}, nil)
	in = replaceImportLayer(t, in, layerData)
	in.AdversaryManifest = nil
	repo := newSourceRepository(t)
	rec, err := repo.ImportSources(in)
	if err != nil {
		t.Fatal(err)
	}
	if rec.AdversaryManifestDigest == "" {
		t.Fatal("layer-backed manifest was not promoted")
	}
	legacy := rec
	legacy.AdversaryManifestDigest = ""
	legacyData, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(repo.Root, "records", key(rec.Digest)+".json")
	if err := os.Chmod(recordPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, legacyData, 0444); err != nil {
		t.Fatal(err)
	}
	rec = legacy
	reopened := Repository{Root: repo.Root}
	path, err := reopened.Materialize(rec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0755) })
	got, err := os.ReadFile(filepath.Join(path, "adversary.yaml"))
	if err != nil || !bytes.Equal(got, a.AdversaryManifest) {
		t.Fatalf("materialized manifest=%q err=%v", got, err)
	}
	files, err := reopened.Inventory(rec)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.Path == "adversary.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatal("layer-backed manifest missing from verified inventory")
	}
	lease, err := reopened.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	payloadManifest, err := readSourceLimited(lease.AdversaryManifest, 1<<20)
	if err != nil || !bytes.Equal(payloadManifest, a.AdversaryManifest) {
		t.Fatalf("payload manifest=%q err=%v", payloadManifest, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestImportRejectsMissingOrConflictingAdversaryManifest(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		a, in := sourceFixture(t)
		defer a.Close()
		in.AdversaryManifest = nil
		repo := newSourceRepository(t)
		if _, err := repo.ImportSources(in); err == nil {
			t.Fatal("missing manifest accepted")
		}
		assertImportValidationLeftNoState(t, repo, in)
	})
	t.Run("conflicting copies", func(t *testing.T) {
		a, in := sourceFixture(t)
		defer a.Close()
		var layerSource blobsource.Source
		for _, blob := range in.Blobs {
			if blob.Descriptor.MediaType == oci.PackageLayerMediaType {
				layerSource = blob.Source
			}
		}
		digest := sha256.Sum256(a.AdversaryManifest)
		in = mutateSourceMetadata(t, in, func(config map[string]any) {
			files := append(config["files"].([]any), map[string]any{"path": "adversary.yaml", "size": float64(len(a.AdversaryManifest)), "sha256": fmt.Sprintf("%x", digest), "mode": float64(0644)})
			sort.Slice(files, func(i, j int) bool {
				return files[i].(map[string]any)["path"].(string) < files[j].(map[string]any)["path"].(string)
			})
			config["files"] = files
		}, nil)
		in = replaceImportLayer(t, in, appendLayerFile(t, layerSource, "adversary.yaml", a.AdversaryManifest))
		in.AdversaryManifest = blobsource.Bytes([]byte("name: local/test\nversion: 1.0.0\ndescription: conflicting attachment\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n"))
		repo := newSourceRepository(t)
		if _, err := repo.ImportSources(in); err == nil {
			t.Fatal("conflicting manifests accepted")
		}
		assertImportValidationLeftNoState(t, repo, in)
	})
}

func TestImportSourcesRejectsUnsafeLayerArchiveBeforePublication(t *testing.T) {
	tests := map[string][]tar.Header{
		"traversal": {{Name: "../escape", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}},
		"duplicate": {{Name: "same", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}, {Name: "same", Mode: 0644, Size: 1, Typeflag: tar.TypeReg}},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			a, in := sourceFixture(t)
			defer a.Close()
			layerData := maliciousLayer(t, entries)
			layerSource := blobsource.Bytes(layerData)
			layerBlob, err := oci.NewSourceBlob(oci.Descriptor{MediaType: oci.PackageLayerMediaType, Digest: layerSource.Digest(), Size: layerSource.Size()}, layerSource)
			if err != nil {
				t.Fatal(err)
			}
			var manifest oci.Manifest
			manifestData, _ := readSourceLimited(in.Manifest, 4<<20)
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				t.Fatal(err)
			}
			for i := range in.Blobs {
				if in.Blobs[i].Descriptor.MediaType == oci.PackageLayerMediaType {
					in.Blobs[i] = layerBlob
				}
			}
			configData, _ := readSourceLimited(in.Blobs[0].Source, 1<<20)
			for _, blob := range in.Blobs {
				if blob.Descriptor.MediaType == oci.EmptyConfigMediaType {
					configData, _ = readSourceLimited(blob.Source, 1<<20)
				}
			}
			manifestData, _, _, err = oci.NewManifest(configData, layerBlob.Descriptor, manifest.Annotations)
			if err != nil {
				t.Fatal(err)
			}
			in.Manifest = blobsource.Bytes(manifestData)
			repo := newSourceRepository(t)
			if _, err := repo.ImportSources(in); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			assertImportValidationLeftNoState(t, repo, in)
		})
	}
}

func commitWithoutLayerValidation(t *testing.T, repo Repository, in SourceImport) Record {
	t.Helper()
	manifestData, err := readSourceLimited(in.Manifest, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	configData := []byte(nil)
	var config, layer blobsource.Source
	for _, blob := range in.Blobs {
		if err := repo.putSource("blobs", blob.Source); err != nil {
			t.Fatal(err)
		}
		switch blob.Descriptor.MediaType {
		case oci.EmptyConfigMediaType:
			config = blob.Source
			configData, err = readSourceLimited(config, 1<<20)
		case oci.PackageLayerMediaType:
			layer = blob.Source
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	adversary, err := readSourceLimited(in.AdversaryManifest, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.putSource("manifests", in.Manifest); err != nil {
		t.Fatal(err)
	}
	if err := repo.putSource("adversary-manifests", in.AdversaryManifest); err != nil {
		t.Fatal(err)
	}
	rec, err := repo.importData(importMetadata{
		Reference: in.Reference, Name: in.Name, Version: in.Version,
		Manifest: manifestData, Config: configData, AdversaryManifest: adversary,
		ManifestDigest: in.Manifest.Digest(), ConfigDigest: config.Digest(), LayerDigest: layer.Digest(),
		AdversaryManifestDigest: in.AdversaryManifest.Digest(),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRepairDoesNotReportSemanticCorruptionAsResolved(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	in = mutateSourceMetadata(t, in, func(config map[string]any) {
		config["files"].([]any)[0].(map[string]any)["size"] = float64(999)
	}, nil)
	repo := newSourceRepository(t)
	rec := commitWithoutLayerValidation(t, repo, in)
	if result := repo.Verify(rec); len(result.Corrupt) == 0 {
		t.Fatal("semantic corruption reported healthy")
	}
	if err := repo.Repair(rec, nil); err == nil {
		t.Fatal("Repair reported semantic corruption resolved")
	}
	report, err := repo.RepairAll(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Repaired) != 0 || len(report.Unresolved) != 1 || report.Unresolved[0] != rec.Digest {
		t.Fatalf("repair report=%#v", report)
	}
}

func TestImportPackedStreamsOwnedLayerIntoRepository(t *testing.T) {
	dir := t.TempDir()
	manifest := "name: team/streaming\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 12<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.bin"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("export {};\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	r := Repository{Root: root}
	rec, err := r.ImportPacked(a, "streaming:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.PayloadSources(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := blobsource.Verify(lease.Blobs[1].Source); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestImportSourcesRejectsCoherentBlobThatConflictsWithManifest(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	r, err := in.Blobs[1].Source.Open()
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
	data = data[:len(data)-1]
	descriptor := in.Blobs[1].Descriptor
	descriptor.Size = int64(len(data))
	descriptor.Digest = oci.Digest(data)
	in.Blobs[1], err = oci.NewSourceBlob(descriptor, blobsource.Bytes(data))
	if err != nil {
		t.Fatal(err)
	}
	repo := newSourceRepository(t)
	if _, err := repo.ImportSources(in); err == nil || !strings.Contains(err.Error(), "descriptors conflict") {
		t.Fatalf("expected manifest descriptor conflict, got %v", err)
	}
}

func TestImportSourcesBoundsChangedLayerAtDeclaredSize(t *testing.T) {
	a, in := sourceFixture(t)
	defer a.Close()
	original := in.Blobs[1].Source
	var read int64
	changed, err := blobsource.New(original.Size(), original.Digest(), func() (io.ReadCloser, error) {
		r, err := original.Open()
		if err != nil {
			return nil, err
		}
		return &countedExtraReader{Reader: io.MultiReader(r, bytes.NewReader([]byte("extra"))), close: r, read: &read}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	in.Blobs[1].Source = changed
	repo := newSourceRepository(t)
	if _, err := repo.ImportSources(in); err == nil || !strings.Contains(err.Error(), "exceeds declared") {
		t.Fatalf("expected overflow, got %v", err)
	}
	if read > original.Size()+1 {
		t.Fatalf("read %d bytes, want at most declared size+1", read)
	}
	if _, err := os.Stat(filepath.Join(repo.Root, "blobs", key(original.Digest()))); !os.IsNotExist(err) {
		t.Fatalf("overflowing source published: %v", err)
	}
}

func TestPutSourceUsesRootedDurableImmutablePublication(t *testing.T) {
	repo := newSourceRepository(t)
	src := blobsource.Bytes([]byte("content"))
	injected := errors.New("sync failed")
	rootreplace.SyncHook = func(step string) error {
		if step == "file" {
			return injected
		}
		return nil
	}
	defer func() { rootreplace.SyncHook = nil }()
	if err := repo.putSource("blobs", src); !errors.Is(err, injected) {
		t.Fatalf("expected sync failure, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo.Root, "blobs", key(src.Digest()))); !os.IsNotExist(err) {
		t.Fatalf("published after sync failure: %v", err)
	}
	rootreplace.SyncHook = nil
	external := t.TempDir()
	if err := os.Remove(filepath.Join(repo.Root, "blobs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(repo.Root, "blobs")); err != nil {
		t.Fatal(err)
	}
	if err := repo.putSource("blobs", src); err == nil {
		t.Fatal("expected rooted symlink rejection")
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 0 {
		t.Fatalf("wrote through symlink: entries=%v err=%v", entries, err)
	}
}

func TestPutSourcePreservesPostLinkDirectorySyncFailure(t *testing.T) {
	repo := newSourceRepository(t)
	if err := repo.init(); err != nil {
		t.Fatal(err)
	}
	src := blobsource.Bytes([]byte("durable content"))
	injected := errors.New("directory sync failed")
	fileSynced := false
	rootreplace.SyncHook = func(step string) error {
		if step == "file" {
			fileSynced = true
		}
		if step == "directory" && fileSynced {
			return injected
		}
		return nil
	}
	defer func() { rootreplace.SyncHook = nil }()
	if err := repo.putSource("blobs", src); !errors.Is(err, injected) {
		t.Fatalf("post-link sync failure masked: %v", err)
	}
	f, err := os.Open(filepath.Join(repo.Root, "blobs", key(src.Digest())))
	if err != nil {
		t.Fatalf("linked artifact missing after sync failure: %v", err)
	}
	verifyErr := verifyReader(f, src)
	closeErr := f.Close()
	if err := errors.Join(verifyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	rootreplace.SyncHook = nil
	if err := repo.putSource("blobs", src); err != nil {
		t.Fatalf("clean retry did not accept verified artifact: %v", err)
	}
}

func TestPutSourceConcurrentWritersShareImmutableContent(t *testing.T) {
	repo := newSourceRepository(t)
	src := blobsource.Bytes(bytes.Repeat([]byte("x"), 2<<20))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- repo.putSource("blobs", src) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(filepath.Join(repo.Root, "blobs", key(src.Digest())))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := verifyReader(f, src); err != nil {
		t.Fatal(err)
	}
}

func TestCopyExactStopsReaderWithNoProgress(t *testing.T) {
	if _, _, err := copyExact(io.Discard, noProgressReader{}, 1); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("expected no-progress error, got %v", err)
	}
}

func TestCopyExactRejectsInvalidReaderCounts(t *testing.T) {
	for _, count := range []int{-1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			if _, _, err := copyExact(io.Discard, invalidCountReader{count: count}, 1); err == nil || !strings.Contains(err.Error(), "invalid byte count") {
				t.Fatalf("count %d: %v", count, err)
			}
		})
	}
}

func TestReadSourceLimitedRejectsDeclaredSizeBeforeOpen(t *testing.T) {
	opened := false
	src, err := blobsource.New((4<<20)+1, oci.Digest(nil), func() (io.ReadCloser, error) { opened = true; return io.NopCloser(bytes.NewReader(nil)), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSourceLimited(src, 4<<20); err == nil {
		t.Fatal("expected ceiling rejection")
	}
	if opened {
		t.Fatal("oversized source was opened")
	}
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type invalidCountReader struct{ count int }

func (r invalidCountReader) Read([]byte) (int, error) { return r.count, nil }

type countedExtraReader struct {
	io.Reader
	close io.Closer
	read  *int64
}

type alternatingSource struct {
	size          int64
	digest        string
	first, second []byte
	opens         int
}

func (s *alternatingSource) Size() int64    { return s.size }
func (s *alternatingSource) Digest() string { return s.digest }
func (s *alternatingSource) Open() (io.ReadCloser, error) {
	s.opens++
	data := s.first
	if s.opens > 1 {
		data = s.second
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func TestImportSourcesStagesAlternatingLayerExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name       string
		firstValid bool
	}{
		{"trusted first read persists", true},
		{"invalid first read leaves no state", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, in := sourceFixture(t)
			defer a.Close()
			var layerIndex int
			for i := range in.Blobs {
				if in.Blobs[i].Descriptor.MediaType == oci.PackageLayerMediaType {
					layerIndex = i
				}
			}
			valid, err := readSourceLimited(in.Blobs[layerIndex].Source, 256<<20)
			if err != nil {
				t.Fatal(err)
			}
			invalid := append([]byte(nil), valid...)
			invalid[len(invalid)-1] ^= 0xff
			first, second := valid, invalid
			if !test.firstValid {
				first, second = invalid, valid
			}
			alternating := &alternatingSource{size: int64(len(valid)), digest: in.Blobs[layerIndex].Descriptor.Digest, first: first, second: second}
			in.Blobs[layerIndex].Source = alternating
			repo := newSourceRepository(t)
			_, err = repo.ImportSources(in)
			if test.firstValid && err != nil {
				t.Fatal(err)
			}
			if !test.firstValid && err == nil {
				t.Fatal("invalid first read accepted")
			}
			if alternating.opens != 1 {
				t.Fatalf("caller-owned layer opened %d times, want 1", alternating.opens)
			}
			if !test.firstValid {
				assertImportValidationLeftNoState(t, repo, in)
			}
		})
	}
}

func (r *countedExtraReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	*r.read += int64(n)
	return n, err
}
func (r *countedExtraReader) Close() error { return r.close.Close() }

func sourceFixture(t *testing.T) (pack.Artifact, SourceImport) {
	t.Helper()
	dir := t.TempDir()
	manifest := "name: team/source\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [index.js]\n"
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('x')"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := pack.Create(context.Background(), pack.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := a.Sources()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	return a, SourceImport{Reference: "source:1.0.0", Name: a.ManifestName, Version: a.Version, Manifest: blobsource.Bytes(a.Manifest), AdversaryManifest: blobsource.Bytes(a.AdversaryManifest), Blobs: blobs}
}

func newSourceRepository(t *testing.T) Repository {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return Repository{Root: root}
}
