package store

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
)

type Store struct {
	Root string
}

type Record struct {
	Name                    string            `json:"name"`
	Version                 string            `json:"version"`
	Digest                  string            `json:"digest"`
	AdversaryManifestDigest string            `json:"adversaryManifestDigest,omitempty"`
	Runtime                 string            `json:"runtime"`
	RuntimeName             string            `json:"runtimeName,omitempty"`
	RuntimeVersion          string            `json:"runtimeVersion,omitempty"`
	Entrypoint              []string          `json:"entrypoint,omitempty"`
	Permissions             any               `json:"permissions,omitempty"`
	Size                    int64             `json:"size"`
	Created                 time.Time         `json:"created"`
	ConfigDigest            string            `json:"configDigest"`
	LayerDigest             string            `json:"layerDigest"`
	Files                   []pack.File       `json:"files"`
	Annotations             map[string]string `json:"annotations,omitempty"`
	Manifest                oci.Manifest      `json:"manifest"`
	ManifestPath            string            `json:"manifestPath,omitempty"`
	AdversaryManifestPath   string            `json:"adversaryManifestPath,omitempty"`
	ConfigPath              string            `json:"configPath,omitempty"`
	LayerPath               string            `json:"layerPath,omitempty"`
}

const MaxAdversaryManifestSize = 1 << 20

func Default() (Store, error) {
	if override := strings.TrimSpace(os.Getenv("ADVERSARY_DATA_DIR")); override != "" {
		return Store{Root: override}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Store{Root: filepath.Join(".", ".adversary")}, nil
	}
	switch runtime.GOOS {
	case "darwin":
		return Store{Root: filepath.Join(home, "Library", "Application Support", "Adversary")}, nil
	case "linux":
		if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdg != "" {
			return Store{Root: filepath.Join(xdg, "adversary")}, nil
		}
		return Store{Root: filepath.Join(home, ".local", "share", "adversary")}, nil
	default:
		return Store{Root: filepath.Join(home, ".adversary")}, nil
	}
}

func (s Store) Put(artifact pack.Artifact) (Record, error) {
	_, err := parseAndCheckManifest(artifact.AdversaryManifest, artifact.Name, artifact.Version)
	if err != nil {
		return Record{}, fmt.Errorf("validate packed adversary.yaml: %w", err)
	}
	if err := s.writeContent("blobs", artifact.ConfigDigest, artifact.Config); err != nil {
		return Record{}, err
	}
	if err := s.writeContent("blobs", artifact.LayerDigest, artifact.Layer); err != nil {
		return Record{}, err
	}
	if err := s.writeContent("manifests", artifact.ManifestDigest, artifact.Manifest); err != nil {
		return Record{}, err
	}
	if err := s.writeContent("adversary-manifests", artifact.AdversaryManifestDigest, artifact.AdversaryManifest); err != nil {
		return Record{}, err
	}
	record := Record{
		Name:                    artifact.Name,
		Version:                 artifact.Version,
		Digest:                  artifact.ManifestDigest,
		AdversaryManifestDigest: artifact.AdversaryManifestDigest,
		Runtime:                 artifact.Runtime,
		RuntimeName:             artifact.RuntimeName,
		RuntimeVersion:          artifact.RuntimeVersion,
		Entrypoint:              artifact.Entrypoint,
		Permissions:             artifact.Permissions,
		Size:                    artifact.Size,
		Created:                 time.Now().UTC(),
		ConfigDigest:            artifact.ConfigDigest,
		LayerDigest:             artifact.LayerDigest,
		Files:                   artifact.Files,
		Annotations:             artifact.OCIManifest.Annotations,
		Manifest:                artifact.OCIManifest,
		ManifestPath:            s.contentPath("manifests", artifact.ManifestDigest),
		AdversaryManifestPath:   s.contentPath("adversary-manifests", artifact.AdversaryManifestDigest),
		ConfigPath:              s.contentPath("blobs", artifact.ConfigDigest),
		LayerPath:               s.contentPath("blobs", artifact.LayerDigest),
	}
	if old, ok := s.resolveDigest(artifact.ManifestDigest); ok {
		record.Created = old.Created
	}
	if err := s.writeRecord(record); err != nil {
		return Record{}, err
	}
	if err := s.WriteRef(record.Name, record.Version, record.Digest); err != nil {
		return Record{}, err
	}
	if err := s.WriteRef(record.Name, oci.DefaultTag, record.Digest); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s Store) List() ([]Record, error) {
	root := filepath.Join(s.Root, "store", "records", "sha256")
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, prefix := range entries {
		if !prefix.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, prefix.Name()))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, prefix.Name(), file.Name()))
			if err != nil {
				return nil, err
			}
			var record Record
			if err := json.Unmarshal(data, &record); err != nil {
				return nil, err
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].Version < records[j].Version
		}
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func (s Store) Inspect(ref string) (Record, error) {
	if strings.HasPrefix(ref, "sha256:") {
		if record, ok := s.resolveDigest(ref); ok {
			return record, nil
		}
		return Record{}, fmt.Errorf("local adversary %q not found", ref)
	}
	name := ref
	tag := oci.DefaultTag
	if before, after, ok := splitNameTag(ref); ok {
		name = before
		tag = after
	}
	digestData, err := os.ReadFile(filepath.Join(s.Root, "refs", name, tag))
	if err != nil {
		return Record{}, fmt.Errorf("local adversary %q not found", ref)
	}
	digest := strings.TrimSpace(string(digestData))
	record, ok := s.resolveDigest(digest)
	if !ok {
		return Record{}, fmt.Errorf("local adversary %q points to missing digest %s", ref, digest)
	}
	return record, nil
}

func splitNameTag(ref string) (string, string, bool) {
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon <= lastSlash {
		return "", "", false
	}
	return ref[:lastColon], ref[lastColon+1:], true
}

func (s Store) Materialize(ref string) (string, Record, error) {
	record, err := s.Inspect(ref)
	if err != nil {
		return "", Record{}, err
	}
	path, err := s.MaterializeRecord(record)
	if err != nil {
		return "", Record{}, err
	}
	return path, record, nil
}

func (s Store) OCIPayload(record Record) ([]byte, []oci.Blob, error) {
	manifestPath := record.ManifestPath
	if manifestPath == "" {
		manifestPath = s.contentPath("manifests", record.Digest)
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, err
	}
	configPath := record.ConfigPath
	if configPath == "" {
		configPath = s.contentPath("blobs", record.ConfigDigest)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}
	layerPath := record.LayerPath
	if layerPath == "" {
		layerPath = s.contentPath("blobs", record.LayerDigest)
	}
	layerData, err := os.ReadFile(layerPath)
	if err != nil {
		return nil, nil, err
	}
	blobs := []oci.Blob{
		{
			Descriptor: oci.Descriptor{
				MediaType: oci.EmptyConfigMediaType,
				Digest:    record.ConfigDigest,
				Size:      int64(len(configData)),
			},
			Data: configData,
		},
		{
			Descriptor: oci.Descriptor{
				MediaType: oci.PackageLayerMediaType,
				Digest:    record.LayerDigest,
				Size:      int64(len(layerData)),
				Annotations: map[string]string{
					"org.opencontainers.image.title": "adversary-layer",
				},
			},
			Data: layerData,
		},
	}
	return manifestData, blobs, nil
}

func (s Store) AdversaryManifest(record Record) ([]byte, error) {
	path := record.AdversaryManifestPath
	if path == "" && record.AdversaryManifestDigest != "" {
		path = s.contentPath("adversary-manifests", record.AdversaryManifestDigest)
	}
	if path == "" {
		materialized, err := s.MaterializeRecord(record)
		if err != nil {
			return nil, err
		}
		path = filepath.Join(materialized, "adversary.yaml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("adversary.yaml is required for publishing: %w", err)
	}
	if _, err := parseAndCheckManifest(data, record.Name, record.Version); err != nil {
		return nil, err
	}
	if record.AdversaryManifestDigest != "" {
		if err := oci.VerifyDigest(data, record.AdversaryManifestDigest); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (s Store) MaterializeRecord(record Record) (string, error) {
	algo, value, ok := strings.Cut(record.Digest, ":")
	if !ok || algo == "" || value == "" {
		return "", fmt.Errorf("invalid digest %q", record.Digest)
	}
	destination := filepath.Join(s.Root, "artifacts", algo, value)
	if info, err := os.Stat(filepath.Join(destination, "adversary.yaml")); err == nil && !info.IsDir() {
		data, err := os.ReadFile(filepath.Join(destination, "adversary.yaml"))
		if err != nil {
			return "", err
		}
		if _, err := parseAndCheckManifest(data, record.Name, record.Version); err != nil {
			return "", fmt.Errorf("validate materialized adversary.yaml: %w", err)
		}
		if err := prepareRuntimeNodeModules(destination); err != nil {
			return "", err
		}
		return destination, nil
	}
	layerPath := record.LayerPath
	if layerPath == "" {
		layerPath = s.contentPath("blobs", record.LayerDigest)
	}
	file, err := os.Open(layerPath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := os.RemoveAll(destination); err != nil {
		return "", err
	}
	if err := os.MkdirAll(destination, 0755); err != nil {
		return "", err
	}
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		clean := filepath.Clean(header.Name)
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return "", fmt.Errorf("unsafe package path %q", header.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return "", err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(target, data, 0644); err != nil {
			return "", err
		}
	}
	manifestPath := filepath.Join(destination, "adversary.yaml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		data, err := s.AdversaryManifest(record)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(manifestPath, data, 0644); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", err
	}
	if _, err := parseAndCheckManifest(data, record.Name, record.Version); err != nil {
		return "", fmt.Errorf("validate materialized adversary.yaml: %w", err)
	}
	if err := prepareRuntimeNodeModules(destination); err != nil {
		return "", err
	}
	return destination, nil
}

func parseAndCheckManifest(data []byte, name, version string) (canonical.Manifest, error) {
	m, err := canonical.Parse(data)
	if err != nil {
		return canonical.Manifest{}, err
	}
	if name != "" && name != m.Name && canonical.ShortName(name) != canonical.ShortName(m.Name) {
		return canonical.Manifest{}, fmt.Errorf("manifest name %q does not match metadata name %q", m.Name, name)
	}
	if version != "" && version != m.Version {
		return canonical.Manifest{}, fmt.Errorf("manifest version %q does not match metadata version %q", m.Version, version)
	}
	return m, nil
}

func prepareRuntimeNodeModules(destination string) error {
	vendorSDK := filepath.Join(destination, "vendor", "adversary-sdk")
	if info, err := os.Stat(vendorSDK); err != nil || !info.IsDir() {
		return nil
	}
	target := filepath.Join(destination, "node_modules", "@adversary", "sdk")
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		return patchVendoredSDK(target)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if err := copyDir(vendorSDK, target); err != nil {
		return err
	}
	return patchVendoredSDK(target)
}

func patchVendoredSDK(sdkDir string) error {
	indexPath := filepath.Join(sdkDir, "dist", "index.js")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil
	}
	text := string(data)
	text = strings.ReplaceAll(text, "const repoPath = input.source.path;", "const repoPath = process.env.ADVERSARY_REPO ?? input.source.path ?? \"/workspace\";")
	text = strings.ReplaceAll(text, "export async function parseInput(path = DEFAULT_INPUT_PATH)", "export async function parseInput(path = process.env.ADVERSARY_INPUT ?? DEFAULT_INPUT_PATH)")
	text = strings.ReplaceAll(text, "export async function writeOutput(output, path = DEFAULT_OUTPUT_PATH)", "export async function writeOutput(output, path = process.env.ADVERSARY_OUTPUT ?? DEFAULT_OUTPUT_PATH)")
	if !strings.Contains(text, "DEFAULT_REPO_PATH") {
		text = strings.Replace(text, "export const DEFAULT_OUTPUT_PATH = \"/adversary/output.json\";", "export const DEFAULT_OUTPUT_PATH = \"/adversary/output.json\";\nexport const DEFAULT_REPO_PATH = \"/workspace\";", 1)
	}
	if text == string(data) {
		return nil
	}
	return os.WriteFile(indexPath, []byte(text), 0644)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}

func (s Store) WriteRef(name, tag, digest string) error {
	dir := filepath.Join(s.Root, "refs", name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, tag), []byte(digest+"\n"), 0644)
}

func (s Store) BlobCount() (int, error) {
	return countFiles(filepath.Join(s.Root, "store", "blobs"))
}

func (s Store) writeContent(kind, digest string, data []byte) error {
	path := s.contentPath(kind, digest)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s Store) writeRecord(record Record) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := s.recordPath(record.Digest)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s Store) resolveDigest(digest string) (Record, bool) {
	data, err := os.ReadFile(s.recordPath(digest))
	if err != nil {
		return Record{}, false
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, false
	}
	return record, true
}

func (s Store) contentPath(kind, digest string) string {
	algo, value, _ := strings.Cut(digest, ":")
	if len(value) < 2 {
		return filepath.Join(s.Root, "store", kind, algo, value)
	}
	return filepath.Join(s.Root, "store", kind, algo, value[:2], value)
}

func (s Store) recordPath(digest string) string {
	algo, value, _ := strings.Cut(digest, ":")
	if len(value) < 2 {
		return filepath.Join(s.Root, "store", "records", algo, value+".json")
	}
	return filepath.Join(s.Root, "store", "records", algo, value[:2], value+".json")
}

func countFiles(root string) (int, error) {
	count := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}
