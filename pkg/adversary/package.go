package adversary

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
)

const (
	ManifestFile = "adversary.yaml"
	MetadataFile = "manifest.json"
)

type Package struct {
	Manifest ManifestMetadata
	Layer    []byte
	Config   []byte
	Blob     oci.Blob
}

type ManifestMetadata struct {
	Name    string         `json:"name"`
	Version string         `json:"version,omitempty"`
	Files   []FileMetadata `json:"files"`
}

type FileMetadata struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func PackageDirectory(dir string) (Package, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Package{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
		return Package{}, fmt.Errorf("%s is required: %w", ManifestFile, err)
	}

	metadata, err := buildMetadata(dir)
	if err != nil {
		return Package{}, err
	}
	layer, err := buildLayer(dir, metadata)
	if err != nil {
		return Package{}, err
	}
	config, err := json.Marshal(struct {
		Created string `json:"created"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
	}{
		Created: "1970-01-01T00:00:00Z",
		Name:    metadata.Name,
		Version: metadata.Version,
	})
	if err != nil {
		return Package{}, err
	}
	descriptor := oci.Descriptor{
		MediaType: oci.PackageLayerMediaType,
		Digest:    oci.Digest(layer),
		Size:      int64(len(layer)),
		Annotations: map[string]string{
			"org.opencontainers.image.title": "adversary-package",
		},
	}
	return Package{
		Manifest: metadata,
		Layer:    layer,
		Config:   config,
		Blob:     oci.Blob{Descriptor: descriptor, Data: layer},
	}, nil
}

func BuildOCIManifest(pkg Package) ([]byte, string, error) {
	annotations := map[string]string{
		"org.opencontainers.image.title": pkg.Manifest.Name,
		"ai.adversary.name":              pkg.Manifest.Name,
	}
	if pkg.Manifest.Version != "" {
		annotations["org.opencontainers.image.version"] = pkg.Manifest.Version
		annotations["ai.adversary.version"] = pkg.Manifest.Version
	}
	data, digest, _, err := oci.NewManifest(pkg.Config, pkg.Blob.Descriptor, annotations)
	return data, digest, err
}

func (p Package) Blobs() []oci.Blob {
	return []oci.Blob{
		{
			Descriptor: oci.Descriptor{
				MediaType: oci.EmptyConfigMediaType,
				Digest:    oci.Digest(p.Config),
				Size:      int64(len(p.Config)),
			},
			Data: p.Config,
		},
		p.Blob,
	}
}

func buildMetadata(dir string) (ManifestMetadata, error) {
	var files []FileMetadata
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if shouldSkip(rel, entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, FileMetadata{
			Path:   rel,
			Size:   info.Size(),
			SHA256: hex.EncodeToString(sum[:]),
		})
		return nil
	})
	if err != nil {
		return ManifestMetadata{}, err
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	manifestData, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return ManifestMetadata{}, err
	}
	name, version := parseManifestIdentity(string(manifestData))
	if name == "" {
		return ManifestMetadata{}, fmt.Errorf("manifest name is required")
	}
	return ManifestMetadata{Name: name, Version: version, Files: files}, nil
}

func buildLayer(dir string, metadata ManifestMetadata) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Name = ""
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	for _, file := range metadata.Files {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name:    file.Path,
			Mode:    0644,
			Size:    int64(len(data)),
			ModTime: time.Unix(0, 0).UTC(),
			Uid:     0,
			Gid:     0,
			Uname:   "",
			Gname:   "",
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	header := &tar.Header{
		Name:    MetadataFile,
		Mode:    0644,
		Size:    int64(len(metadataData)),
		ModTime: time.Unix(0, 0).UTC(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}
	if _, err := tw.Write(metadataData); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ExtractLayer(layer []byte, destination string) (ManifestMetadata, error) {
	if err := os.MkdirAll(destination, 0755); err != nil {
		return ManifestMetadata{}, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return ManifestMetadata{}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var metadata ManifestMetadata
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ManifestMetadata{}, err
		}
		clean := filepath.Clean(header.Name)
		if clean == "." || strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return ManifestMetadata{}, fmt.Errorf("unsafe package path %q", header.Name)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return ManifestMetadata{}, err
		}
		if header.Name == MetadataFile {
			if err := json.Unmarshal(data, &metadata); err != nil {
				return ManifestMetadata{}, err
			}
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return ManifestMetadata{}, err
		}
		if err := os.WriteFile(target, data, 0644); err != nil {
			return ManifestMetadata{}, err
		}
	}
	if metadata.Name == "" {
		manifestData, err := os.ReadFile(filepath.Join(destination, ManifestFile))
		if err == nil {
			name, version := parseManifestIdentity(string(manifestData))
			metadata.Name = name
			metadata.Version = version
		}
	}
	return metadata, nil
}

func shouldSkip(rel string, entry fs.DirEntry) bool {
	base := filepath.Base(rel)
	if rel == MetadataFile {
		return true
	}
	switch base {
	case ".git", ".adversary", "node_modules":
		return true
	}
	return false
}

func parseManifestIdentity(text string) (string, string) {
	var name string
	var version string
	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) != raw {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"`)
		value = strings.Trim(value, `'`)
		switch strings.TrimSpace(key) {
		case "name":
			name = value
		case "version":
			version = value
		}
	}
	return name, version
}
