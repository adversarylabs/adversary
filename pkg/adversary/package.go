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
	"time"

	"github.com/adversarylabs/adversary/internal/archiveutil"
	canonical "github.com/adversarylabs/adversary/pkg/manifest"
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
	Mode   int64  `json:"mode,omitempty"`
}

func PackageDirectory(dir string) (Package, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Package{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
		return Package{}, fmt.Errorf("%s is required: %w", ManifestFile, err)
	}

	metadata, layer, err := buildMetadataAndLayer(dir)
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

var beforePackageOpen func(string)

func buildMetadataAndLayer(dir string) (ManifestMetadata, []byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ManifestMetadata{}, nil, err
	}
	defer root.Close()
	manifestData, err := root.ReadFile(ManifestFile)
	if err != nil {
		return ManifestMetadata{}, nil, err
	}
	m, err := canonical.Parse(manifestData)
	if err != nil {
		return ManifestMetadata{}, nil, err
	}
	metadata := ManifestMetadata{Name: m.Name, Version: m.Version}
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return ManifestMetadata{}, nil, err
	}
	gz.Name = ""
	gz.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
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
		before, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("unsupported package file type: %s", rel)
		}
		if beforePackageOpen != nil {
			beforePackageOpen(rel)
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if !after.Mode().IsRegular() || !os.SameFile(before, after) {
			f.Close()
			return fmt.Errorf("package file changed while opening: %s", rel)
		}
		h := sha256.New()
		header := &tar.Header{Name: rel, Mode: int64(0644 | after.Mode().Perm()&0111), Size: after.Size(), ModTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			f.Close()
			return err
		}
		n, copyErr := io.CopyBuffer(io.MultiWriter(tw, h), f, make([]byte, 32<<10))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != after.Size() {
			return fmt.Errorf("package file changed while reading: %s", rel)
		}
		metadata.Files = append(metadata.Files, FileMetadata{Path: rel, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: int64(after.Mode().Perm() & 0111)})
		return nil
	})
	if err != nil {
		tw.Close()
		gz.Close()
		return ManifestMetadata{}, nil, err
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return ManifestMetadata{}, nil, err
	}
	header := &tar.Header{Name: MetadataFile, Mode: 0444, Size: int64(len(metadataData)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX}
	if err := tw.WriteHeader(header); err != nil {
		return ManifestMetadata{}, nil, err
	}
	if _, err := tw.Write(metadataData); err != nil {
		return ManifestMetadata{}, nil, err
	}
	if err := tw.Close(); err != nil {
		return ManifestMetadata{}, nil, err
	}
	if err := gz.Close(); err != nil {
		return ManifestMetadata{}, nil, err
	}
	return metadata, buf.Bytes(), nil
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
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported package file type: %s", rel)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, copyErr := io.CopyBuffer(h, f, make([]byte, 32<<10))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		files = append(files, FileMetadata{
			Path:   rel,
			Size:   info.Size(),
			SHA256: hex.EncodeToString(h.Sum(nil)), Mode: int64(info.Mode().Perm() & 0111),
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
	m, err := canonical.Parse(manifestData)
	if err != nil {
		return ManifestMetadata{}, fmt.Errorf("parse %s: %w", ManifestFile, err)
	}
	return ManifestMetadata{Name: m.Name, Version: m.Version, Files: files}, nil
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
	defer tw.Close()
	defer gz.Close()
	for _, file := range metadata.Files {
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, err
		}
		header := &tar.Header{
			Name:    file.Path,
			Mode:    0644 | file.Mode,
			Size:    file.Size,
			ModTime: time.Unix(0, 0).UTC(),
			Uid:     0,
			Gid:     0,
			Uname:   "",
			Gname:   "",
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(header); err != nil {
			f.Close()
			return nil, err
		}
		if _, err := io.CopyBuffer(tw, f, make([]byte, 32<<10)); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
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
	rooted, err := os.OpenRoot(destination)
	if err != nil {
		return ManifestMetadata{}, err
	}
	defer rooted.Close()
	return ExtractLayerRoot(layer, rooted)
}

func ExtractLayerRoot(layer []byte, rooted *os.Root) (ManifestMetadata, error) {
	if err := archiveutil.ExtractGzipTar(bytes.NewReader(layer), rooted, archiveutil.DefaultLimits); err != nil {
		return ManifestMetadata{}, err
	}
	var metadata ManifestMetadata
	if data, err := rooted.ReadFile(MetadataFile); err == nil {
		if err := json.Unmarshal(data, &metadata); err != nil {
			return ManifestMetadata{}, err
		}
	} else if !os.IsNotExist(err) {
		return ManifestMetadata{}, err
	}
	manifestData, err := rooted.ReadFile(ManifestFile)
	if err == nil {
		m, parseErr := canonical.Parse(manifestData)
		if parseErr != nil {
			return ManifestMetadata{}, fmt.Errorf("parse extracted %s: %w", ManifestFile, parseErr)
		}
		if metadata.Name != "" && (metadata.Name != m.Name || metadata.Version != m.Version) {
			return ManifestMetadata{}, fmt.Errorf("extracted manifest identity %s@%s does not match package metadata %s@%s", m.Name, m.Version, metadata.Name, metadata.Version)
		}
		metadata.Name, metadata.Version = m.Name, m.Version
	} else if !os.IsNotExist(err) {
		return ManifestMetadata{}, err
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
