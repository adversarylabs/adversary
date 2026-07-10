package adversary

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
)

type Cache struct {
	Root string
}

type InstallRecord struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	Reference      string `json:"reference"`
	ManifestDigest string `json:"manifestDigest"`
	Path           string `json:"path"`
}

func DefaultCache() (Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Cache{}, err
	}
	return Cache{Root: filepath.Join(home, ".adversary", "cache")}, nil
}

func (c Cache) Install(artifact oci.PulledArtifact) (InstallRecord, error) {
	var pulledManifest *canonical.Manifest
	if len(artifact.AdversaryManifest) > 0 {
		parsed, err := canonical.Parse(artifact.AdversaryManifest)
		if err != nil {
			return InstallRecord{}, fmt.Errorf("parse pulled adversary.yaml: %w", err)
		}
		pulledManifest = &parsed
	}
	var layer []byte
	for _, descriptor := range artifact.Manifest.Layers {
		if descriptor.MediaType == oci.PackageLayerMediaType || layer == nil {
			layer = artifact.Blobs[descriptor.Digest]
		}
	}
	if len(layer) == 0 {
		return InstallRecord{}, fmt.Errorf("artifact has no package layer")
	}
	digestPath, err := oci.DigestPath(artifact.ManifestDigest)
	if err != nil {
		return InstallRecord{}, err
	}
	if err := os.MkdirAll(c.Root, 0755); err != nil {
		return InstallRecord{}, err
	}
	rooted, err := os.OpenRoot(c.Root)
	if err != nil {
		return InstallRecord{}, err
	}
	defer rooted.Close()
	if err := rooted.MkdirAll("artifacts", 0755); err != nil {
		return InstallRecord{}, err
	}
	destRel := filepath.ToSlash(filepath.Join("artifacts", digestPath))
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return InstallRecord{}, err
	}
	stageRel := fmt.Sprintf("artifacts/.staging-%x", nonce)
	if err := rooted.Mkdir(stageRel, 0700); err != nil {
		return InstallRecord{}, err
	}
	defer rooted.RemoveAll(stageRel)
	stage, err := rooted.OpenRoot(stageRel)
	if err != nil {
		return InstallRecord{}, err
	}
	defer stage.Close()
	metadata, err := ExtractLayerRoot(layer, stage)
	if err != nil {
		return InstallRecord{}, err
	}
	if len(artifact.AdversaryManifest) > 0 {
		if metadata.Name != "" && (metadata.Name != pulledManifest.Name || metadata.Version != pulledManifest.Version) {
			return InstallRecord{}, fmt.Errorf("pulled adversary.yaml identity %s@%s does not match package metadata %s@%s", pulledManifest.Name, pulledManifest.Version, metadata.Name, metadata.Version)
		}
		if err := stage.WriteFile(ManifestFile, artifact.AdversaryManifest, 0644); err != nil {
			return InstallRecord{}, err
		}
		metadata.Name, metadata.Version = pulledManifest.Name, pulledManifest.Version
	}
	if metadata.Name == "" {
		return InstallRecord{}, fmt.Errorf("%s is required", ManifestFile)
	}
	expectedFiles, err := snapshotFiles(stage)
	if err != nil {
		return InstallRecord{}, err
	}
	if err := rooted.MkdirAll(filepath.ToSlash(filepath.Dir(destRel)), 0755); err != nil {
		return InstallRecord{}, err
	}
	published := false
	if _, err := rooted.Lstat(destRel); err == nil {
		if err := validateInstalledArtifact(rooted, destRel, metadata, artifact.AdversaryManifest, expectedFiles); err != nil {
			return InstallRecord{}, fmt.Errorf("invalid existing artifact: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return InstallRecord{}, err
	} else {
		if beforeCacheInstallPublish != nil {
			beforeCacheInstallPublish(rooted, stageRel)
		}
		if err := rooted.Rename(stageRel, destRel); err != nil {
			if validateErr := validateInstalledArtifact(rooted, destRel, metadata, artifact.AdversaryManifest, expectedFiles); validateErr != nil {
				return InstallRecord{}, fmt.Errorf("publish artifact: %w", err)
			}
		} else {
			published = true
		}
	}
	if published {
		if err := validateInstalledArtifact(rooted, destRel, metadata, artifact.AdversaryManifest, expectedFiles); err != nil {
			_ = rooted.RemoveAll(destRel)
			return InstallRecord{}, fmt.Errorf("verify published artifact: %w", err)
		}
	}
	destination := filepath.Join(c.Root, filepath.FromSlash(destRel))
	record := InstallRecord{
		Name:           metadata.Name,
		Version:        metadata.Version,
		Reference:      artifact.Reference.Locator(),
		ManifestDigest: artifact.ManifestDigest,
		Path:           destination,
	}
	if err := c.writeRecord(record); err != nil {
		return InstallRecord{}, err
	}
	return record, nil
}

var beforeCacheInstallPublish func(*os.Root, string)

type installedFile struct {
	size   int64
	digest [sha256.Size]byte
}

func snapshotFiles(rooted *os.Root) (map[string]installedFile, error) {
	files := map[string]installedFile{}
	err := fs.WalkDir(rooted.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file %q", path)
		}
		data, err := rooted.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = installedFile{size: int64(len(data)), digest: sha256.Sum256(data)}
		return nil
	})
	return files, err
}

func validateInstalledArtifact(rooted *os.Root, rel string, metadata ManifestMetadata, expectedManifest []byte, expected map[string]installedFile) error {
	sub, err := rooted.OpenRoot(rel)
	if err != nil {
		return err
	}
	defer sub.Close()
	manifest, err := sub.ReadFile(ManifestFile)
	if err != nil {
		return err
	}
	parsed, err := canonical.Parse(manifest)
	if err != nil {
		return err
	}
	if parsed.Name != metadata.Name || parsed.Version != metadata.Version {
		return fmt.Errorf("manifest identity mismatch")
	}
	if len(expectedManifest) > 0 && !bytes.Equal(manifest, expectedManifest) {
		return fmt.Errorf("manifest content mismatch")
	}
	actual, err := snapshotFiles(sub)
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("installed file set mismatch")
	}
	for path, want := range expected {
		if got, ok := actual[path]; !ok || got != want {
			return fmt.Errorf("file mismatch %q", path)
		}
	}
	return nil
}

func (c Cache) Resolve(name string) (InstallRecord, bool) {
	data, err := c.readCacheRecord("index", name)
	if err != nil {
		return InstallRecord{}, false
	}
	var record InstallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return InstallRecord{}, false
	}
	matched := record.Name == name
	if !matched {
		for _, alias := range referenceAliases(record.Reference) {
			if alias == name {
				matched = true
				break
			}
		}
	}
	return record, matched && c.validRecord(record)
}

func (c Cache) ResolveDigest(digest string) (InstallRecord, bool) {
	if _, err := oci.ParseDigest(digest); err != nil {
		return InstallRecord{}, false
	}
	data, err := c.readCacheRecord("digests", digest)
	if err != nil {
		return InstallRecord{}, false
	}
	var record InstallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return InstallRecord{}, false
	}
	return record, record.ManifestDigest == digest && c.validRecord(record)
}

func (c Cache) writeRecord(record InstallRecord) error {
	if err := os.MkdirAll(c.Root, 0755); err != nil {
		return err
	}
	rooted, err := os.OpenRoot(c.Root)
	if err != nil {
		return err
	}
	defer rooted.Close()
	if err := rooted.MkdirAll("index", 0755); err != nil {
		return err
	}
	if err := rooted.MkdirAll("digests", 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if record.ManifestDigest != "" {
		if _, err := oci.ParseDigest(record.ManifestDigest); err != nil {
			return err
		}
		if err := rooted.WriteFile("digests/"+cacheKey(record.ManifestDigest)+".json", data, 0644); err != nil {
			return err
		}
	}
	keys := []string{record.Name}
	if record.Reference != "" {
		keys = append(keys, referenceAliases(record.Reference)...)
	}
	for _, key := range keys {
		if err := rooted.WriteFile("index/"+cacheKey(key)+".json", data, 0644); err != nil {
			return err
		}
	}
	return nil
}

func referenceAliases(reference string) []string {
	ref, err := oci.ParseReference(reference)
	if err != nil {
		return []string{reference}
	}
	aliases := []string{
		reference,
		ref.Locator(),
		ref.Name(),
		ref.Repository,
		ref.ShortName(),
	}
	if ref.Registry == oci.DefaultRegistry {
		if ref.Tag != "" && ref.Tag != oci.DefaultTag {
			aliases = append(aliases, ref.Repository+":"+ref.Tag)
		}
		if ref.Tag == oci.DefaultTag {
			aliases = append(aliases, ref.Repository)
		}
	}
	return uniqueStrings(aliases)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

// cacheKey hashes the exact UTF-8 bytes. Canonically equivalent Unicode strings
// intentionally remain distinct; reference and manifest parsers define identity.
func cacheKey(s string) string { return fmt.Sprintf("v2-%x", sha256.Sum256([]byte(s))) }

func (c Cache) readCacheRecord(kind, key string) ([]byte, error) {
	rooted, err := os.OpenRoot(c.Root)
	if err != nil {
		return nil, err
	}
	defer rooted.Close()
	data, err := rooted.ReadFile(kind + "/" + cacheKey(key) + ".json")
	if err == nil || !os.IsNotExist(err) {
		return data, err
	}
	// Compatibility: read pre-v2 lossy keys, but all new writes use v2 keys.
	return rooted.ReadFile(kind + "/" + sanitize(key) + ".json")
}

func (c Cache) validRecord(record InstallRecord) bool {
	d, err := oci.DigestPath(record.ManifestDigest)
	if err != nil {
		return false
	}
	expected, err := filepath.Abs(filepath.Join(c.Root, "artifacts", d))
	if err != nil {
		return false
	}
	actual, err := filepath.Abs(filepath.Clean(record.Path))
	if err != nil || actual != expected || strings.ContainsRune(record.Path, '\x00') {
		return false
	}
	rooted, err := os.OpenRoot(c.Root)
	if err != nil {
		return false
	}
	defer rooted.Close()
	info, err := rooted.Stat(filepath.ToSlash(filepath.Join("artifacts", d)))
	return err == nil && info.IsDir()
}
