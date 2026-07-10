package adversary

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	destination := filepath.Join(c.Root, "artifacts", digestPath)
	metadata, err := ExtractLayer(layer, destination)
	if err != nil {
		return InstallRecord{}, err
	}
	if len(artifact.AdversaryManifest) > 0 {
		if metadata.Name != "" && (metadata.Name != pulledManifest.Name || metadata.Version != pulledManifest.Version) {
			return InstallRecord{}, fmt.Errorf("pulled adversary.yaml identity %s@%s does not match package metadata %s@%s", pulledManifest.Name, pulledManifest.Version, metadata.Name, metadata.Version)
		}
		if err := os.WriteFile(filepath.Join(destination, ManifestFile), artifact.AdversaryManifest, 0644); err != nil {
			return InstallRecord{}, err
		}
		metadata.Name, metadata.Version = pulledManifest.Name, pulledManifest.Version
	}
	if metadata.Name == "" {
		return InstallRecord{}, fmt.Errorf("%s is required", ManifestFile)
	}
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

func (c Cache) Resolve(name string) (InstallRecord, bool) {
	data, err := readCacheRecord(c.Root, "index", name)
	if err != nil {
		return InstallRecord{}, false
	}
	var record InstallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return InstallRecord{}, false
	}
	return record, c.validRecord(record)
}

func (c Cache) ResolveDigest(digest string) (InstallRecord, bool) {
	if _, err := oci.ParseDigest(digest); err != nil {
		return InstallRecord{}, false
	}
	data, err := readCacheRecord(c.Root, "digests", digest)
	if err != nil {
		return InstallRecord{}, false
	}
	var record InstallRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return InstallRecord{}, false
	}
	return record, c.validRecord(record)
}

func (c Cache) writeRecord(record InstallRecord) error {
	indexDir := filepath.Join(c.Root, "index")
	if err := os.MkdirAll(indexDir, 0755); err != nil {
		return err
	}
	digestsDir := filepath.Join(c.Root, "digests")
	if err := os.MkdirAll(digestsDir, 0755); err != nil {
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
		if err := os.WriteFile(filepath.Join(digestsDir, cacheKey(record.ManifestDigest)+".json"), data, 0644); err != nil {
			return err
		}
	}
	keys := []string{record.Name}
	if record.Reference != "" {
		keys = append(keys, referenceAliases(record.Reference)...)
	}
	for _, key := range keys {
		if err := os.WriteFile(filepath.Join(indexDir, cacheKey(key)+".json"), data, 0644); err != nil {
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

func readCacheRecord(root, kind, key string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(root, kind, cacheKey(key)+".json"))
	if err == nil || !os.IsNotExist(err) {
		return data, err
	}
	// Compatibility: read pre-v2 lossy keys, but all new writes use v2 keys.
	return os.ReadFile(filepath.Join(root, kind, sanitize(key)+".json"))
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
	return err == nil && actual == expected && !strings.ContainsRune(record.Path, '\x00')
}
