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
	"slices"
	"strings"

	"github.com/adversarylabs/adversary/internal/archiveutil"
	"github.com/adversarylabs/adversary/internal/publock"
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
	if artifact.Manifest.SchemaVersion != 2 || artifact.Manifest.ArtifactType != oci.ArtifactMediaType || artifact.Manifest.Config.MediaType != oci.EmptyConfigMediaType || len(artifact.Manifest.Layers) != 1 || artifact.Manifest.Layers[0].MediaType != oci.PackageLayerMediaType {
		return InstallRecord{}, fmt.Errorf("unsupported adversary artifact layout")
	}
	var config struct {
		Name           string   `json:"name"`
		FullName       string   `json:"full_name"`
		Version        string   `json:"version"`
		Runtime        string   `json:"runtime"`
		RuntimeName    string   `json:"runtime_name"`
		RuntimeVersion string   `json:"runtime_version"`
		RuntimeImage   string   `json:"runtime_image"`
		Entrypoint     []string `json:"entrypoint"`
		Files          []struct {
			Path   string `json:"path"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
			Mode   int64  `json:"mode"`
		} `json:"files"`
	}
	if configData, ok := artifact.Blobs[artifact.Manifest.Config.Digest]; ok {
		if err := oci.VerifyDigest(configData, artifact.Manifest.Config.Digest); err != nil {
			return InstallRecord{}, fmt.Errorf("config: %w", err)
		}
		if err := json.Unmarshal(configData, &config); err != nil {
			return InstallRecord{}, fmt.Errorf("config: %w", err)
		}
		for key, want := range map[string]string{"ai.adversary.name": config.Name, "ai.adversary.full_name": config.FullName, "ai.adversary.version": config.Version, "ai.adversary.runtime": config.Runtime, "ai.adversary.runtime.name": config.RuntimeName, "ai.adversary.runtime.version": config.RuntimeVersion, "ai.adversary.runtime.image": config.RuntimeImage} {
			if artifact.Manifest.Annotations[key] != want {
				return InstallRecord{}, fmt.Errorf("manifest annotation %s conflicts with config", key)
			}
		}
	} else {
		return InstallRecord{}, fmt.Errorf("artifact config blob is missing")
	}
	if err := oci.VerifyDigest(artifact.Blobs[artifact.Manifest.Layers[0].Digest], artifact.Manifest.Layers[0].Digest); err != nil {
		return InstallRecord{}, fmt.Errorf("layer: %w", err)
	}
	if artifact.ManifestDigest == "" {
		return InstallRecord{}, fmt.Errorf("manifest digest is required")
	}
	var pulledManifest *canonical.Manifest
	if len(artifact.AdversaryManifest) > 0 {
		parsed, err := canonical.Parse(artifact.AdversaryManifest)
		if err != nil {
			return InstallRecord{}, fmt.Errorf("parse pulled adversary.yaml: %w", err)
		}
		pulledManifest = &parsed
	}
	layer := artifact.Blobs[artifact.Manifest.Layers[0].Digest]
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
	publicationLock, err := publock.Acquire(c.Root, artifact.ManifestDigest)
	if err != nil {
		return InstallRecord{}, err
	}
	defer publicationLock.Close()
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
	defer func() {
		if staged, e := rooted.OpenRoot(stageRel); e == nil {
			_ = archiveutil.Unseal(staged)
			_ = staged.Close()
		}
		_ = rooted.RemoveAll(stageRel)
	}()
	stage, err := rooted.OpenRoot(stageRel)
	if err != nil {
		return InstallRecord{}, err
	}
	stageClosed := false
	defer func() {
		if !stageClosed {
			_ = stage.Close()
		}
	}()
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
	installedManifestData, err := stage.ReadFile(ManifestFile)
	if err != nil {
		return InstallRecord{}, err
	}
	installedManifest, err := canonical.Parse(installedManifestData)
	if err != nil {
		return InstallRecord{}, err
	}
	pulledManifest = &installedManifest
	if config.Name == "" || config.FullName == "" || config.Version == "" || config.Runtime == "" || config.Entrypoint == nil || (config.RuntimeImage == "" && (config.RuntimeName == "" || config.RuntimeVersion == "")) {
		return InstallRecord{}, fmt.Errorf("config identity and runtime fields are required")
	}
	if config.FullName != pulledManifest.Name || (pulledManifest.Version != "" && config.Version != pulledManifest.Version) {
		return InstallRecord{}, fmt.Errorf("config identity conflicts with adversary.yaml")
	}
	if config.RuntimeImage != pulledManifest.Runtime.Image || (pulledManifest.Runtime.Image == "" && (config.RuntimeName != pulledManifest.Runtime.Name || config.RuntimeVersion != pulledManifest.Runtime.Version)) || (pulledManifest.Runtime.Image != "" && ((config.RuntimeName != "" && config.RuntimeName != pulledManifest.Runtime.Name) || (config.RuntimeVersion != "" && config.RuntimeVersion != pulledManifest.Runtime.Version))) || !slices.Equal(config.Entrypoint, pulledManifest.Runtime.Command) {
		return InstallRecord{}, fmt.Errorf("config runtime conflicts with adversary.yaml")
	}
	if config.Files == nil {
		return InstallRecord{}, fmt.Errorf("config files metadata is required")
	}
	{
		actual, err := snapshotFiles(stage)
		if err != nil {
			return InstallRecord{}, err
		}
		allowed := map[string]bool{ManifestFile: true, MetadataFile: true}
		for _, file := range config.Files {
			if allowed[file.Path] {
				return InstallRecord{}, fmt.Errorf("duplicate or reserved config file path %q", file.Path)
			}
			allowed[file.Path] = true
			got, ok := actual[file.Path]
			if !ok || got.size != file.Size || got.mode != os.FileMode(file.Mode)&0111 || fmt.Sprintf("%x", got.digest) != file.SHA256 {
				return InstallRecord{}, fmt.Errorf("config file metadata mismatch for %q", file.Path)
			}
		}
		for path := range actual {
			if !allowed[path] {
				return InstallRecord{}, fmt.Errorf("file %q is not declared by config", path)
			}
		}
	}
	expectedFiles, err := snapshotFiles(stage)
	if err != nil {
		return InstallRecord{}, err
	}
	if err := archiveutil.PreparePublish(stage); err != nil {
		return InstallRecord{}, err
	}
	if err := archiveutil.ValidatePrepared(stage); err != nil {
		return InstallRecord{}, err
	}
	if err := stage.Close(); err != nil {
		return InstallRecord{}, err
	}
	stageClosed = true
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
		didPublish, publishErr := archiveutil.PublishSealed(c.Root, rooted, stageRel, destRel)
		if publishErr != nil {
			if didPublish {
				cleanupPublished(rooted, destRel)
				return InstallRecord{}, publishErr
			}
			if validateErr := validateInstalledArtifact(rooted, destRel, metadata, artifact.AdversaryManifest, expectedFiles); validateErr != nil {
				return InstallRecord{}, fmt.Errorf("publish artifact: %w", publishErr)
			}
		} else {
			published = true
		}
	}
	if published {
		if err := validateInstalledArtifact(rooted, destRel, metadata, artifact.AdversaryManifest, expectedFiles); err != nil {
			if doomed, openErr := rooted.OpenRoot(destRel); openErr == nil {
				_ = archiveutil.Unseal(doomed)
				_ = doomed.Close()
			}
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

func cleanupPublished(rooted *os.Root, rel string) {
	if doomed, e := rooted.OpenRoot(rel); e == nil {
		_ = archiveutil.Unseal(doomed)
		_ = doomed.Close()
	}
	_ = rooted.RemoveAll(rel)
}

var beforeCacheInstallPublish func(*os.Root, string)

type installedFile struct {
	size   int64
	digest [sha256.Size]byte
	mode   os.FileMode
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
		files[path] = installedFile{size: int64(len(data)), digest: sha256.Sum256(data), mode: info.Mode().Perm() & 0111}
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
	if err := archiveutil.ValidateSealed(sub); err != nil {
		return err
	}
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
	lock, err := publock.Acquire(c.Root, record.ManifestDigest)
	if err != nil {
		return InstallRecord{}, false
	}
	defer lock.Close()
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
	lock, err := publock.Acquire(c.Root, digest)
	if err != nil {
		return InstallRecord{}, false
	}
	defer lock.Close()
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
