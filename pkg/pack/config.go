package pack

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/oci"
)

// ArtifactConfig is the strict, immutable metadata contract carried by an
// Adversary OCI artifact config blob.
type ArtifactConfig struct {
	Created        string   `json:"created"`
	Name           string   `json:"name"`
	FullName       string   `json:"full_name"`
	Version        string   `json:"version"`
	Runtime        string   `json:"runtime"`
	RuntimeName    string   `json:"runtime_name,omitempty"`
	RuntimeVersion string   `json:"runtime_version,omitempty"`
	RuntimeImage   string   `json:"runtime_image,omitempty"`
	Entrypoint     []string `json:"entrypoint,omitempty"`
	Files          []File   `json:"files"`
}

// DecodeArtifactConfig rejects unknown, duplicate, trailing, and malformed
// fields before returning typed metadata.
func DecodeArtifactConfig(data []byte) (ArtifactConfig, error) {
	if err := rejectDuplicateJSONFields(data); err != nil {
		return ArtifactConfig{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var config ArtifactConfig
	if err := dec.Decode(&config); err != nil {
		return ArtifactConfig{}, fmt.Errorf("decode artifact config: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return ArtifactConfig{}, err
	}
	if config.Files == nil {
		return ArtifactConfig{}, errors.New("artifact config does not contain a file inventory")
	}
	if err := ValidateFileInventory(config.Files); err != nil {
		return ArtifactConfig{}, err
	}
	return config, nil
}

// ValidateFileInventory enforces the canonical package-layer inventory form.
func ValidateFileInventory(files []File) error {
	for i, file := range files {
		clean := path.Clean(file.Path)
		if file.Path == "" || clean != file.Path || clean == "." || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "\\") || strings.HasPrefix(file.Path, "../") {
			return fmt.Errorf("invalid inventory path %q", file.Path)
		}
		if file.Size < 0 || (file.Mode != 0o644 && file.Mode != 0o755) {
			return fmt.Errorf("invalid inventory metadata for %q", file.Path)
		}
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != 32 || file.SHA256 != strings.ToLower(file.SHA256) {
			return fmt.Errorf("invalid inventory digest for %q", file.Path)
		}
		if i > 0 && files[i-1].Path >= file.Path {
			return errors.New("inventory is not uniquely sorted")
		}
	}
	if !sort.SliceIsSorted(files, func(i, j int) bool { return files[i].Path < files[j].Path }) {
		return errors.New("inventory is not sorted")
	}
	return nil
}

// ValidateArtifactMetadata cross-checks config, OCI annotations, and the
// canonical attached adversary manifest. files must be the validated layer
// inventory when runtime classification and entrypoint presence are checked.
func ValidateArtifactMetadata(config ArtifactConfig, annotations map[string]string, canonical manifest.Manifest, files []File) error {
	version := canonical.Version
	if version == "" {
		version = oci.DefaultTag
	}
	expectedRuntimeName := runtimeName(canonical)
	requiredAnnotations := []string{
		"org.opencontainers.image.title", "org.opencontainers.image.version",
		"ai.adversary.name", "ai.adversary.full_name", "ai.adversary.version", "ai.adversary.runtime",
		"ai.adversary.runtime.name", "ai.adversary.runtime.version", "ai.adversary.runtime.image",
	}
	for _, name := range requiredAnnotations {
		if _, present := annotations[name]; !present {
			return fmt.Errorf("required OCI annotation %q is missing", name)
		}
	}
	checks := []struct{ label, got, want string }{
		{"config creation timestamp", config.Created, "1970-01-01T00:00:00Z"},
		{"config full name", config.FullName, canonical.Name},
		{"config version", config.Version, version},
		{"config runtime name", config.RuntimeName, expectedRuntimeName},
		{"config runtime version", config.RuntimeVersion, canonical.Runtime.Version},
		{"config runtime image", config.RuntimeImage, canonical.Runtime.Image},
		{"annotation name", annotations["ai.adversary.name"], config.Name},
		{"annotation full name", annotations["ai.adversary.full_name"], config.FullName},
		{"annotation version", annotations["ai.adversary.version"], config.Version},
		{"annotation runtime", annotations["ai.adversary.runtime"], config.Runtime},
		{"annotation runtime name", annotations["ai.adversary.runtime.name"], config.RuntimeName},
		{"annotation runtime version", annotations["ai.adversary.runtime.version"], config.RuntimeVersion},
		{"annotation runtime image", annotations["ai.adversary.runtime.image"], config.RuntimeImage},
		{"OCI title annotation", annotations["org.opencontainers.image.title"], config.Name},
		{"OCI version annotation", annotations["org.opencontainers.image.version"], config.Version},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf("%s conflicts: got %q, want %q", check.label, check.got, check.want)
		}
	}
	if config.Name == "" || config.FullName == "" || config.Version == "" {
		return errors.New("artifact config identity fields must not be empty")
	}
	if !reflect.DeepEqual(config.Entrypoint, canonical.Runtime.Command) {
		return fmt.Errorf("config entrypoint conflicts with attached manifest")
	}
	wantRuntime := "custom"
	if expectedRuntimeName == "node" || inventoryContains(files, "package.json") {
		wantRuntime = "typescript"
	}
	if config.Runtime != wantRuntime {
		return fmt.Errorf("config runtime conflicts: got %q, want %q", config.Runtime, wantRuntime)
	}
	entrypoint, required, err := checkedPackageEntrypoint(canonical)
	if err != nil {
		return err
	}
	if required && !inventoryContains(files, entrypoint) {
		return fmt.Errorf("runtime entrypoint %q is missing from package-layer inventory", entrypoint)
	}
	return nil
}

func inventoryContains(files []File, name string) bool {
	i := sort.Search(len(files), func(i int) bool { return files[i].Path >= name })
	return i < len(files) && files[i].Path == name
}

func rejectDuplicateJSONFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanJSONValue(dec, "$"); err != nil {
		return fmt.Errorf("decode artifact config: %w", err)
	}
	return requireJSONEOF(dec)
}

func scanJSONValue(dec *json.Decoder, location string) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate field %q at %s", key, location)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec, location+"."+key); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := scanJSONValue(dec, fmt.Sprintf("%s[%d]", location, i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	_, err = dec.Token()
	return err
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("artifact config contains trailing JSON value")
		}
		return fmt.Errorf("decode artifact config: %w", err)
	}
	return nil
}
