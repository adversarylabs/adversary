// Package manifest owns the canonical adversary manifest representation and parser.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const (
	FileName = "adversary.yaml"
	MaxSize  = 1 << 20
)

type Manifest struct {
	Name        string      `yaml:"name" json:"name"`
	Version     string      `yaml:"version" json:"version"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Triggers    Triggers    `yaml:"triggers,omitempty" json:"triggers,omitempty"`
	Runtime     Runtime     `yaml:"runtime" json:"runtime"`
	Permissions Permissions `yaml:"permissions,omitempty" json:"permissions,omitempty"`
	Findings    Findings    `yaml:"findings,omitempty" json:"findings,omitempty"`
}

type Triggers struct {
	Manual       bool     `yaml:"manual,omitempty" json:"manual,omitempty"`
	FilesChanged []string `yaml:"files_changed,omitempty" json:"files_changed,omitempty"`
}

type Runtime struct {
	Name    string   `yaml:"name" json:"name"`
	Image   string   `yaml:"image,omitempty" json:"image,omitempty"`
	Version string   `yaml:"version" json:"version"`
	Command []string `yaml:"command" json:"command"`
}

type Permissions struct {
	Filesystem FilesystemPermissions `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	Network    *bool                 `yaml:"network,omitempty" json:"network,omitempty"`
	Env        []string              `yaml:"env,omitempty" json:"env,omitempty"`
}

type FilesystemPermissions struct {
	Read  []string `yaml:"read,omitempty" json:"read,omitempty"`
	Write []string `yaml:"write,omitempty" json:"write,omitempty"`
}

type Findings struct {
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
}

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?:/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)*$`)
	versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	envRE     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func Load(path string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return Manifest{}, err
	}
	if len(data) > MaxSize {
		return Manifest{}, fmt.Errorf("adversary.yaml is too large: %d bytes exceeds %d bytes", len(data), MaxSize)
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	if len(data) > MaxSize {
		return Manifest{}, fmt.Errorf("adversary.yaml is too large: %d bytes exceeds %d bytes", len(data), MaxSize)
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return Manifest{}, errors.New("manifest is empty")
	}
	if err := safeNode(doc.Content[0], "manifest"); err != nil {
		return Manifest{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("manifest must contain one YAML document")
		}
		return Manifest{}, fmt.Errorf("decode manifest YAML: %w", err)
	}
	var out Manifest
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&out); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest YAML: %w", err)
	}
	if err := validatePresentFields(doc.Content[0], out); err != nil {
		return Manifest{}, err
	}
	if err := out.Validate(); err != nil {
		return Manifest{}, err
	}
	return out, nil
}

func validatePresentFields(root *yaml.Node, m Manifest) error {
	if hasField(root, "version") && m.Version == "" {
		return errors.New("manifest version must not be empty when present")
	}
	runtime := fieldNode(root, "runtime")
	if runtime != nil {
		if hasField(runtime, "name") && m.Runtime.Name == "" {
			return errors.New("manifest runtime.name must not be empty when present")
		}
		if hasField(runtime, "image") && m.Runtime.Image == "" {
			return errors.New("manifest runtime.image must not be empty when present")
		}
		if hasField(runtime, "version") && m.Runtime.Version == "" {
			return errors.New("manifest runtime.version must not be empty when present")
		}
	}
	findings := fieldNode(root, "findings")
	if findings != nil && hasField(findings, "format") && m.Findings.Format == "" {
		return errors.New("manifest findings.format must not be empty when present")
	}
	return nil
}

func fieldNode(mapping *yaml.Node, name string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func hasField(mapping *yaml.Node, name string) bool { return fieldNode(mapping, name) != nil }

func safeNode(n *yaml.Node, path string) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%s: YAML aliases and anchors are not allowed", path)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode {
				return fmt.Errorf("%s: mapping keys must be strings", path)
			}
			if seen[key.Value] {
				return fmt.Errorf("%s: duplicate field %q", path, key.Value)
			}
			seen[key.Value] = true
			if err := safeNode(n.Content[i+1], path+"."+key.Value); err != nil {
				return err
			}
		}
	} else {
		for _, child := range n.Content {
			if err := safeNode(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m Manifest) Validate() error {
	if !nameRE.MatchString(m.Name) {
		return fmt.Errorf("manifest name %q must be a normalized lowercase slash-separated name", m.Name)
	}
	if m.Version != "" && !versionRE.MatchString(m.Version) {
		return fmt.Errorf("manifest version %q must be semantic version x.y.z", m.Version)
	}
	if m.Runtime.Image != "" {
		if strings.ContainsRune(m.Runtime.Image, 0) || strings.IndexFunc(m.Runtime.Image, unicode.IsSpace) >= 0 {
			return errors.New("manifest runtime.image must be a normalized image reference")
		}
	}
	if m.Runtime.Name != "" && m.Runtime.Name != "node" && m.Runtime.Name != "process" {
		return fmt.Errorf("manifest runtime.name %q is unsupported (supported: node, process)", m.Runtime.Name)
	}
	if m.Runtime.Image == "" && m.Runtime.Name == "" {
		return errors.New("manifest runtime.name or runtime.image is required")
	}
	if m.Runtime.Image == "" && m.Runtime.Version == "" {
		return errors.New("manifest runtime.version is required for named runtimes")
	}
	if m.Runtime.Version != "" && !normalizedNonEmpty(m.Runtime.Version) {
		return errors.New("manifest runtime.version must be non-empty and normalized")
	}
	if len(m.Runtime.Command) == 0 {
		return errors.New("manifest runtime.command must not be empty")
	}
	for i, arg := range m.Runtime.Command {
		if !normalizedNonEmpty(arg) {
			return fmt.Errorf("manifest runtime.command[%d] must be non-empty", i)
		}
	}
	for i, glob := range m.Triggers.FilesChanged {
		if !normalizedNonEmpty(glob) {
			return fmt.Errorf("manifest triggers.files_changed[%d] must be non-empty", i)
		}
	}
	for kind, paths := range map[string][]string{"read": m.Permissions.Filesystem.Read, "write": m.Permissions.Filesystem.Write} {
		for i, path := range paths {
			if !normalizedNonEmpty(path) {
				return fmt.Errorf("manifest permissions.filesystem.%s[%d] must be a non-empty path", kind, i)
			}
		}
	}
	for i, env := range m.Permissions.Env {
		if !envRE.MatchString(env) {
			return fmt.Errorf("manifest permissions.env[%d] %q is not an environment variable name", i, env)
		}
	}
	if m.Findings.Format != "" && m.Findings.Format != "adversary.review.v1" {
		return fmt.Errorf("manifest findings.format %q is unsupported", m.Findings.Format)
	}
	return nil
}

func normalizedNonEmpty(value string) bool {
	return value != "" && !strings.ContainsRune(value, 0) && value == strings.TrimSpace(value)
}

func ValidateProjectName(name string) error {
	if !nameRE.MatchString(name) || strings.Contains(name, "/") {
		return fmt.Errorf("project name %q must be a normalized lowercase npm package name", name)
	}
	return nil
}

func ShortName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), "/")
	return filepath.Base(name)
}
