// Package manifest owns the canonical adversary manifest representation and parser.
package manifest

import (
	"bytes"
	_ "crypto/sha512" // register maintained OCI SHA-384 and SHA-512 digests
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	semver "github.com/Masterminds/semver/v3"
	distref "github.com/distribution/reference"
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
	nameRE           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?:/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)*$`)
	versionRE        = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	envRE            = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	imageComponentRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	imageTagRE       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	imageDigestRE    = regexp.MustCompile(`^(?:sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})$`)
	registryHostRE   = regexp.MustCompile(`^(?:localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)(?::[0-9]{1,5})?$`)
)

const runtimeImageRepositoryMax = 255 // distribution/reference.RepositoryNameTotalLengthMax

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
	if out.Runtime.Image != "" {
		canonicalImage, err := canonicalRuntimeImage(out.Runtime.Image)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest runtime.image: canonicalize reference: %w", err)
		}
		out.Runtime.Image = canonicalImage
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
	hasName, hasImage := m.Runtime.Name != "", m.Runtime.Image != ""
	if hasName == hasImage {
		return errors.New("manifest runtime must specify exactly one execution identity: runtime.name or runtime.image")
	}
	if hasImage {
		if err := validateRuntimeImage(m.Runtime.Image); err != nil {
			return fmt.Errorf("manifest runtime.image: %w", err)
		}
		if _, err := canonicalRuntimeImage(m.Runtime.Image); err != nil {
			return fmt.Errorf("manifest runtime.image: canonicalize reference: %w", err)
		}
		if m.Runtime.Version != "" {
			return errors.New("manifest runtime.version is only valid with runtime.name; image commands execute inside the image")
		}
	}
	if m.Runtime.Name != "" && m.Runtime.Name != "node" && m.Runtime.Name != "process" {
		return fmt.Errorf("manifest runtime.name %q is unsupported (supported: node, process)", m.Runtime.Name)
	}
	if hasName && m.Runtime.Version == "" {
		return errors.New("manifest runtime.version is required for named runtimes")
	}
	if m.Runtime.Version != "" {
		if !normalizedNonEmpty(m.Runtime.Version) {
			return errors.New("manifest runtime.version must be non-empty and normalized")
		}
		if _, err := RuntimeConstraint(m.Runtime.Version); err != nil {
			return fmt.Errorf("manifest runtime.version %q is not a semantic-version constraint: %w", m.Runtime.Version, err)
		}
	}
	if len(m.Runtime.Command) == 0 {
		return errors.New("manifest runtime.command must not be empty")
	}
	for i, arg := range m.Runtime.Command {
		if !normalizedNonEmpty(arg) {
			return fmt.Errorf("manifest runtime.command[%d] must be non-empty", i)
		}
	}
	if m.Runtime.Name == "node" {
		if err := validateNodeEntrypoint(m.Runtime.Command[0]); err != nil {
			return fmt.Errorf("manifest runtime.command[0]: %w", err)
		}
	}
	for i, glob := range m.Triggers.FilesChanged {
		if !normalizedNonEmpty(glob) {
			return fmt.Errorf("manifest triggers.files_changed[%d] must be non-empty", i)
		}
	}
	permissionOwners := map[string]string{}
	for _, group := range []struct {
		kind  string
		paths []string
	}{{"read", m.Permissions.Filesystem.Read}, {"write", m.Permissions.Filesystem.Write}} {
		kind, paths := group.kind, group.paths
		for i, path := range paths {
			if err := validatePermissionPath(path); err != nil {
				return fmt.Errorf("manifest permissions.filesystem.%s[%d]: %w", kind, i, err)
			}
			clean := filepath.ToSlash(filepath.Clean(path))
			if owner, exists := permissionOwners[clean]; exists {
				return fmt.Errorf("manifest permissions.filesystem.%s[%d] duplicates/conflicts with %s permission %q", kind, i, owner, clean)
			}
			permissionOwners[clean] = kind
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

// validateRuntimeImage validates stable distribution-reference syntax without
// applying registry defaults or consulting process environment. Familiar names
// such as "node:22" are valid here; Parse canonicalizes them with fixed defaults.
func validateRuntimeImage(value string) error {
	if !normalizedNonEmpty(value) || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return errors.New("must be a non-empty reference without whitespace")
	}
	if strings.Contains(value, "://") || strings.Contains(value, "\\") || strings.Contains(value, "?") || strings.Contains(value, "#") {
		return errors.New("must be an OCI image reference, not a URL")
	}
	if strings.Count(value, "@") > 1 {
		return errors.New("has repeated digest separators")
	}
	nameTag, digest, hasDigest := strings.Cut(value, "@")
	if hasDigest && !imageDigestRE.MatchString(digest) {
		return errors.New("has a malformed digest")
	}
	if nameTag == "" {
		return errors.New("is missing an image name")
	}

	name := nameTag
	lastSlash, lastColon := strings.LastIndex(nameTag, "/"), strings.LastIndex(nameTag, ":")
	if lastColon > lastSlash {
		name = nameTag[:lastColon]
		if !imageTagRE.MatchString(nameTag[lastColon+1:]) {
			return errors.New("has a malformed tag")
		}
	}
	if strings.Contains(name, "@") || strings.Contains(name, "//") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return errors.New("has a malformed repository name")
	}
	parts := strings.Split(name, "/")
	start := 0
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" || strings.HasPrefix(parts[0], "[")) {
		if err := validateRegistryHost(parts[0]); err != nil {
			return err
		}
		start = 1
	}
	for _, part := range parts[start:] {
		if !imageComponentRE.MatchString(part) {
			return errors.New("repository components must be normalized lowercase names")
		}
	}
	// The distribution reference library applies its 255-byte bound only to
	// the repository path; the registry host, tag, and digest are excluded.
	// canonicalRuntimeImage below rechecks after familiar-name normalization
	// (including an injected "library/" namespace where applicable).
	if len(strings.Join(parts[start:], "/")) > runtimeImageRepositoryMax {
		return fmt.Errorf("repository path must not exceed %d bytes", runtimeImageRepositoryMax)
	}
	return nil
}

// canonicalRuntimeImage applies distribution/reference's fixed Docker Hub
// familiar-name normalization. It deliberately does not consult Adversary's
// configurable registry host. Non-digested references always carry a tag.
func canonicalRuntimeImage(value string) (string, error) {
	named, err := distref.ParseNormalizedNamed(value)
	if err != nil {
		return "", err
	}
	if _, digested := named.(distref.Digested); !digested {
		named = distref.TagNameOnly(named)
	}
	return named.String(), nil
}

func validateRegistryHost(host string) error {
	port := ""
	hasPort := false
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		if end < 0 || net.ParseIP(host[1:end]) == nil || !strings.Contains(host[1:end], ":") {
			return errors.New("has a malformed registry IPv6 host")
		}
		suffix := host[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return errors.New("has a malformed registry IPv6 host")
			}
			port = strings.TrimPrefix(suffix, ":")
			hasPort = true
		}
	} else {
		if !registryHostRE.MatchString(host) {
			return errors.New("has a malformed registry host")
		}
		if colon := strings.LastIndex(host, ":"); colon >= 0 {
			port = host[colon+1:]
			hasPort = true
		}
	}
	if hasPort {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return errors.New("registry port must be between 1 and 65535")
		}
	}
	return nil
}

// RuntimeConstraint parses the manifest's maintained semantic-version constraint
// syntax. A bare major/minor is intentionally shorthand for that release line.
func RuntimeConstraint(requirement string) (*semver.Constraints, error) {
	v := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(requirement), "node@"), "v")
	parts := strings.Split(v, ".")
	if len(parts) <= 2 && strings.IndexAny(v, "<>=~^*xX ,|") < 0 {
		for _, part := range parts {
			if part == "" || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, fmt.Errorf("invalid bare version %q", requirement)
			}
		}
		if len(parts) == 1 {
			n, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil || n == ^uint64(0) {
				return nil, fmt.Errorf("invalid bare version %q", requirement)
			}
			v = fmt.Sprintf(">=%s.0.0, <%d.0.0", v, n+1)
		} else {
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil || n == ^uint64(0) {
				return nil, fmt.Errorf("invalid bare version %q", requirement)
			}
			v = fmt.Sprintf(">=%s.0, <%s.%d.0", v, parts[0], n+1)
		}
	}
	return semver.NewConstraint(v)
}

func validatePermissionPath(path string) error {
	if !normalizedNonEmpty(path) {
		return errors.New("must be a non-empty normalized path")
	}
	if filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) || strings.Contains(path, ":") {
		return errors.New("must be relative to the project root")
	}
	if strings.Contains(path, `\`) {
		return errors.New("must use portable forward-slash separators")
	}
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("must remain within the project root")
	}
	if clean != path && filepath.ToSlash(clean) != path {
		return errors.New("must be lexically normalized")
	}
	return nil
}

func validateNodeEntrypoint(entrypoint string) error {
	if filepath.IsAbs(entrypoint) || filepath.VolumeName(entrypoint) != "" || strings.HasPrefix(entrypoint, "/") || strings.HasPrefix(entrypoint, `\`) || (len(entrypoint) >= 2 && entrypoint[1] == ':') {
		return errors.New("Node entry point must be relative to the project root")
	}
	if strings.Contains(entrypoint, `\`) {
		return errors.New("Node entry point must use portable forward-slash separators")
	}
	clean := filepath.Clean(entrypoint)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("Node entry point must remain within the project root")
	}
	if clean != entrypoint {
		return errors.New("Node entry point must be lexically normalized")
	}
	if !(strings.HasSuffix(entrypoint, ".js") || strings.HasSuffix(entrypoint, ".mjs") || strings.HasSuffix(entrypoint, ".cjs")) {
		return errors.New("must be a JavaScript entry point for runtime.name node")
	}
	return nil
}

// ValidateProject checks runtime declarations against the project contract
// without guessing a runtime from files present in the directory.
func (m Manifest) ValidateProject(root string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Runtime.Image != "" {
		return nil
	}
	if m.Runtime.Name == "node" {
		if _, err := os.Stat(filepath.Join(root, "package.json")); err != nil {
			return fmt.Errorf("node runtime requires package.json: %w", err)
		}
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
	if len(name) > 214 {
		return fmt.Errorf("project name %q exceeds npm's 214-byte package name limit", name)
	}
	if npmReservedProjectNames[name] {
		return fmt.Errorf("project name %q is reserved by npm or Node.js", name)
	}
	return nil
}

// npmReservedProjectNames is the intersection of the existing unscoped
// project-name grammar and npm/validate-npm-package-name v8's exclusion and
// builtin-module lists. Names containing slash, colon, or a leading underscore
// are already rejected by the stricter project-name grammar above.
var npmReservedProjectNames = map[string]bool{
	"assert": true, "async_hooks": true, "buffer": true, "child_process": true,
	"cluster": true, "console": true, "constants": true, "crypto": true,
	"dgram": true, "diagnostics_channel": true, "dns": true, "domain": true,
	"events": true, "favicon.ico": true, "fs": true, "http": true,
	"http2": true, "https": true, "inspector": true, "module": true,
	"net": true, "node_modules": true, "os": true, "path": true,
	"perf_hooks": true, "process": true, "punycode": true, "querystring": true,
	"readline": true, "repl": true, "stream": true, "string_decoder": true,
	"sys": true, "timers": true, "tls": true, "trace_events": true,
	"tty": true, "url": true, "util": true, "v8": true, "vm": true,
	"wasi": true, "worker_threads": true, "zlib": true,
}

func ShortName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), "/")
	return filepath.Base(name)
}
