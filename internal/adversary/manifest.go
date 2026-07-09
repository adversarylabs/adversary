package adversary

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	adversarycache "github.com/adversarylabs/adversary/pkg/adversary"
	localstore "github.com/adversarylabs/adversary/pkg/store"
)

type Manifest struct {
	Name        string      `yaml:"name"`
	Version     string      `yaml:"version"`
	Description string      `yaml:"description"`
	Triggers    Triggers    `yaml:"triggers"`
	Runtime     Runtime     `yaml:"runtime"`
	Permissions Permissions `yaml:"permissions"`
	Findings    Findings    `yaml:"findings"`
}

type Triggers struct {
	FilesChanged []string `yaml:"files_changed"`
}

type Runtime struct {
	Image   string   `yaml:"image"`
	Command []string `yaml:"command"`
}

type Permissions struct {
	Filesystem FilesystemPermissions `yaml:"filesystem"`
	Network    *bool                 `yaml:"network"`
	Env        []string              `yaml:"env"`
}

type FilesystemPermissions struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
}

type Findings struct {
	Format string `yaml:"format"`
}

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}

	manifest, err := parseManifest(data)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.Name == "" {
		return Manifest{}, fmt.Errorf("manifest name is required")
	}
	if manifest.Runtime.Image == "" {
		return Manifest{}, fmt.Errorf("manifest runtime.image is required")
	}
	return manifest, nil
}

func parseManifest(data []byte) (Manifest, error) {
	text := string(data)
	if strings.Contains(text, "\nruntime:\n  type:") || strings.Contains(text, "\nruntime:\r\n  type:") {
		return Manifest{}, fmt.Errorf("runtime.type is not supported in v1")
	}
	if strings.Contains(text, "\ninput:") || strings.HasPrefix(text, "input:") {
		return Manifest{}, fmt.Errorf("input.supports is not supported in v1")
	}

	var manifest Manifest
	var section string
	var subsection string
	var list string

	for _, raw := range strings.Split(text, "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}

		indent := leadingSpaces(raw)
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "- ") {
			value := parseYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")))
			switch list {
			case "triggers.files_changed":
				manifest.Triggers.FilesChanged = append(manifest.Triggers.FilesChanged, value)
			case "runtime.command":
				manifest.Runtime.Command = append(manifest.Runtime.Command, value)
			case "permissions.filesystem.read":
				manifest.Permissions.Filesystem.Read = append(manifest.Permissions.Filesystem.Read, value)
			case "permissions.filesystem.write":
				manifest.Permissions.Filesystem.Write = append(manifest.Permissions.Filesystem.Write, value)
			case "permissions.env":
				manifest.Permissions.Env = append(manifest.Permissions.Env, value)
			}
			continue
		}

		key, value, ok := splitYAMLKeyValue(trimmed)
		if !ok {
			return Manifest{}, fmt.Errorf("invalid manifest line: %s", raw)
		}

		if indent == 0 {
			section = key
			subsection = ""
			list = ""
			switch key {
			case "name":
				manifest.Name = parseYAMLScalar(value)
			case "version":
				manifest.Version = parseYAMLScalar(value)
			case "description":
				manifest.Description = parseYAMLScalar(value)
			case "triggers", "runtime", "permissions", "findings":
			default:
				return Manifest{}, fmt.Errorf("unsupported manifest field %q", key)
			}
			continue
		}

		switch section {
		case "triggers":
			if indent == 2 && key == "files_changed" {
				list = "triggers.files_changed"
			}
		case "runtime":
			if indent == 2 {
				switch key {
				case "image":
					manifest.Runtime.Image = parseYAMLScalar(value)
					list = ""
				case "command":
					list = "runtime.command"
				case "type":
					return Manifest{}, fmt.Errorf("runtime.type is not supported in v1")
				}
			}
		case "permissions":
			if indent == 2 {
				switch key {
				case "filesystem":
					subsection = "filesystem"
					list = ""
				case "network":
					network := parseYAMLScalar(value) == "true"
					manifest.Permissions.Network = &network
					list = ""
				case "env":
					list = "permissions.env"
				}
			} else if indent == 4 && subsection == "filesystem" {
				switch key {
				case "read":
					list = "permissions.filesystem.read"
				case "write":
					list = "permissions.filesystem.write"
				}
			}
		case "findings":
			if indent == 2 && key == "format" {
				manifest.Findings.Format = parseYAMLScalar(value)
			}
		}
	}

	return manifest, nil
}

func leadingSpaces(s string) int {
	count := 0
	for count < len(s) && s[count] == ' ' {
		count++
	}
	return count
}

func splitYAMLKeyValue(s string) (string, string, bool) {
	key, value, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

func parseYAMLScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func ResolveReference(ref string) (ResolvedAdversary, error) {
	manifestPath := filepath.Join(ref, "adversary.yaml")
	if info, err := os.Stat(manifestPath); err == nil && !info.IsDir() {
		buildContext, err := filepath.Abs(ref)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		manifest, err := LoadManifest(manifestPath)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		resolved := ResolvedAdversary{
			Name:          manifest.Name,
			Image:         "adversary-local-typescript",
			Command:       manifest.Runtime.Command,
			Manifest:      &manifest,
			NetworkOff:    manifest.Permissions.Network != nil && !*manifest.Permissions.Network,
			LocalDir:      true,
			BuildContext:  buildContext,
			ExecutionPath: buildContext,
		}
		if isTypeScriptAdversary(buildContext) {
			resolved.Command = typeScriptHostCommand(buildContext, manifest.Runtime.Command)
		}
		return resolved, nil
	}

	if cache, err := adversarycache.DefaultCache(); err == nil {
		if record, ok := cache.Resolve(ref); ok {
			return ResolveReference(record.Path)
		}
	}

	if store, err := localstore.Default(); err == nil {
		if path, record, err := store.Materialize(ref); err == nil {
			resolved, err := ResolveReference(path)
			if err != nil {
				return ResolvedAdversary{}, err
			}
			resolved.StoreBacked = true
			resolved.StorePath = path
			resolved.ExecutionPath = path
			if record.Runtime == "typescript" {
				resolved.Image = "adversary-local-typescript"
				resolved.Command = typeScriptHostCommand(path, resolved.Command)
			}
			return resolved, nil
		}
	}

	return ResolvedAdversary{
		Name: ref,
	}, nil
}

func isTypeScriptAdversary(path string) bool {
	if info, err := os.Stat(filepath.Join(path, "package.json")); err == nil && !info.IsDir() {
		return true
	}
	if info, err := os.Stat(filepath.Join(path, "dist", "index.js")); err == nil && !info.IsDir() {
		return true
	}
	return false
}

func typeScriptHostCommand(path string, command []string) []string {
	hostCommand := append([]string(nil), command...)
	for i, part := range hostCommand {
		if i > 0 && !filepath.IsAbs(part) && strings.HasSuffix(part, ".js") {
			hostCommand[i] = filepath.Join(path, part)
		}
	}
	return hostCommand
}

type ResolvedAdversary struct {
	Name          string
	Image         string
	Command       []string
	Manifest      *Manifest
	NetworkOff    bool
	LocalDir      bool
	BuildContext  string
	StoreBacked   bool
	StorePath     string
	ExecutionPath string
}
