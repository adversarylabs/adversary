package adversary

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	adversarycache "github.com/adversarylabs/adversary/pkg/adversary"
	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	localstore "github.com/adversarylabs/adversary/pkg/store"
)

type Manifest = canonical.Manifest
type Triggers = canonical.Triggers
type Runtime = canonical.Runtime
type Permissions = canonical.Permissions
type FilesystemPermissions = canonical.FilesystemPermissions
type Findings = canonical.Findings

func LoadManifest(path string) (Manifest, error) {
	return canonical.Load(path)
}

func parseManifest(data []byte) (Manifest, error) {
	return canonical.Parse(data)
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
			Name:           manifest.Name,
			Image:          "adversary-local-typescript",
			RuntimeName:    normalizeRuntimeName(manifest.Runtime.Name, manifest.Runtime.Command),
			RuntimeVersion: manifest.Runtime.Version,
			Command:        manifest.Runtime.Command,
			Manifest:       &manifest,
			NetworkOff:     manifest.Permissions.Network != nil && !*manifest.Permissions.Network,
			LocalDir:       true,
			BuildContext:   buildContext,
			ExecutionPath:  buildContext,
		}
		if isTypeScriptAdversary(buildContext) {
			resolved.RuntimeName = "node"
			resolved.Command = typeScriptHostCommand(buildContext, resolved.RuntimeName, manifest.Runtime.Command)
		}
		return resolved, nil
	}

	if cache, err := adversarycache.DefaultCache(); err == nil {
		if record, ok := cache.Resolve(ref); ok {
			resolved, err := ResolveReference(record.Path)
			if err != nil {
				return ResolvedAdversary{}, err
			}
			if resolved.Name != record.Name || (record.Version != "" && resolved.Manifest.Version != record.Version) {
				return ResolvedAdversary{}, fmt.Errorf("cached manifest identity does not match cache record")
			}
			return resolved, nil
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
				resolved.RuntimeName = "node"
				resolved.RuntimeVersion = record.RuntimeVersion
				resolved.Command = typeScriptHostCommand(path, resolved.RuntimeName, resolved.Command)
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

func typeScriptHostCommand(path, runtimeName string, command []string) []string {
	hostCommand := append([]string(nil), command...)
	for i, part := range hostCommand {
		if !filepath.IsAbs(part) && strings.HasSuffix(part, ".js") {
			hostCommand[i] = filepath.Join(path, part)
		}
	}
	if runtimeName == "node" && (len(hostCommand) == 0 || hostCommand[0] != "node") {
		hostCommand = append([]string{"node"}, hostCommand...)
	}
	return hostCommand
}

func normalizeRuntimeName(name string, command []string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		if name == "typescript" {
			return "node"
		}
		return name
	}
	if len(command) > 0 && command[0] == "node" {
		return "node"
	}
	return ""
}

type ResolvedAdversary struct {
	Name           string
	Image          string
	RuntimeName    string
	RuntimeVersion string
	Command        []string
	Manifest       *Manifest
	NetworkOff     bool
	LocalDir       bool
	BuildContext   string
	StoreBacked    bool
	StorePath      string
	ExecutionPath  string
}
