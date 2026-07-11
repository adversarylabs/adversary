package adversary

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	canonical "github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/repository"
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
	return resolveReference(ref, nil)
}
func ResolveReferenceWithResolver(ref string, resolver Resolver) (ResolvedAdversary, error) {
	return resolveReference(ref, &resolver)
}
func resolveReference(ref string, resolver *Resolver) (ResolvedAdversary, error) {
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
		image := manifest.Runtime.Image
		if manifest.Runtime.Name != "" {
			image = "host:" + manifest.Runtime.Name
		}
		resolved := ResolvedAdversary{
			Name:           manifest.Name,
			Image:          image,
			RuntimeName:    strings.TrimSpace(manifest.Runtime.Name),
			RuntimeVersion: manifest.Runtime.Version,
			Command:        manifest.Runtime.Command,
			Manifest:       &manifest,
			NetworkOff:     manifest.Permissions.Network != nil && !*manifest.Permissions.Network,
			LocalDir:       true,
			BuildContext:   buildContext,
			ExecutionPath:  buildContext,
		}
		if resolved.RuntimeName == "node" {
			resolved.Command = typeScriptHostCommand(buildContext, resolved.RuntimeName, manifest.Runtime.Command)
		}
		return resolved, nil
	}
	if resolver == nil {
		defaultResolver, err := DefaultResolver()
		if err != nil {
			return ResolvedAdversary{}, err
		}
		resolver = &defaultResolver
	}
	if resolution, resolveErr := resolver.Resolve(ref); resolveErr == nil && !resolution.Local {
		resolved, err := resolveReference(resolution.Path, resolver)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		resolved.StoreBacked = true
		resolved.StoreRecord = resolution.Record
		resolved.StorePath = resolution.Path
		resolved.ExecutionPath = resolution.Path
		if resolved.RuntimeName == "node" {
			resolved.Image = "host:node"
			resolved.Command = typeScriptHostCommand(resolution.Path, resolved.RuntimeName, resolved.Command)
		}
		return resolved, nil
	} else if errors.Is(resolveErr, repository.ErrAmbiguous) {
		return ResolvedAdversary{}, resolveErr
	} else if !errors.Is(resolveErr, ErrNotFound) {
		return ResolvedAdversary{}, resolveErr
	}
	return ResolvedAdversary{
		Name: ref,
	}, nil
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
	StoreRecord    repository.Record
	StorePath      string
	ExecutionPath  string
}
