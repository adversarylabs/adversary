package adversary

import (
	"errors"
	"io"
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
type EnvironmentPermissions = canonical.EnvironmentPermissions
type Findings = canonical.Findings

func parseManifest(data []byte) (Manifest, error) {
	return canonical.Parse(data)
}

func ResolveReferenceWithRuntime(ref string, resolver Resolver, files RuntimeFiles) (ResolvedAdversary, error) {
	if files == nil {
		return ResolvedAdversary{}, errors.New("runtime filesystem dependency is required")
	}
	return resolveReference(ref, &resolver, files)
}
func resolveReference(ref string, resolver *Resolver, files RuntimeFiles) (ResolvedAdversary, error) {
	manifestPath := filepath.Join(ref, "adversary.yaml")
	if info, err := files.Stat(manifestPath); err == nil && !info.IsDir() {
		buildContext, err := files.Abs(ref)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		manifestFile, err := files.Open(manifestPath)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		manifestData, readErr := io.ReadAll(io.LimitReader(manifestFile, canonical.MaxSize+1))
		closeErr := manifestFile.Close()
		if readErr != nil {
			return ResolvedAdversary{}, readErr
		}
		if closeErr != nil {
			return ResolvedAdversary{}, closeErr
		}
		manifest, err := parseManifest(manifestData)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		image, err := runtimeExecutionImage(manifest.Runtime)
		if err != nil {
			return ResolvedAdversary{}, err
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
		resolved, err := resolveReference(resolution.Path, resolver, files)
		if err != nil {
			return ResolvedAdversary{}, err
		}
		resolved.StoreBacked = true
		resolved.StoreRecord = resolution.Record
		resolved.CanonicalReference = resolution.CanonicalReference
		resolved.Digest = resolution.Digest
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

func runtimeExecutionImage(runtime canonical.Runtime) (string, error) {
	switch {
	case runtime.Name != "" && runtime.Image != "":
		return "", errors.New("manifest runtime has both name and image execution identities")
	case runtime.Name != "":
		return "host:" + runtime.Name, nil
	case runtime.Image != "":
		return runtime.Image, nil
	default:
		return "", errors.New("manifest runtime has no execution identity")
	}
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
	Name               string
	Image              string
	RuntimeName        string
	RuntimeVersion     string
	Command            []string
	Manifest           *Manifest
	NetworkOff         bool
	LocalDir           bool
	BuildContext       string
	StoreBacked        bool
	StoreRecord        repository.Record
	CanonicalReference string
	Digest             string
	Publisher          string
	StorePath          string
	ExecutionPath      string
}
