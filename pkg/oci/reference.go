package oci

import (
	"fmt"
	"os"
	"strings"
)

const (
	DefaultRegistry  = "registry.adversarylabs.ai"
	DefaultNamespace = "library"
	DefaultTag       = "latest"
)

type Reference struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

func ParseReference(input string) (Reference, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Reference{}, fmt.Errorf("reference is required")
	}
	if strings.Contains(input, "://") {
		return Reference{}, fmt.Errorf("reference must not include a URL scheme")
	}

	var digest string
	if before, after, ok := strings.Cut(input, "@"); ok {
		input = before
		digest = after
		if digest == "" {
			return Reference{}, fmt.Errorf("reference digest is empty")
		}
	}

	tag := ""
	lastSlash := strings.LastIndex(input, "/")
	lastColon := strings.LastIndex(input, ":")
	if lastColon > lastSlash {
		tag = input[lastColon+1:]
		input = input[:lastColon]
		if tag == "" {
			return Reference{}, fmt.Errorf("reference tag is empty")
		}
	}
	if tag == "" && digest == "" {
		tag = DefaultTag
	}

	parts := strings.Split(input, "/")
	for _, part := range parts {
		if part == "" {
			return Reference{}, fmt.Errorf("invalid empty reference component")
		}
	}

	registry := DefaultRegistryHost()
	repositoryParts := parts
	explicitRegistry := false
	if len(parts) > 1 && isRegistryHost(parts[0]) {
		registry = parts[0]
		repositoryParts = parts[1:]
		explicitRegistry = true
	}
	if !explicitRegistry && len(repositoryParts) == 1 {
		repositoryParts = []string{DefaultNamespace, repositoryParts[0]}
	}
	repository := strings.Join(repositoryParts, "/")
	if repository == "" {
		return Reference{}, fmt.Errorf("repository is required")
	}

	return Reference{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
	}, nil
}

func DefaultRegistryHost() string {
	if value := strings.TrimSpace(os.Getenv("ADVERSARY_REGISTRY_HOST")); value != "" {
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		return strings.TrimRight(value, "/")
	}
	return DefaultRegistry
}

func isRegistryHost(component string) bool {
	return strings.Contains(component, ".") || strings.Contains(component, ":") || component == "localhost"
}

func (r Reference) Name() string {
	return r.Registry + "/" + r.Repository
}

func (r Reference) Locator() string {
	if r.Digest != "" {
		return r.Name() + "@" + r.Digest
	}
	return r.Name() + ":" + r.Tag
}

func (r Reference) ManifestReference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

func (r Reference) ShortName() string {
	parts := strings.Split(r.Repository, "/")
	return parts[len(parts)-1]
}
