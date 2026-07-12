package oci

import (
	"fmt"
	"os"
	"strings"

	distref "github.com/distribution/reference"
)

const (
	DefaultRegistry  = "registry.adversarylabs.ai"
	DefaultNamespace = "library"
	DefaultTag       = "latest"
)

type Reference struct{ Registry, Repository, Tag, Digest string }

func ParseReference(input string) (Reference, error) {
	return ParseReferenceWithDefaults(input, DefaultRegistryHost(), DefaultNamespace)
}

// ParseReferenceWithDefaults parses a reference using caller-owned defaults.
// Persistent indexes must use this function rather than process environment so
// their identity remains stable across restarts and configuration changes.
func ParseReferenceWithDefaults(input, registry, namespace string) (Reference, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Reference{}, fmt.Errorf("reference is required")
	}
	if strings.Contains(input, "://") {
		return Reference{}, fmt.Errorf("reference must not include a URL scheme")
	}
	if strings.Count(input, "@") > 1 {
		return Reference{}, fmt.Errorf("invalid reference: repeated digest separator")
	}

	qualified := input
	namePart := input
	if before, _, ok := strings.Cut(namePart, "@"); ok {
		namePart = before
	}
	first := namePart
	hasSlash := strings.Contains(first, "/")
	if before, _, ok := strings.Cut(first, "/"); ok {
		first = before
	}
	explicitRegistry := hasSlash && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" || strings.HasPrefix(first, "["))
	if !explicitRegistry {
		if !strings.Contains(namePart, "/") {
			qualified = strings.TrimRight(registry, "/") + "/" + strings.Trim(namespace, "/") + "/" + input
		} else {
			qualified = strings.TrimRight(registry, "/") + "/" + input
		}
	}
	named, err := distref.ParseNormalizedNamed(qualified)
	if err != nil {
		return Reference{}, fmt.Errorf("invalid OCI reference %q: %w", input, err)
	}
	if _, ok := named.(distref.Digested); !ok {
		named = distref.TagNameOnly(named)
	}
	r := Reference{Registry: distref.Domain(named), Repository: distref.Path(named)}
	if tagged, ok := named.(distref.Tagged); ok {
		r.Tag = tagged.Tag()
	}
	if digested, ok := named.(distref.Digested); ok {
		if _, err := ParseDigest(digested.Digest().String()); err != nil {
			return Reference{}, err
		}
		r.Digest = digested.Digest().String()
	}
	return r, nil
}

func DefaultRegistryHost() string {
	if value := strings.TrimSpace(os.Getenv("ADVERSARY_REGISTRY_HOST")); value != "" {
		return strings.TrimRight(value, "/")
	}
	return DefaultRegistry
}

func (r Reference) Name() string { return r.Registry + "/" + r.Repository }
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
