package adversary

import canonical "github.com/adversarylabs/adversary/pkg/manifest"

// LoadManifest and the legacy ResolveReference helpers are concrete
// filesystem conveniences. Production runtime composition uses
// ResolveReferenceWithRuntime with its injected filesystem instead.
func LoadManifest(path string) (Manifest, error) {
	return canonical.Load(path)
}

func ResolveReference(ref string) (ResolvedAdversary, error) {
	return resolveReference(ref, nil, OSRuntimeFiles{})
}

func ResolveReferenceWithResolver(ref string, resolver Resolver) (ResolvedAdversary, error) {
	return resolveReference(ref, &resolver, OSRuntimeFiles{})
}
