package cmd

import "strings"

// canonicalCatalogReference keeps historical catalog spellings working at the
// CLI boundary. Catalog IDs are domain/name; depot/ci was published in early
// examples before the canonical ci/depot ID was established.
func canonicalCatalogReference(value string) string {
	value = strings.TrimSpace(value)
	const legacy = "depot/ci"
	const canonical = "ci/depot"
	if value == legacy {
		return canonical
	}
	if strings.HasPrefix(value, legacy) && len(value) > len(legacy) {
		switch value[len(legacy)] {
		case ':', '@':
			return canonical + value[len(legacy):]
		}
	}
	return value
}
