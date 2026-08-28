package cmd

import "strings"

var officialCatalogDomains = map[string]struct{}{
	"cloud": {}, "ci": {}, "container": {}, "deps": {}, "factory": {},
	"go": {}, "infra": {}, "lang": {}, "meta": {}, "review": {},
	"security": {}, "web": {},
}

// canonicalCatalogReference keeps historical catalog spellings working at the
// CLI boundary. Catalog IDs are domain/name; depot/ci was published in early
// examples before the canonical ci/depot ID was established.
func canonicalCatalogReference(value string) string {
	value = strings.TrimSpace(value)
	const legacy = "depot/ci"
	const canonical = "ci/depot"
	if value == legacy {
		value = canonical
	}
	if strings.HasPrefix(value, legacy) && len(value) > len(legacy) {
		switch value[len(legacy)] {
		case ':', '@':
			value = canonical + value[len(legacy):]
		}
	}
	name := value
	if before, _, ok := strings.Cut(name, "@"); ok {
		name = before
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	parts := strings.Split(name, "/")
	if len(parts) == 2 {
		if _, official := officialCatalogDomains[strings.ToLower(parts[0])]; official {
			return "library/" + value
		}
	}
	return value
}
