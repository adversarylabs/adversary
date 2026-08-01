// Package telemetry implements sanitized CLI usage reporting policy.
//
// Opt-out uses industry-standard and product-specific environment variables.
// Handlers in cmd must not call os.Getenv directly (process-edge rule); this
// package is the intentional boundary for ambient telemetry preference.
package telemetry

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	MaxAdversaries = 64
	MaxIDLength    = 128
)

// Official free-catalog domains (domain/name taxonomy). Two-segment ids are
// only reported when the domain is in this set so bare path segments like
// internal/private-reviewer cannot leak as catalog identifiers.
var officialCatalogDomains = map[string]struct{}{
	"go": {}, "ci": {}, "container": {}, "security": {}, "review": {},
	"infra": {}, "deps": {}, "meta": {}, "cloud": {}, "lang": {}, "web": {},
}

// pathExists is injected in tests.
var pathExists = defaultPathExists

func defaultPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Disabled reports whether the user opted out of sharing sanitized usage data.
//
// Truthy values for any of:
//
//	DO_NOT_TRACK
//	ADVERSARY_DO_NOT_TRACK
//	ADVERSARY_NO_TELEMETRY
//
// Or ADVERSARY_TELEMETRY set to 0|false|off|no|disabled.
func Disabled() bool {
	return DisabledWith(os.Getenv)
}

// DisabledWith is testable with an injected getenv.
func DisabledWith(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	if envTruthy(getenv("DO_NOT_TRACK")) {
		return true
	}
	if envTruthy(getenv("ADVERSARY_DO_NOT_TRACK")) {
		return true
	}
	if envTruthy(getenv("ADVERSARY_NO_TELEMETRY")) {
		return true
	}
	if v := strings.TrimSpace(getenv("ADVERSARY_TELEMETRY")); v != "" {
		switch strings.ToLower(v) {
		case "0", "false", "off", "no", "disabled":
			return true
		}
	}
	return false
}

func envTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "y":
		return true
	default:
		return false
	}
}

// SanitizeAdversarySelection collapses refs to official catalog ids or coarse
// buckets. No filesystem paths, flags, or host identifiers.
func SanitizeAdversarySelection(refs []string) []string {
	out := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, raw := range refs {
		if len(out) >= MaxAdversaries {
			break
		}
		id := SanitizeAdversaryRef(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// SanitizeAdversaryRef normalizes one adversary reference for telemetry.
//
// Local projects (including catalog-shaped relative paths that resolve to an
// on-disk adversary.yaml) always become "local". Only official free-catalog
// domain/name ids that are not local projects are preserved.
func SanitizeAdversaryRef(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}

	// Runtime prefers an on-disk <ref>/adversary.yaml over catalog lookup.
	// Detect that first so ci/private-reviewer never reports as catalog id.
	if isLocalAdversaryProject(raw) {
		return "local"
	}

	ref := strings.ToLower(raw)
	// Explicit path shapes including Windows drive letters (c:/Users/...).
	if strings.HasPrefix(ref, ".") ||
		strings.HasPrefix(ref, "/") ||
		strings.HasPrefix(ref, "~") ||
		isWindowsDrivePath(ref) ||
		strings.Contains(ref, `\`) ||
		strings.Contains(ref, "..") {
		return "local"
	}

	if at := strings.IndexByte(ref, '@'); at >= 0 {
		ref = ref[:at]
	}
	if colon := strings.LastIndexByte(ref, ':'); colon >= 0 {
		slash := strings.LastIndexByte(ref, '/')
		if colon > slash {
			ref = ref[:colon]
		}
	}

	parts := strings.Split(ref, "/")
	filtered := parts[:0]
	for _, p := range parts {
		if p != "" {
			filtered = append(filtered, p)
		}
	}
	parts = filtered
	// Only peel Adversary Labs registry hosts. External OCI hosts must not
	// become catalog-shaped ids (registry.example.com/go/secret → go/secret).
	if len(parts) > 2 && isRegistryHostPart(parts[0]) && !isWindowsDriveLetter(parts[0]) {
		if !isOfficialRegistryHost(parts[0]) {
			return "external"
		}
		ref = strings.Join(parts[1:], "/")
	} else {
		ref = strings.Join(parts, "/")
	}

	if len(ref) > MaxIDLength {
		ref = ref[:MaxIDLength]
	}

	// Official catalog domain/name only (syntax + allowlist).
	if domain, name, ok := splitCatalogID(ref); ok {
		if _, official := officialCatalogDomains[domain]; official && isSingleSegmentID(name) {
			return domain + "/" + name
		}
		// Path-shaped but not an official catalog id (e.g. internal/private-reviewer).
		return "local"
	}

	// Bare short names are ambiguous with local project directories — never emit.
	if isSingleSegmentID(ref) {
		return "local"
	}

	return "other"
}

// isLocalAdversaryProject reports whether ref is an on-disk adversary project
// (directory with adversary.yaml), matching CLI resolution precedence.
func isLocalAdversaryProject(raw string) bool {
	p := strings.TrimSpace(raw)
	if p == "" {
		return false
	}
	// Drop digest.
	if at := strings.IndexByte(p, '@'); at >= 0 {
		p = p[:at]
	}
	// Drop trailing :tag when not a Windows drive path (C:\ or C:/).
	if !isWindowsDrivePath(strings.ToLower(p)) {
		if colon := strings.LastIndexByte(p, ':'); colon > 0 {
			// Keep "C:" style only when it is a drive prefix; otherwise treat as tag.
			if !(colon == 1 && len(p) > 2 && (p[2] == '/' || p[2] == '\\')) {
				slash := strings.LastIndexByte(p, '/')
				bslash := strings.LastIndexByte(p, '\\')
				sep := slash
				if bslash > sep {
					sep = bslash
				}
				if colon > sep {
					p = p[:colon]
				}
			}
		}
	}

	// Direct path to adversary.yaml
	base := filepath.Base(p)
	if strings.EqualFold(base, "adversary.yaml") || strings.EqualFold(base, "adversary.yml") {
		return pathExists(p)
	}

	// Directory containing adversary.yaml (runtime local project form).
	for _, name := range []string{"adversary.yaml", "adversary.yml"} {
		if pathExists(filepath.Join(p, name)) {
			return true
		}
	}
	return false
}

func isRegistryHostPart(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || value == "localhost"
}

func isWindowsDrivePath(value string) bool {
	// c:/users/... or c:\users\...
	if len(value) < 3 {
		return false
	}
	drive := value[0]
	if !((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
		return false
	}
	if value[1] != ':' {
		return false
	}
	return value[2] == '/' || value[2] == '\\'
}

func isWindowsDriveLetter(value string) bool {
	// bare "c:" segment after split on /
	if len(value) != 2 {
		return false
	}
	drive := value[0]
	if !((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
		return false
	}
	return value[1] == ':'
}

func isOfficialRegistryHost(value string) bool {
	// Only Adversary Labs production registry hosts. localhost (any port) is
	// not official — localhost:5000/go/private must not become go/private.
	host := value
	if i := strings.IndexByte(value, ':'); i >= 0 {
		host = value[:i]
	}
	return host == "registry.adversarylabs.ai" ||
		strings.HasSuffix(host, ".adversarylabs.ai")
}

func splitCatalogID(value string) (domain, name string, ok bool) {
	slash := strings.IndexByte(value, '/')
	if slash <= 0 || slash == len(value)-1 {
		return "", "", false
	}
	if strings.Count(value, "/") != 1 {
		return "", "", false
	}
	domain = value[:slash]
	name = value[slash+1:]
	if !isSingleSegmentID(domain) || !isSingleSegmentID(name) {
		return "", "", false
	}
	return domain, name, true
}

func isSingleSegmentID(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
			if i == 0 || i == len(value)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
