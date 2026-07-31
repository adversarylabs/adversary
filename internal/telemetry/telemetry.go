// Package telemetry implements sanitized CLI usage reporting policy.
//
// Opt-out uses industry-standard and product-specific environment variables.
// Handlers in cmd must not call os.Getenv directly (process-edge rule); this
// package is the intentional boundary for ambient telemetry preference.
package telemetry

import (
	"os"
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
	"infra": {}, "deps": {}, "meta": {}, "cloud": {}, "lang": {},
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
// Only official free-catalog domain/name ids are preserved. Bare short names
// and path-shaped two-segment values (e.g. private-reviewer, internal/x)
// collapse to "local" so directory components never leave the machine.
func SanitizeAdversaryRef(value string) string {
	ref := strings.TrimSpace(strings.ToLower(value))
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, ".") ||
		strings.HasPrefix(ref, "/") ||
		strings.HasPrefix(ref, "~") ||
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
	if len(parts) > 2 && isRegistryHostPart(parts[0]) {
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

func isRegistryHostPart(value string) bool {
	return strings.Contains(value, ".") || strings.Contains(value, ":") || value == "localhost"
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
