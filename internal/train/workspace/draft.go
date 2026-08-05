package workspace

import (
	"strings"
)

// PackageRole is how a package participates in a train pass.
type PackageRole string

const (
	RoleLocalTrainable PackageRole = "local"    // may receive train drafts
	RoleOfficialJury   PackageRole = "official" // grade only; never drafts
)

// GoldOutcome is the train attribution for one human gold concern.
type GoldOutcome struct {
	// OwnerID is the best-fit package for routing (local preferred on override/tie).
	OwnerID string
	// OwnerRole is local or official.
	OwnerRole PackageRole
	// OfficialCaught is true if any official jury package matched the gold.
	OfficialCaught bool
	// OfficialCatcher is the official package id that matched (if any).
	OfficialCatcher string
	// LocalMiss is true when a train-eligible local owns the gold, missed, and no official catch.
	LocalMiss bool
	// EmitDraft is true when a suggested issue should be drafted for OwnerID (local only).
	EmitDraft bool
	// Reason explains the decision for stories/tests.
	Reason string
}

// PackageMeta describes a package available during train.
type PackageMeta struct {
	ID   string
	Role PackageRole
	// TrainEligible is true for locals included in this run (--adversary filter).
	TrainEligible bool
}

// AttributeGold decides draft eligibility for one gold concern.
//
// Rules (design doc):
//   - Official never receives train drafts.
//   - If any official catches the gold, do not draft for locals.
//   - Local miss + train-eligible + no official catch => draft.
//   - Local override maps official surface to local ownership for drafts.
func AttributeGold(
	cfg Config,
	ownerID string,
	ownerRole PackageRole,
	localMissed bool,
	officialCatcher string,
	trainEligibleLocal bool,
) GoldOutcome {
	out := GoldOutcome{
		OwnerID:   ownerID,
		OwnerRole: ownerRole,
	}
	if officialCatcher != "" {
		out.OfficialCaught = true
		out.OfficialCatcher = officialCatcher
	}

	// Never draft for official owners.
	if ownerRole == RoleOfficialJury {
		out.EmitDraft = false
		out.LocalMiss = false
		if out.OfficialCaught {
			out.Reason = "official package owned gold; not a train draft target"
		} else {
			out.Reason = "gold fits official-only mission; not training home-grown clones"
		}
		return out
	}

	// Official catch suppresses local drafts even if local also owned.
	if out.OfficialCaught {
		out.EmitDraft = false
		out.LocalMiss = false
		out.Reason = "official " + out.OfficialCatcher + " caught gold; no local train draft"
		return out
	}

	if ownerRole == RoleLocalTrainable && localMissed && trainEligibleLocal {
		out.LocalMiss = true
		out.EmitDraft = true
		out.Reason = "local miss with no official catch; draft for " + ownerID
		return out
	}

	if ownerRole == RoleLocalTrainable && localMissed && !trainEligibleLocal {
		out.LocalMiss = true
		out.EmitDraft = false
		out.Reason = "local miss but package not train-eligible this run"
		return out
	}

	out.EmitDraft = false
	out.Reason = "no local miss (caught or out of train set)"
	return out
}

// PreferLocalOwner applies overrides and local-over-official preference when both claim.
func PreferLocalOwner(cfg Config, localID, officialID string, localInScope, officialInScope bool) (ownerID string, role PackageRole) {
	if localID != "" {
		if override, ok := cfg.LocalOverride(officialID); ok && normalizeID(override) == normalizeID(localID) {
			return localID, RoleLocalTrainable
		}
		if override, ok := cfg.LocalOverride(localID); ok {
			return override, RoleLocalTrainable
		}
	}
	if localInScope && localID != "" {
		// Prefer local when both in scope (customer ownership).
		if officialInScope {
			return localID, RoleLocalTrainable
		}
		return localID, RoleLocalTrainable
	}
	if officialInScope && officialID != "" && cfg.OfficialIncluded(officialID) {
		return officialID, RoleOfficialJury
	}
	if localID != "" {
		return localID, RoleLocalTrainable
	}
	return officialID, RoleOfficialJury
}

// IsOfficialPackageID reports whether id looks like a registry/official package
// (used when packages aren't tagged explicitly). Locals from workspace are not official.
func IsOfficialPackageID(id string, localIDs map[string]bool) bool {
	id = normalizeID(id)
	if localIDs[id] {
		return false
	}
	// Common official short names
	officials := []string{
		"engineering-review", "go-concurrency", "go-testing", "go-security",
		"go-http", "go-database", "go-cli", "go-modules", "go",
		"githubactions", "dockerfile", "terraform", "kustomize", "helm",
		"secrets", "complexity", "python", "typescript", "nodejs",
	}
	for _, o := range officials {
		if id == o || id == strings.ReplaceAll(o, "-", "/") || strings.HasSuffix(id, "/"+o) {
			return true
		}
	}
	return false
}

// needed for PreferLocalOwner - import strings already in package via normalize
// Fix IsOfficialPackageID - uses strings - already imported in draft.go? Need strings import.
