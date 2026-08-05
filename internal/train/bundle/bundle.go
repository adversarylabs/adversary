package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// Section names present on a full bundle.
const (
	SectionCheckout         = "checkout"
	SectionDiff             = "diff"
	SectionRepoMetadata     = "repo_metadata"
	SectionHumanReview      = "human_review"
	SectionFollowUp         = "follow_up"
	SectionExpectedConcerns = "expected_concerns"
	SectionKnownNonIssues   = "known_non_issues"
	SectionSplit            = "split"
)

// RoleReviewer is the projection role for adversary/baseline runners.
const RoleReviewer = "reviewer"

// RoleJudge is the projection role for judges that may see labels.
const RoleJudge = "judge"

// reviewerAllowedSections is the only content a reviewer materialization may contain.
var reviewerAllowedSections = map[string]bool{
	SectionCheckout:     true,
	SectionDiff:         true,
	SectionRepoMetadata: true,
}

// forbiddenInReviewer must never appear in a reviewer projection.
var forbiddenInReviewer = []string{
	SectionHumanReview,
	SectionFollowUp,
	SectionExpectedConcerns,
	SectionKnownNonIssues,
	SectionSplit,
}

// Manifest is an immutable prepared-input bundle.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	CaseID        string            `json:"case_id"`
	Sections      map[string]Section `json:"sections"`
	BundleDigest  string            `json:"bundle_digest,omitempty"`
}

// Section references content by digest and optional inline payload for small fixtures.
type Section struct {
	Kind    string          `json:"kind,omitempty"`
	Digest  string          `json:"digest"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Projection is a role-specific view of a bundle.
type Projection struct {
	Role           string            `json:"role"`
	CaseID         string            `json:"case_id"`
	BundleDigest   string            `json:"bundle_digest"`
	Sections       map[string]Section `json:"sections"`
	ProjectionDigest string          `json:"projection_digest,omitempty"`
}

// BuildFromCase constructs a full bundle from a case (payloads stored as digests of JSON).
func BuildFromCase(c *cases.Case) (*Manifest, error) {
	if c == nil {
		return nil, fmt.Errorf("nil case")
	}
	sections := map[string]Section{}

	checkout := map[string]string{
		"base_sha":  c.PullRequest.BaseSHA,
		"head_sha":  c.ReviewEvent.ReviewedSHA,
		"repo":      c.Repository.Owner + "/" + c.Repository.Name,
	}
	if err := putSection(sections, SectionCheckout, "git-refs", checkout); err != nil {
		return nil, err
	}
	diff := map[string]string{
		"base_sha": c.PullRequest.BaseSHA,
		"head_sha": c.ReviewEvent.ReviewedSHA,
		"note":     "logical diff between base and reviewed head",
	}
	if err := putSection(sections, SectionDiff, "diff-meta", diff); err != nil {
		return nil, err
	}
	meta := map[string]string{
		"owner": c.Repository.Owner,
		"name":  c.Repository.Name,
		// origin-url intentionally omitted (redaction)
	}
	if err := putSection(sections, SectionRepoMetadata, "meta", meta); err != nil {
		return nil, err
	}
	if err := putSection(sections, SectionHumanReview, "comments", c.Comments); err != nil {
		return nil, err
	}
	if err := putSection(sections, SectionFollowUp, "follow_up", c.FollowUp); err != nil {
		return nil, err
	}
	if err := putSection(sections, SectionExpectedConcerns, "labels", c.Labels.ExpectedConcerns); err != nil {
		return nil, err
	}
	if err := putSection(sections, SectionKnownNonIssues, "non_issues", c.Labels.KnownNonIssues); err != nil {
		return nil, err
	}
	if err := putSection(sections, SectionSplit, "split", map[string]string{"split": c.Metadata.Split}); err != nil {
		return nil, err
	}

	m := &Manifest{
		SchemaVersion: 3,
		CaseID:        c.ID,
		Sections:      sections,
	}
	d, err := DigestManifest(m)
	if err != nil {
		return nil, err
	}
	m.BundleDigest = d
	return m, nil
}

func putSection(sections map[string]Section, name, kind string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	sections[name] = Section{
		Kind:    kind,
		Digest:  "sha256:" + hex.EncodeToString(sum[:]),
		Payload: raw,
	}
	return nil
}

// DigestManifest computes sha256 of JCS-like canonical JSON without bundle_digest field.
func DigestManifest(m *Manifest) (string, error) {
	clone := *m
	clone.BundleDigest = ""
	// Stable key order via encoding/json map sort in Go 1.x for map[string] — actually Go randomizes map order.
	// Use explicit canonicalization.
	raw, err := canonicalJSON(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(v any) ([]byte, error) {
	// Marshal then re-parse into ordered structure.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, err
	}
	return marshalCanonical(node)
}

func marshalCanonical(v any) ([]byte, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			vb, err := marshalCanonical(t[k])
			if err != nil {
				return nil, err
			}
			b.Write(vb)
		}
		b.WriteByte('}')
		return []byte(b.String()), nil
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			eb, err := marshalCanonical(el)
			if err != nil {
				return nil, err
			}
			b.Write(eb)
		}
		b.WriteByte(']')
		return []byte(b.String()), nil
	default:
		return json.Marshal(t)
	}
}

// ProjectForRole builds a role projection. Reviewer never receives label/follow-up sections.
func ProjectForRole(m *Manifest, role string) (*Projection, error) {
	if m == nil {
		return nil, fmt.Errorf("nil manifest")
	}
	out := &Projection{
		Role:         role,
		CaseID:       m.CaseID,
		BundleDigest: m.BundleDigest,
		Sections:     map[string]Section{},
	}
	switch role {
	case RoleReviewer:
		for name, sec := range m.Sections {
			if reviewerAllowedSections[name] {
				// Copy without large unnecessary fields is fine; strip payload for forbidden is automatic by omission.
				out.Sections[name] = sec
			}
		}
		if err := AssertReviewerIsolation(out); err != nil {
			return nil, err
		}
	case RoleJudge:
		// Judge may see expected concerns and human review for matching; still omit split identity noise if desired.
		for name, sec := range m.Sections {
			if name == SectionSplit {
				continue
			}
			out.Sections[name] = sec
		}
	default:
		return nil, fmt.Errorf("unknown role %q", role)
	}
	d, err := DigestProjection(out)
	if err != nil {
		return nil, err
	}
	out.ProjectionDigest = d
	return out, nil
}

// AssertReviewerIsolation fails if any forbidden section is present or if payloads contain label markers.
func AssertReviewerIsolation(p *Projection) error {
	if p == nil {
		return fmt.Errorf("nil projection")
	}
	if p.Role != RoleReviewer {
		return fmt.Errorf("AssertReviewerIsolation only applies to reviewer role, got %q", p.Role)
	}
	for _, name := range forbiddenInReviewer {
		if _, ok := p.Sections[name]; ok {
			return fmt.Errorf("reviewer projection must not include section %q", name)
		}
	}
	// Payload scan for accidental label leakage in allowed sections.
	for name, sec := range p.Sections {
		if len(sec.Payload) == 0 {
			continue
		}
		s := string(sec.Payload)
		if strings.Contains(s, "expected_concerns") || strings.Contains(s, "follow_up_commits") {
			return fmt.Errorf("reviewer section %q payload appears to contain label/follow-up content", name)
		}
	}
	return nil
}

// DigestProjection digests the projection without projection_digest field.
func DigestProjection(p *Projection) (string, error) {
	clone := *p
	clone.ProjectionDigest = ""
	raw, err := canonicalJSON(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// MaterializeReviewerInput writes reviewer-visible files for a run sandbox.
// Only base/head refs and diff meta — never labels or follow-ups.
func MaterializeReviewerInput(p *Projection, destDir string) error {
	if err := AssertReviewerIsolation(p); err != nil {
		return err
	}
	if err := securefs.MkdirAll(destDir); err != nil {
		return err
	}
	// Write projection manifest without forbidden sections.
	clean := *p
	raw, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return err
	}
	if err := securefs.WriteFile(filepath.Join(destDir, "projection.json"), raw); err != nil {
		return err
	}
	for name, sec := range p.Sections {
		if !reviewerAllowedSections[name] {
			return fmt.Errorf("refusing to materialize forbidden section %q", name)
		}
		if len(sec.Payload) > 0 {
			if err := securefs.WriteFile(filepath.Join(destDir, name+".json"), sec.Payload); err != nil {
				return err
			}
		}
	}
	return nil
}

// SaveManifest writes the full bundle (including sensitive sections) under data root.
func SaveManifest(dataRoot string, m *Manifest) (string, error) {
	dir := filepath.Join(dataRoot, "bundles", m.CaseID)
	if err := securefs.MkdirAll(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "manifest.json")
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := securefs.WriteFile(path, raw); err != nil {
		return "", err
	}
	return path, nil
}

// LoadManifest loads a bundle manifest.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
