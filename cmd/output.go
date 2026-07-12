package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"unicode"

	"github.com/adversarylabs/adversary/internal/version"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
	"github.com/spf13/cobra"
)

const outputSchemaVersion = 1

type outputEnvelope[T any] struct {
	SchemaVersion int    `json:"schemaVersion"`
	Command       string `json:"command"`
	Data          T      `json:"data"`
}

func writeJSON[T any](w io.Writer, command string, data T) error {
	return writeJSONVersion(w, outputSchemaVersion, command, data)
}

func writeJSONVersion[T any](w io.Writer, version int, command string, data T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(outputEnvelope[T]{SchemaVersion: version, Command: command, Data: data})
}

func validateFormat(format string, legacyJSON bool) (string, error) {
	if format != "text" && format != "json" {
		return "", fmt.Errorf("--format must be text or json")
	}
	if legacyJSON && format != "text" {
		return "", fmt.Errorf("--json and --format cannot be combined")
	}
	if legacyJSON {
		return "json", nil
	}
	return format, nil
}

func commandFormat(cmd *cobra.Command, format string, legacyJSON bool) (string, error) {
	if legacyJSON && cmd.Flags().Changed("format") {
		return "", fmt.Errorf("--json and --format cannot be combined")
	}
	return validateFormat(format, legacyJSON)
}

func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

type versionDTO struct {
	Version               string `json:"version"`
	Commit                string `json:"commit"`
	BuildDate             string `json:"buildDate"`
	GoVersion             string `json:"goVersion"`
	ReviewProtocolVersion int    `json:"reviewProtocolVersion"`
}

func currentVersion() versionDTO {
	return versionDTO{version.Version, version.Commit, version.BuildDate, runtime.Version(), review.ProtocolVersion}
}

type artifactDTO struct {
	CanonicalReference string              `json:"canonicalReference"`
	Digest             string              `json:"digest"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Origin             artifactOriginDTO   `json:"origin"`
	Trust              artifactTrustDTO    `json:"trust"`
	Manifest           artifactManifestDTO `json:"manifest"`
	Files              artifactFilesDTO    `json:"files"`
}

type artifactOriginDTO struct {
	Kind            string `json:"kind"`
	CanonicalSource string `json:"canonicalSource"`
}
type artifactTrustDTO struct {
	Status   string `json:"status"`
	Decision string `json:"decision"`
}
type artifactManifestDTO struct {
	Validation              string `json:"validation"`
	ManifestDigest          string `json:"manifestDigest"`
	ConfigDigest            string `json:"configDigest"`
	LayerDigest             string `json:"layerDigest"`
	AdversaryManifestDigest string `json:"adversaryManifestDigest"`
}
type artifactFilesDTO struct {
	Status  string            `json:"status"`
	Reason  string            `json:"reason"`
	Entries []artifactFileDTO `json:"entries"`
}
type artifactFileDTO struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
	Mode      string `json:"mode"`
}

func storedArtifactDTO(canonical, digest string, recName, recVersion, manifest, config, layer, adversaryManifest string) artifactDTO {
	return artifactDTO{CanonicalReference: canonical, Digest: digest, Name: recName, Version: recVersion,
		Origin:   artifactOriginDTO{Kind: "unifiedRepository", CanonicalSource: canonical},
		Trust:    artifactTrustDTO{Status: "unverified", Decision: "The repository verifies content digests and strict manifests but does not currently verify publisher signatures."},
		Manifest: artifactManifestDTO{Validation: "strictOnImport", ManifestDigest: manifest, ConfigDigest: config, LayerDigest: layer, AdversaryManifestDigest: adversaryManifest},
		Files:    artifactFilesDTO{Status: "unavailable", Reason: "The resolver interface does not expose a per-file inventory; no file metadata was inferred.", Entries: []artifactFileDTO{}},
	}
}

func storedArtifactDTOWithFiles(canonical, digest string, rec repository.Record, files []pack.File) artifactDTO {
	out := storedArtifactDTO(canonical, digest, rec.Name, rec.Version, rec.ManifestDigest, rec.ConfigDigest, rec.LayerDigest, rec.AdversaryManifestDigest)
	out.Files = artifactFilesDTO{Status: "available", Reason: "Inventory verified from the immutable OCI config.", Entries: make([]artifactFileDTO, 0, len(files))}
	for _, f := range files {
		out.Files.Entries = append(out.Files.Entries, artifactFileDTO{Path: f.Path, Digest: "sha256:" + f.SHA256, SizeBytes: f.Size, Mode: fmt.Sprintf("%#o", f.Mode)})
	}
	return out
}

type legacyRecordV0DTO struct {
	Digest                  string `json:"digest"`
	Name                    string `json:"name"`
	Version                 string `json:"version"`
	ManifestDigest          string `json:"manifestDigest"`
	ConfigDigest            string `json:"configDigest"`
	LayerDigest             string `json:"layerDigest"`
	AdversaryManifestDigest string `json:"adversaryManifestDigest"`
}
type legacyArtifactV0DTO struct {
	Record             legacyRecordV0DTO `json:"record"`
	CanonicalReference string            `json:"canonicalReference"`
	Digest             string            `json:"digest"`
}

func legacyArtifact(canonical, digest string, rec repository.Record) legacyArtifactV0DTO {
	return legacyArtifactV0DTO{CanonicalReference: canonical, Digest: digest, Record: legacyRecordV0DTO{rec.Digest, rec.Name, rec.Version, rec.ManifestDigest, rec.ConfigDigest, rec.LayerDigest, rec.AdversaryManifestDigest}}
}

type listDTO struct {
	Artifacts []artifactDTO `json:"artifacts"`
}
type packDTO struct {
	Name               string           `json:"name"`
	Version            string           `json:"version"`
	Runtime            string           `json:"runtime"`
	RuntimeRequirement string           `json:"runtimeRequirement,omitempty"`
	Digest             string           `json:"digest"`
	CanonicalReference string           `json:"canonicalReference"`
	SizeBytes          int64            `json:"sizeBytes"`
	References         []string         `json:"references"`
	Files              []packFileDTO    `json:"files"`
	Warnings           []packWarningDTO `json:"warnings"`
}
type legacyPackV1DTO struct {
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	Runtime            string   `json:"runtime"`
	RuntimeRequirement string   `json:"runtimeRequirement,omitempty"`
	Digest             string   `json:"digest"`
	CanonicalReference string   `json:"canonicalReference"`
	SizeBytes          int64    `json:"sizeBytes"`
	References         []string `json:"references"`
}
type packFileDTO struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
	Mode      string `json:"mode"`
}
type packWarningDTO struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}
type packCheckDTO struct {
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	Runtime  string           `json:"runtime"`
	Files    []packFileDTO    `json:"files"`
	Warnings []packWarningDTO `json:"warnings"`
}
type pushDTO struct {
	CanonicalReference string `json:"canonicalReference"`
	Digest             string `json:"digest"`
	ManifestDigest     string `json:"manifestDigest"`
}
type pullDTO struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	CanonicalReference string `json:"canonicalReference"`
	Digest             string `json:"digest"`
}
type searchDTO struct {
	Results []searchResultDTO `json:"results"`
}
type searchResultDTO struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
}
type whoamiDTO struct {
	Authenticated bool   `json:"authenticated"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	Subscription  string `json:"subscription,omitempty"`
	Status        string `json:"status,omitempty"`
}
