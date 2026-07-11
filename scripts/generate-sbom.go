//go:build ignore

// generate-sbom emits a deterministic SPDX 2.3 module dependency graph.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type module struct {
	Path, Version string
	Main          bool
	Replace       *module
}
type pkg struct {
	Name             string        `json:"name"`
	SPDXID           string        `json:"SPDXID"`
	VersionInfo      string        `json:"versionInfo"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	Supplier         string        `json:"supplier"`
	ExternalRefs     []externalRef `json:"externalRefs"`
}
type externalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}
type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      any            `json:"creationInfo"`
	Packages          []pkg          `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

func id(path, version string) string {
	h := sha256.Sum256([]byte(path + "\x00" + version))
	return "SPDXRef-Package-" + hex.EncodeToString(h[:12])
}
func purl(path, version string) string {
	return "pkg:golang/" + strings.ReplaceAll(url.PathEscape(path), "%2F", "/") + "@" + url.PathEscape(version)
}

func main() {
	version, output := flag.String("version", "dev", "release version"), flag.String("output", "sbom.spdx.json", "output path")
	moduleDir := flag.String("dir", ".", "module directory")
	flag.Parse()
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Dir = *moduleDir
	raw, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	modules := []module{}
	for {
		var m module
		err := dec.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		modules = append(modules, m)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	packages := make([]pkg, 0, len(modules))
	rels := []relationship{}
	mainID := ""
	seenIDs := map[string]bool{}
	for _, m := range modules {
		path, v, download := m.Path, m.Version, ""
		if m.Replace != nil && m.Replace.Version != "" {
			path, v = m.Replace.Path, m.Replace.Version
		} else if m.Replace != nil {
			h := sha256.Sum256([]byte(m.Replace.Path))
			v = m.Version + "+replace." + hex.EncodeToString(h[:6])
			download = "NOASSERTION"
		}
		if m.Main {
			v = *version
		}
		if v == "" {
			v = "unknown"
		}
		if download == "" {
			download = "https://proxy.golang.org/" + path + "/@v/" + v + ".zip"
		}
		pid := id(path, v)
		if seenIDs[pid] {
			panic("duplicate SPDX package identity: " + path + "@" + v)
		}
		seenIDs[pid] = true
		if m.Main {
			mainID = pid
		}
		packages = append(packages, pkg{path, pid, v, download, false, "NOASSERTION", "NOASSERTION", "NOASSERTION", []externalRef{{"PACKAGE-MANAGER", "purl", purl(path, v)}}})
	}
	if mainID == "" {
		panic("main module absent")
	}
	rels = append(rels, relationship{"SPDXRef-DOCUMENT", "DESCRIBES", mainID})
	for _, p := range packages {
		if p.SPDXID != mainID {
			rels = append(rels, relationship{mainID, "DEPENDS_ON", p.SPDXID})
		}
	}
	epoch, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64)
	if err != nil {
		panic("SOURCE_DATE_EPOCH is required")
	}
	d := document{"SPDX-2.3", "CC0-1.0", "SPDXRef-DOCUMENT", "adversary-" + *version, "https://github.com/adversarylabs/adversary/sbom/" + *version, map[string]any{"created": time.Unix(epoch, 0).UTC().Format(time.RFC3339), "creators": []string{"Tool: adversary-release"}}, packages, rels}
	f, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err := e.Encode(d); err != nil {
		panic(err)
	}
}
