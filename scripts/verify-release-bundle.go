//go:build ignore

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "bundle: "+f+"\n", a...); os.Exit(1) }
func digest(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func main() {
	dir, version, commit, formula := flag.String("dir", "dist", "directory"), flag.String("version", "", "version"), flag.String("commit", "", "commit"), flag.String("formula", "", "formula")
	flag.Parse()
	archives := []string{"adversary_" + *version + "_darwin_amd64.tar.gz", "adversary_" + *version + "_darwin_arm64.tar.gz", "adversary_" + *version + "_linux_amd64.tar.gz", "adversary_" + *version + "_linux_arm64.tar.gz"}
	checksummed := append(append([]string{}, archives...), "adversary_"+*version+".spdx.json", *formula, "release-manifest.json")
	expected := append(append([]string{}, checksummed...), "checksums.txt")
	sort.Strings(expected)
	entries, err := os.ReadDir(*dir)
	if err != nil {
		die("read directory: %v", err)
	}
	actual := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			die("non-regular bundle entry %q", e.Name())
		}
		actual = append(actual, e.Name())
	}
	sort.Strings(actual)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		die("membership mismatch\nwant %v\ngot  %v", expected, actual)
	}

	data, err := os.ReadFile(filepath.Join(*dir, "checksums.txt"))
	if err != nil {
		die("checksums: %v", err)
	}
	want := map[string]bool{}
	for _, n := range checksummed {
		want[n] = true
	}
	seen := map[string]bool{}
	hexRE := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !hexRE.MatchString(fields[0]) || filepath.Base(fields[1]) != fields[1] || !want[fields[1]] || seen[fields[1]] {
			die("invalid checksum line %q", line)
		}
		seen[fields[1]] = true
		if got := digest(filepath.Join(*dir, fields[1])); got != fields[0] {
			die("checksum mismatch for %s", fields[1])
		}
	}
	if len(seen) != len(want) {
		die("checksum membership mismatch")
	}

	var m struct {
		SchemaVersion                    int `json:"schemaVersion"`
		Version, Commit, SourceDateEpoch string
		Artifacts                        map[string]string `json:"artifacts"`
	}
	b, _ := os.ReadFile(filepath.Join(*dir, "release-manifest.json"))
	if json.Unmarshal(b, &m) != nil || m.SchemaVersion != 1 || m.Version != *version || m.Commit != *commit || m.SourceDateEpoch == "" {
		die("release manifest identity mismatch")
	}
	if len(m.Artifacts) != len(checksummed)-1 {
		die("release manifest artifact count mismatch")
	}
	for _, n := range checksummed {
		if n == "release-manifest.json" {
			continue
		}
		if m.Artifacts[n] != "sha256:"+digest(filepath.Join(*dir, n)) {
			die("manifest digest mismatch for %s", n)
		}
	}

	epoch, err := strconv.ParseInt(m.SourceDateEpoch, 10, 64)
	if err != nil {
		die("invalid sourceDateEpoch")
	}
	for _, name := range archives {
		verifyArchive(filepath.Join(*dir, name), *version, epoch)
	}
	formulaData, _ := os.ReadFile(filepath.Join(*dir, *formula))
	if !bytes.Contains(formulaData, []byte(`version "`+*version+`"`)) {
		die("formula version mismatch")
	}
	for _, name := range archives {
		if !bytes.Contains(formulaData, []byte(name)) {
			die("formula archive mapping missing: %s", name)
		}
	}
	verifySPDX(filepath.Join(*dir, "adversary_"+*version+".spdx.json"), *version)
}

func verifyArchive(path, version string, epoch int64) {
	f, err := os.Open(path)
	if err != nil {
		die("open archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		die("gzip: %v", err)
	}
	if !gz.ModTime.IsZero() {
		die("gzip timestamp is not normalized")
	}
	tr := tar.NewReader(gz)
	want := map[string]bool{"adversary": false, "LICENSE": false, "README.md": false, "docs/release.md": false, "docs/trust-model.md": false}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			die("tar: %v", err)
		}
		n := strings.TrimPrefix(h.Name, "./")
		if n == "" || n == "docs/" {
			continue
		}
		if _, ok := want[n]; !ok {
			die("unexpected archive member %q", h.Name)
		}
		want[n] = true
		if h.Uid != 0 || h.Gid != 0 {
			die("archive owner is not normalized")
		}
		if h.ModTime.Unix() != epoch {
			die("archive mtime is not normalized")
		}
		wantMode := int64(0644)
		if n == "adversary" || strings.HasSuffix(n, "/") {
			wantMode = 0755
		}
		if h.Mode != wantMode {
			die("archive mode for %s is %o", n, h.Mode)
		}
		if n == "adversary" {
			data, err := io.ReadAll(io.LimitReader(tr, 128<<20))
			if err != nil || !bytes.Contains(data, []byte(version)) {
				die("archive binary version stamp missing")
			}
		}
	}
	for n, found := range want {
		if !found {
			die("archive member %s missing", n)
		}
	}
}

func verifySPDX(path, version string) {
	var d struct {
		SPDXVersion, DataLicense, SPDXID, Name, DocumentNamespace string
		Packages                                                  []struct {
			SPDXID, Name, VersionInfo, DownloadLocation string
			ExternalRefs                                []struct{ ReferenceCategory, ReferenceType, ReferenceLocator string } `json:"externalRefs"`
		}
		Relationships []struct{ SPDXElementID, RelationshipType, RelatedSPDXElement string }
	}
	b, _ := os.ReadFile(path)
	if json.Unmarshal(b, &d) != nil || d.SPDXVersion != "SPDX-2.3" || d.DataLicense != "CC0-1.0" || d.SPDXID != "SPDXRef-DOCUMENT" || d.Name != "adversary-"+version || len(d.Packages) == 0 {
		die("invalid SPDX document")
	}
	ids := map[string]bool{d.SPDXID: true}
	for _, p := range d.Packages {
		if p.SPDXID == "" || ids[p.SPDXID] || p.Name == "" || p.VersionInfo == "" || p.DownloadLocation == "" {
			die("invalid or duplicate SPDX package")
		}
		ids[p.SPDXID] = true
		if len(p.ExternalRefs) != 1 || p.ExternalRefs[0].ReferenceType != "purl" {
			die("package purl missing")
		}
	}
	describes, depends := false, 0
	for _, r := range d.Relationships {
		if !ids[r.SPDXElementID] || !ids[r.RelatedSPDXElement] {
			die("relationship references unknown SPDX ID")
		}
		if r.SPDXElementID == d.SPDXID && r.RelationshipType == "DESCRIBES" {
			for _, p := range d.Packages {
				if p.SPDXID == r.RelatedSPDXElement && p.Name == "github.com/adversarylabs/adversary" && p.VersionInfo == version {
					describes = true
				}
			}
		}
		if r.RelationshipType == "DEPENDS_ON" {
			depends++
		}
	}
	if !describes || depends != len(d.Packages)-1 {
		die("SPDX dependency relationships incomplete")
	}
}
