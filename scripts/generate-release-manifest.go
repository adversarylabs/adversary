//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
)

type manifest struct {
	SchemaVersion   int               `json:"schemaVersion"`
	Version         string            `json:"version"`
	Commit          string            `json:"commit"`
	SourceDateEpoch string            `json:"sourceDateEpoch"`
	Artifacts       map[string]string `json:"artifacts"`
}

func main() {
	dir, version, commit := flag.String("dir", "dist", "bundle directory"), flag.String("version", "", "version"), flag.String("commit", "", "commit")
	formula, output := flag.String("formula", "", "formula name"), flag.String("output", "", "manifest output")
	flag.Parse()
	names := []string{
		"adversary_" + *version + "_darwin_amd64.tar.gz", "adversary_" + *version + "_darwin_arm64.tar.gz",
		"adversary_" + *version + "_linux_amd64.tar.gz", "adversary_" + *version + "_linux_arm64.tar.gz",
		"adversary_" + *version + ".spdx.json", *formula,
	}
	sort.Strings(names)
	artifacts := make(map[string]string, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(data)
		artifacts[name] = "sha256:" + hex.EncodeToString(sum[:])
	}
	epoch := os.Getenv("SOURCE_DATE_EPOCH")
	if epoch == "" {
		panic("SOURCE_DATE_EPOCH is required")
	}
	f, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err := e.Encode(manifest{1, *version, *commit, epoch, artifacts}); err != nil {
		panic(err)
	}
}
