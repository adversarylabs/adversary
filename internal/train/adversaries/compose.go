package adversaries

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/pkg/compose"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

// ExpandUsesRefs returns the ordered product run set for a local package:
// the package itself plus transitive adversary.yaml uses. Always expands when
// uses are present — independent of train official jury settings.
//
// Registry members appear as name[:version] refs (CLI pull on run). Local path
// members are absolute directories when they exist.
func ExpandUsesRefs(pkg Package) ([]string, error) {
	if len(pkg.Uses) == 0 {
		if pkg.Dir != "" {
			return []string{pkg.Dir}, nil
		}
		return nil, nil
	}
	root := pkg.Dir
	if root == "" {
		return nil, fmt.Errorf("package %s has uses but empty Dir", pkg.ID)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	loader := trainComposeLoader{root: abs}
	res, err := compose.Expand([]string{abs}, loader, compose.Options{})
	if err != nil {
		return nil, err
	}
	if len(res.Refs) == 0 {
		return []string{abs}, nil
	}
	return res.Refs, nil
}

// FormatUsesSummary is a short log line for composition members.
func FormatUsesSummary(pkg Package) string {
	if len(pkg.Uses) == 0 {
		return ""
	}
	var parts []string
	for _, u := range pkg.Uses {
		switch {
		case u.Name != "" && u.Version != "":
			parts = append(parts, u.Name+":"+u.Version)
		case u.Name != "":
			parts = append(parts, u.Name)
		case u.Path != "":
			parts = append(parts, "path:"+u.Path)
		}
	}
	return strings.Join(parts, ", ")
}

// trainComposeLoader expands only from the local package tree (and nested local
// paths). Registry uses entries are returned as name refs without install.
type trainComposeLoader struct {
	root string
}

func (l trainComposeLoader) Load(ref string) (manifest.Manifest, string, error) {
	ref = strings.TrimSpace(ref)
	// Local directory with adversary.yaml
	dir := ref
	if st, err := os.Stat(ref); err == nil {
		if !st.IsDir() {
			dir = filepath.Dir(ref)
		}
		yamlPath := filepath.Join(dir, manifest.FileName)
		if _, err := os.Stat(yamlPath); err == nil {
			m, err := manifest.Load(yamlPath)
			if err != nil {
				return manifest.Manifest{}, "", err
			}
			abs, _ := filepath.Abs(dir)
			return m, abs, nil
		}
	}
	// Registry name: leaf for expand (no further uses without materialize).
	// Return empty uses so expand stops; CLI will pull on run.
	return manifest.Manifest{
		Name: ref,
		Uses: nil,
		Runtime: manifest.Runtime{
			Name:    "node",
			Version: "22",
			Command: []string{"dist/index.js"},
		},
	}, "", nil
}

// Ensure trainComposeLoader can resolve UseReference for path members: Load is
// only called on roots and discovered members. For path members, compose joins
// packageDir then Loads. Empty packageDir for registry leaves is OK — no uses.
var _ compose.Loader = trainComposeLoader{}
