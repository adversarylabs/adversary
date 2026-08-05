package cases

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adversarylabs/adversary/internal/train/securefs"
	"gopkg.in/yaml.v3"
)

// Load loads a case from JSON or YAML path.
func Load(path string) (*Case, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Case
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("yaml: %w", err)
		}
	default:
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
	}
	return &c, nil
}

// SaveJSON writes a case as JSON (user-only perms: may contain private review bodies).
func SaveJSON(path string, c *Case) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return securefs.WriteFile(path, raw)
}

// ListIDs lists case IDs under a directory (json/yaml files).
func ListIDs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			continue
		}
		c, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		ids = append(ids, c.ID)
	}
	return ids, nil
}
