// Package catalogapply writes an approved catalog-training rule into the local
// private catalog. It intentionally performs no git or network operations.
package catalogapply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
	"gopkg.in/yaml.v3"
)

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Apply writes one approved rule into its adversary source and marks the inbox
// row applied. The caller owns any later git commit or pull request.
func Apply(_ context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string) error {
	row, err := results.Get(stateRoot, id)
	if err != nil {
		return err
	}
	if row.Status == results.StatusDismissed {
		return fmt.Errorf("candidate %s is dismissed", row.ID)
	}
	owner := strings.TrimSpace(row.Package)
	if owner == "" || owner == "unassigned" {
		return fmt.Errorf("choose an adversary before applying this candidate")
	}
	if !safeID.MatchString(owner) {
		return fmt.Errorf("invalid adversary id %q", owner)
	}
	rule := strings.TrimSpace(row.ProposedRule)
	if rule == "" {
		return fmt.Errorf("add a proposed rule before applying this candidate")
	}

	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, owner)
	if rel, err := filepath.Rel(root, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("adversary path escapes configured root")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if strings.TrimSpace(row.AdversaryMission) == "" {
			return fmt.Errorf("new adversary %q needs a mission before it can be created", owner)
		}
		if err := createAdversary(dir, owner, row.AdversaryMission); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if strings.TrimSpace(row.AdversaryMission) != "" {
		if err := addManifestEntry(filepath.Join(workspaceRoot, "adversarylabs.yaml"), owner, strings.TrimSpace(row.AdversaryMission)); err != nil {
			return err
		}
	}

	target := policyFile(dir)
	marker := "<!-- adversary-catalog-train:" + row.ID + " -->"
	if err := appendRule(target, marker, rule, evidenceURL(row)); err != nil {
		return err
	}
	row.Status = results.StatusApplied
	row.AppliedAt = time.Now().UTC()
	row.AppliedPath = target
	return results.SaveResult(stateRoot, row)
}

func adversaryRoot(workspaceRoot string, cfg workspace.Config) (string, error) {
	root := strings.TrimSpace(cfg.Adversaries.Root)
	if root == "" {
		return "", fmt.Errorf("apply-to-catalog requires adversaries.root")
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(workspaceRoot, root)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func policyFile(dir string) string {
	for _, rel := range []string{filepath.Join("agent", "scope.md"), filepath.Join("docs", "scope.md"), "README.md"} {
		path := filepath.Join(dir, rel)
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return filepath.Join(dir, "README.md")
}

func appendRule(path, marker, rule, evidence string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read adversary policy: %w", err)
	}
	if strings.Contains(string(raw), marker) {
		return nil
	}
	body := strings.TrimRight(string(raw), "\n")
	if !strings.Contains(body, "## Learned rules") {
		body += "\n\n## Learned rules\n"
	}
	body += "\n- " + strings.ReplaceAll(rule, "\n", " ")
	if evidence != "" {
		body += " ([evidence](" + evidence + "))"
	}
	body += "\n  " + marker + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write adversary policy: %w", err)
	}
	return nil
}

func evidenceURL(row results.Result) string {
	if strings.TrimSpace(row.CommentURL) != "" {
		return strings.TrimSpace(row.CommentURL)
	}
	return strings.TrimSpace(row.PRURL)
}

func createAdversary(dir, id, mission string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create adversary: %w", err)
	}
	title := strings.ReplaceAll(id, "-", " ")
	readme := fmt.Sprintf("# %s\n\n## Purpose\n\n%s\n", title, strings.TrimSpace(mission))
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		return fmt.Errorf("create adversary policy: %w", err)
	}
	return nil
}

func addManifestEntry(path, id, summary string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read catalog manifest: %w", err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("parse catalog manifest: %w", err)
	}
	adversaries := mappingPath(&document, "spec", "adversaries")
	if adversaries == nil || adversaries.Kind != yaml.SequenceNode {
		return fmt.Errorf("catalog manifest has no spec.adversaries list")
	}
	for _, item := range adversaries.Content {
		if valueAt(item, "id") == id {
			return nil
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	for _, pair := range [][2]string{{"id", id}, {"path", "adversaries/" + id}, {"summary", summary}} {
		entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: pair[0]}, &yaml.Node{Kind: yaml.ScalarNode, Value: pair[1]})
	}
	adversaries.Content = append(adversaries.Content, entry)
	out, err := yaml.Marshal(&document)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func mappingPath(root *yaml.Node, keys ...string) *yaml.Node {
	node := root
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	for _, key := range keys {
		if node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		node = next
	}
	return node
}

func valueAt(node *yaml.Node, key string) string {
	if node == nil || node.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1].Value
		}
	}
	return ""
}
