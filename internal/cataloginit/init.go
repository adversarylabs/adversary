package cataloginit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Options struct {
	Destination string
}

type Result struct {
	Location string
}

var files = map[string]string{
	"adversarylabs.yaml": `apiVersion: adversarylabs.dev/v1alpha1
kind: AdversaryCatalog
metadata:
  name: private-adversaries
spec:
  adversaries: []
`,
	"README.md": `# Private adversary catalog

This repository is the source of truth for your organization's private
AdversaryLabs adversaries. AdversaryLabs proposes learned changes through pull
requests so your team can review, test, merge, and revert them with normal Git
workflows.

## Layout

- **adversarylabs.yaml** declares the catalog and its adversaries.
- **adversaries/** contains one directory per private adversary.
- **evaluations/** contains regression examples used to validate proposals.
- **exceptions/** contains explicitly scoped exceptions to learned rules.

Connect this private repository from the Private library in AdversaryLabs.
`,
	"adversaries/.gitkeep": "",
	"evaluations/.gitkeep": "",
	"exceptions/.gitkeep":  "",
}

func Create(opts Options) (Result, error) {
	destination := strings.TrimSpace(opts.Destination)
	if destination == "" {
		destination = "adversary-catalog"
	}
	if _, err := os.Lstat(destination); err == nil {
		return Result{}, fmt.Errorf("destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return Result{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, fmt.Errorf("create destination parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".adversary-catalog-init-*")
	if err != nil {
		return Result{}, fmt.Errorf("create catalog staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	for name, content := range files {
		target := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return Result{}, fmt.Errorf("write %s: %w", name, err)
		}
	}
	if err := os.Rename(staging, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return Result{}, fmt.Errorf("destination already exists: %s", destination)
		}
		return Result{}, fmt.Errorf("publish generated catalog: %w", err)
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, err
	}
	return Result{Location: abs}, nil
}

func RenderSuccess(w io.Writer, result Result, platform string) {
	fmt.Fprintln(w, "Creating private adversary catalog...")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "✓ Generated catalog")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Location")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", result.Location)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Next steps")
	fmt.Fprintln(w)
	if platform == "windows" {
		fmt.Fprintf(w, "  Set-Location -LiteralPath %s\n", powershellQuote(result.Location))
	} else {
		fmt.Fprintf(w, "  cd %s\n", shellQuote(result.Location))
	}
	fmt.Fprintln(w, "  git init")
	fmt.Fprintln(w, "  git add .")
	fmt.Fprintln(w, `  git commit -m "Initialize private adversary catalog"`)
	fmt.Fprintln(w, "  Create a private GitHub repository, push this directory, then link it from /library.")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
