package initproject

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/pkg/manifest"
	projecttemplates "github.com/adversarylabs/adversary/templates"
)

const (
	DefaultSDK     = "typescript"
	DefaultVersion = "0.1.0"
)

var supportedSDKs = map[string]string{
	"typescript": "TypeScript",
}

var publishProject = publishNoReplace
var writeTemplateFile = os.WriteFile
var renderTemplate = func(data []byte, values map[string]string) ([]byte, error) {
	return []byte(applyPlaceholders(string(data), values)), nil
}

type Options struct {
	Destination string
	SDK         string
}

type Result struct {
	Location string
	SDK      string
}

func Create(opts Options) (Result, error) {
	destination := strings.TrimSpace(opts.Destination)
	if destination == "" {
		return Result{}, fmt.Errorf("destination is required")
	}

	sdk := strings.TrimSpace(opts.SDK)
	if sdk == "" {
		sdk = DefaultSDK
	}
	sdkLabel, ok := supportedSDKs[sdk]
	if !ok {
		return Result{}, fmt.Errorf("unsupported SDK %q; supported SDKs: %s", sdk, strings.Join(SupportedSDKs(), ", "))
	}

	templateRoot := sdk
	if _, err := fs.Stat(projecttemplates.FS, templateRoot); err != nil {
		if os.IsNotExist(err) {
			return Result{}, fmt.Errorf("template missing for SDK %q", sdk)
		}
		return Result{}, err
	}

	projectName := filepath.Base(filepath.Clean(destination))
	if err := manifest.ValidateProjectName(projectName); err != nil {
		return Result{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return Result{}, fmt.Errorf("create destination parent: %w", err)
	}
	if _, err := os.Lstat(destination); err == nil {
		return Result{}, fmt.Errorf("destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return Result{}, err
	}
	staging, err := os.MkdirTemp(parent, ".adversary-init-*")
	if err != nil {
		return Result{}, fmt.Errorf("create project staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	values := map[string]string{
		"name":        projectName,
		"description": "Replace with a description.",
		"version":     DefaultVersion,
		"sdk":         sdk,
	}

	err = fs.WalkDir(projecttemplates.FS, templateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(templateRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(staging, rel)
		if rel == "." {
			return nil
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := projecttemplates.FS.ReadFile(path)
		if err != nil {
			return err
		}
		data, err = renderTemplate(data, values)
		if err != nil {
			return fmt.Errorf("render template %s: %w", path, err)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return writeTemplateFile(target, data, writableFileMode(info.Mode()))
	})
	if err != nil {
		return Result{}, err
	}
	if err := os.Chmod(staging, 0755); err != nil {
		return Result{}, fmt.Errorf("set project root permissions: %w", err)
	}
	// The platform helper publishes the fully rendered sibling atomically and
	// fails if any destination was created concurrently.
	if err := publishProject(staging, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return Result{}, fmt.Errorf("destination already exists: %s", destination)
		}
		return Result{}, fmt.Errorf("publish generated project: %w", err)
	}

	abs, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Location: abs,
		SDK:      sdkLabel,
	}, nil
}

func SupportedSDKs() []string {
	sdks := make([]string, 0, len(supportedSDKs))
	for sdk := range supportedSDKs {
		sdks = append(sdks, sdk)
	}
	sort.Strings(sdks)
	return sdks
}

func RenderSuccess(w io.Writer, result Result, _ string, platform string) {
	fmt.Fprintln(w, "Creating adversary...")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "✓ Generated project")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Location")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", result.Location)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SDK")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", result.SDK)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Next steps")
	fmt.Fprintln(w)
	if platform == "windows" {
		fmt.Fprintf(w, "  Set-Location -LiteralPath %s\n", powershellQuote(result.Location))
	} else {
		fmt.Fprintf(w, "  cd %s\n", shellQuote(result.Location))
	}
	fmt.Fprintln(w, "  npm ci")
	fmt.Fprintln(w, "  npm run build")
	fmt.Fprintln(w, "  adversary run . --repo /path/to/repository")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func applyPlaceholders(input string, values map[string]string) string {
	output := input
	for key, value := range values {
		output = strings.ReplaceAll(output, "{{"+key+"}}", value)
	}
	return output
}

func writableFileMode(mode fs.FileMode) fs.FileMode {
	perm := mode.Perm()
	if perm == 0 {
		return 0644
	}
	return perm | 0600
}
