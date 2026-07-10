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
	// Mkdir is the atomic ownership claim. From here on, cleanup is restricted to
	// the path this invocation exclusively created.
	if err := os.Mkdir(destination, 0755); err != nil {
		if os.IsExist(err) {
			return Result{}, fmt.Errorf("destination already exists: %s", destination)
		}
		return Result{}, fmt.Errorf("claim destination: %w", err)
	}
	owned := true
	defer func() {
		if owned {
			_ = os.RemoveAll(destination)
		}
	}()
	values := map[string]string{
		"name":        projectName,
		"description": "Replace with a description.",
		"version":     DefaultVersion,
		"sdk":         sdk,
	}

	err := fs.WalkDir(projecttemplates.FS, templateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(templateRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
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
		data = []byte(applyPlaceholders(string(data), values))
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, writableFileMode(info.Mode()))
	})
	if err != nil {
		return Result{}, err
	}

	abs, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, err
	}

	owned = false
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

func RenderSuccess(w io.Writer, result Result, _ string) {
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
	fmt.Fprintf(w, "  cd %s\n", shellQuote(result.Location))
	fmt.Fprintln(w, "  npm install")
	fmt.Fprintln(w, "  npm run build")
	fmt.Fprintln(w, "  adversary run . --repo /path/to/repository")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
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
