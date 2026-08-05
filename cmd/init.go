package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

type initOptions struct {
	sdk  string
	path string // parent directory; destination becomes path/name
}

func newInitCommand(app *application.App) *cobra.Command {
	opts := &initOptions{}

	cmd := &cobra.Command{
		Use:   "init <name>",
		Short: "Create a new adversary project",
		Long: `Create a new adversary project from an SDK template.

<name> is the project directory name (and default package id). Use --path to
place it under a parent directory instead of the current working directory.

  adversary init my-adversary
  adversary init my-adversary --path ../packages
  adversary init person-mitchellh --path /Users/me/src/github.com/adversarylabs`,
		Example: `  adversary init my-adversary
  adversary init my-adversary --sdk typescript
  adversary init my-adversary --path ../packages
  adversary init person-mitchellh --path ~/go/src/github.com/adversarylabs`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest, err := resolveInitDestination(args[0], opts.path)
			if err != nil {
				return err
			}
			result, err := app.Dependencies().Projects.Init(application.ProjectInitOptions{
				Destination: dest,
				SDK:         opts.sdk,
			})
			if err != nil {
				return err
			}
			app.Dependencies().Projects.RenderInit(cmd.OutOrStdout(), result, dest)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.sdk, "sdk", application.DefaultProjectSDK, "SDK template to use: typescript")
	cmd.Flags().StringVar(&opts.path, "path", "", "parent directory for the project (default: current directory)")

	return cmd
}

// resolveInitDestination joins optional parent path with the project name.
// If name is already an absolute path or contains path separators and --path
// is empty, name is used as the full destination (historical behavior).
func resolveInitDestination(name, parent string) (string, error) {
	name = strings.TrimSpace(name)
	parent = strings.TrimSpace(parent)
	if name == "" {
		return "", fmt.Errorf("project name is required")
	}
	if parent == "" {
		return name, nil
	}
	// Avoid double-nesting: if name already looks like a path, reject with --path.
	if filepath.IsAbs(name) || strings.Contains(name, string(filepath.Separator)) || strings.Contains(name, "/") || strings.Contains(name, `\`) {
		return "", fmt.Errorf("use either a simple name with --path, or a full destination without --path (got name %q and --path %q)", name, parent)
	}
	return filepath.Join(parent, name), nil
}
