package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/spf13/cobra"
)

type validateOptions struct{ format string }

type validateDTO struct {
	Path            string          `json:"path"`
	ManifestVersion string          `json:"manifestVersion"`
	Name            string          `json:"name"`
	Runtime         string          `json:"runtime"`
	Status          string          `json:"status"`
	Errors          []validateIssue `json:"errors"`
}

type validateIssue struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func newValidateCommand(app *application.App) *cobra.Command {
	opts := &validateOptions{}
	cmd := &cobra.Command{
		Use:   "validate <path-or-reference>",
		Short: "Validate an adversary project with the canonical v1 manifest parser",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := validateFormat(opts.format, false)
			if err != nil {
				return err
			}
			fail := func(code, path string, cause error) error {
				if format == "json" {
					data := validateDTO{Path: path, ManifestVersion: "adversary.manifest.v1", Status: "invalid", Errors: []validateIssue{{Code: code, Path: path, Message: cause.Error()}}}
					if writeErr := writeJSON(cmd.OutOrStdout(), "validate", data); writeErr != nil {
						return writeErr
					}
				}
				return cause
			}
			path, err := filepath.Abs(args[0])
			if err != nil {
				return fail("invalid_path", args[0], err)
			}
			if _, statErr := os.Stat(path); statErr != nil && os.IsNotExist(statErr) {
				resolution, resolveErr := app.Dependencies().Resolver.Resolve(cmd.Context(), args[0])
				if resolveErr != nil {
					return fail("unresolved_reference", args[0], fmt.Errorf("validate path or reference %q: %w", args[0], resolveErr))
				}
				path = resolution.Path
			}
			root := path
			if info, statErr := os.Stat(path); statErr != nil {
				return fail("unreadable_path", path, fmt.Errorf("validate %q: %w", args[0], statErr))
			} else if !info.IsDir() {
				root = filepath.Dir(path)
			} else {
				path = filepath.Join(path, manifest.FileName)
			}
			m, err := manifest.Load(path)
			if err != nil {
				return fail("invalid_manifest", path, fmt.Errorf("validate manifest v1 %q: %w", path, err))
			}
			if err := m.ValidateProject(root); err != nil {
				return fail("invalid_project", root, fmt.Errorf("validate project v1 %q: %w", root, err))
			}
			result := validateDTO{Path: path, ManifestVersion: "adversary.manifest.v1", Name: m.Name, Runtime: m.Runtime.Name, Status: "valid", Errors: []validateIssue{}}
			if format == "json" {
				return writeJSON(cmd.OutOrStdout(), "validate", result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Valid adversary.manifest.v1: %s\nName: %s\nRuntime: %s\n", path, m.Name, m.Runtime.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	return cmd
}
