package cmd

import (
	"errors"
	"fmt"

	"github.com/adversarylabs/adversary/internal/application"
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
			validated, err := app.Dependencies().Projects.Validate(cmd.Context(), args[0], app.Dependencies().Resolver)
			if err != nil {
				var projectErr *application.ProjectError
				if errors.As(err, &projectErr) {
					return fail(projectErr.Code, projectErr.Path, projectErr)
				}
				return fail("invalid_project", args[0], err)
			}
			result := validateDTO{Path: validated.Path, ManifestVersion: "adversary.manifest.v1", Name: validated.Name, Runtime: validated.Runtime, Status: "valid", Errors: []validateIssue{}}
			if format == "json" {
				return writeJSON(cmd.OutOrStdout(), "validate", result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Valid adversary.manifest.v1: %s\nName: %s\nRuntime: %s\n", validated.Path, validated.Name, validated.Runtime)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	return cmd
}
