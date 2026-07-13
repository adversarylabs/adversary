package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/spf13/cobra"
)

type packOptions struct {
	builder string
	name    string
	format  string
	json    bool
	check   bool
}

func newPackCommand(app *application.App) *cobra.Command {
	opts := &packOptions{builder: "local"}
	cmd := &cobra.Command{
		Use:   "pack <path>",
		Short: "Package the current adversary into the local content-addressable store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, opts.json)
			if err != nil {
				return err
			}
			if opts.builder != "local" && opts.builder != "docker" {
				return fmt.Errorf("--builder must be local or docker")
			}
			if opts.json {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			if opts.check {
				checked, err := app.Dependencies().Projects.Check(pack.Options{Dir: args[0], NameOverride: opts.name, Builder: opts.builder})
				if err != nil {
					return err
				}
				files, warnings := packOutputDetails(checked.Files, checked.Warnings)
				if format == "json" {
					return writeJSON(cmd.OutOrStdout(), "pack-check", packCheckDTO{Name: checked.Name, Version: checked.Version, Runtime: checked.Runtime, Files: files, Warnings: warnings})
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Package check passed (no build or repository changes).")
				fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\nVersion: %s\nRuntime: %s\nFiles:\n", checked.Name, checked.Version, checked.Runtime)
				writePackDetails(cmd.OutOrStdout(), files, warnings)
				return nil
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Packing adversary...")
			artifact, err := app.Dependencies().Projects.Pack(cmd.Context(), pack.Options{Dir: args[0], NameOverride: opts.name, Build: true, Builder: opts.builder, Stdout: cmd.ErrOrStderr(), Stderr: cmd.ErrOrStderr()})
			if err != nil {
				return err
			}
			resolver := app.Dependencies().Resolver
			requested := artifact.Name + ":" + artifact.Version
			unified, importErr := resolver.ImportPacked(artifact, requested)
			if err := errors.Join(importErr, artifact.Close()); err != nil {
				return err
			}
			canonical, err := resolver.CanonicalReferenceFor(unified.Digest, requested)
			if err != nil {
				return fmt.Errorf("read committed canonical reference: %w", err)
			}
			canonicalRef, err := app.Dependencies().References.Parse(canonical)
			if err != nil {
				return fmt.Errorf("read committed canonical reference: %w", err)
			}
			canonicalRef.Tag, canonicalRef.Digest = oci.DefaultTag, ""
			latest := canonicalRef.Locator()
			if err := registerExactRef(resolver, latest, unified.Digest); err != nil {
				return err
			}
			if format == "json" {
				requirement := ""
				if artifact.RuntimeName != "" {
					requirement = artifact.RuntimeName + "@" + artifact.RuntimeVersion
				}
				files, warnings := packOutputDetails(artifact.Files, pack.WarningsForFiles(artifact.Files))
				if opts.json {
					return writeJSON(cmd.OutOrStdout(), "pack", legacyPackV1DTO{Name: artifact.ManifestName, Version: artifact.Version, Runtime: artifact.Runtime, RuntimeRequirement: requirement, Digest: unified.Digest, CanonicalReference: requested, SizeBytes: artifact.Size, References: []string{requested, artifact.Name + ":" + oci.DefaultTag}})
				}
				return writeJSONVersion(cmd.OutOrStdout(), 2, "pack", packDTO{Name: artifact.ManifestName, Version: artifact.Version, Runtime: artifact.Runtime, RuntimeRequirement: requirement, Digest: unified.Digest, CanonicalReference: canonical, SizeBytes: artifact.Size, References: []string{canonical, latest}, Files: files, Warnings: warnings})
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\n", artifact.ManifestName)
			fmt.Fprintf(cmd.OutOrStdout(), "Version: %s\n", artifact.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "Runtime: %s\n", artifact.Runtime)
			if artifact.RuntimeName != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Runtime Requirement: %s@%s\n", artifact.RuntimeName, artifact.RuntimeVersion)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Digest: %s\n", unified.Digest)
			fmt.Fprintf(cmd.OutOrStdout(), "Canonical reference: %s\nUnified digest: %s\n", canonical, unified.Digest)
			fmt.Fprintf(cmd.OutOrStdout(), "Size: %s\n", humanSize(artifact.Size))
			files, warnings := packOutputDetails(artifact.Files, pack.WarningsForFiles(artifact.Files))
			fmt.Fprintln(cmd.OutOrStdout(), "Files:")
			writePackDetails(cmd.OutOrStdout(), files, warnings)
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Stored locally as:")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), canonical)
			fmt.Fprintln(cmd.OutOrStdout(), latest)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.builder, "builder", "local", "build mechanism: local or docker")
	cmd.Flags().StringVar(&opts.name, "name", "", "override the local artifact name")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.json, "json", false, "deprecated alias for --format json")
	cmd.Flags().BoolVar(&opts.check, "check", false, "validate and inventory without building or storing")
	return cmd
}

func packOutputDetails(filesIn []pack.File, warningsIn []pack.Warning) ([]packFileDTO, []packWarningDTO) {
	files := make([]packFileDTO, 0, len(filesIn))
	warnings := make([]packWarningDTO, 0, len(warningsIn))
	for _, f := range filesIn {
		files = append(files, packFileDTO{f.Path, f.Size, f.SHA256, fmt.Sprintf("%#o", f.Mode)})
	}
	for _, w := range warningsIn {
		warnings = append(warnings, packWarningDTO{w.Path, w.Kind, w.Message})
	}
	return files, warnings
}
func writePackDetails(w io.Writer, files []packFileDTO, warnings []packWarningDTO) {
	for _, f := range files {
		fmt.Fprintf(w, "  %s  %d bytes  %s  mode %s\n", f.Path, f.SizeBytes, f.SHA256, f.Mode)
	}
	for _, warning := range warnings {
		fmt.Fprintf(w, "WARNING [%s] %s: %s\n", warning.Kind, warning.Path, warning.Message)
	}
}
