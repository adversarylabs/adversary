package cmd

import (
	"errors"
	"fmt"
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
			fmt.Fprintln(cmd.ErrOrStderr(), "Packing adversary...")
			artifact, err := pack.Create(cmd.Context(), pack.Options{Dir: args[0], NameOverride: opts.name, Build: true, Builder: opts.builder, Stdout: cmd.ErrOrStderr(), Stderr: cmd.ErrOrStderr(), Streaming: true})
			if err != nil {
				return err
			}
			resolver := app.Dependencies().Resolver
			canonical := artifact.Name + ":" + artifact.Version
			unified, importErr := resolver.ImportPacked(artifact, canonical)
			if err := errors.Join(importErr, artifact.Close()); err != nil {
				return err
			}
			latest := artifact.Name + ":" + oci.DefaultTag
			if err := registerExactRef(resolver, latest, unified.Digest); err != nil {
				return err
			}
			if format == "json" {
				requirement := ""
				if artifact.RuntimeName != "" {
					requirement = artifact.RuntimeName + "@" + artifact.RuntimeVersion
				}
				return writeJSON(cmd.OutOrStdout(), "pack", packDTO{artifact.ManifestName, artifact.Version, artifact.Runtime, requirement, unified.Digest, canonical, artifact.Size, []string{canonical, latest}})
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
	return cmd
}
