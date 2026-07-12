package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

type listOptions struct {
	json   bool
	format string
}

func newListCommand(app *application.App) *cobra.Command {
	opts := &listOptions{}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List locally stored adversaries",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, opts.json)
			if err != nil {
				return err
			}
			if opts.json {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			entries, err := app.Dependencies().Resolver.Entries(10000)
			if err != nil {
				return err
			}
			if format == "json" {
				if opts.json {
					items := make([]legacyArtifactV0DTO, 0, len(entries))
					for _, e := range entries {
						items = append(items, legacyArtifact(e.CanonicalReference, e.Digest, e.Record))
					}
					return json.NewEncoder(cmd.OutOrStdout()).Encode(items)
				}
				items := make([]artifactDTO, 0, len(entries))
				for _, e := range entries {
					files, err := app.Dependencies().Resolver.Inventory(e.Record)
					if err != nil {
						return fmt.Errorf("read stored artifact inventory for %s: %w", e.CanonicalReference, err)
					}
					items = append(items, storedArtifactDTOWithFiles(e.CanonicalReference, e.Digest, e.Record, files))
				}
				return writeJSON(cmd.OutOrStdout(), "list", listDTO{Artifacts: items})
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No local adversaries found.")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tCANONICAL REFERENCE\tDIGEST")
			for _, entry := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", entry.Record.Name, entry.Record.Version, entry.CanonicalReference, shortDigest(entry.Digest))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print local adversaries as JSON")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	return cmd
}
