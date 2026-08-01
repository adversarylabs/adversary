package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

type listOptions struct {
	json      bool
	format    string
	installed bool
	catalog   bool
	outdated  bool
}

func newListCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	opts := &listOptions{}
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List adversaries available to you (local store and registry)",
		Long: `List adversaries from the local store and the remote catalog you can access.

Each name appears once. STATUS is one of:
  installed  present in the local store (at or ahead of the catalog version)
  catalog    in the remote catalog but not installed locally
  outdated   installed, but the catalog has a newer version (LATEST)

Flags filter after status is computed, so --installed still shows outdated rows.

Retired official paths (…/adversarylabs/… and flat …/library/go-cli style
packs) are hidden. Domain catalog ids (go/cli, security/secrets, …) remain.

Remote entries require network access and, for private catalog results, login.
If the remote catalog is unavailable, local adversaries are still listed
(without outdated detection).`,
		Example: `  adversary list
  adversary list --installed
  adversary list --catalog
  adversary list --outdated
  adversary list --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandFormat(cmd, opts.format, opts.json)
			if err != nil {
				return err
			}
			if opts.json {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}

			// Legacy --json keeps the previous local-only repository record array for scripts.
			if opts.json {
				entries, err := app.Dependencies().Resolver.Entries(10000)
				if err != nil {
					return err
				}
				items := make([]legacyArtifactV0DTO, 0, len(entries))
				for _, e := range entries {
					items = append(items, legacyArtifact(e.CanonicalReference, e.Digest, e.Record))
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(items)
			}

			scope := inventoryScope{
				Installed: opts.installed,
				Catalog:   opts.catalog,
				Outdated:  opts.outdated,
			}
			items, err := collectInventory(cmd.Context(), app, valueOf(apiURL), valueOf(profile), "", cmd.ErrOrStderr(), scope)
			if err != nil {
				return err
			}
			if format == "json" {
				entries, err := app.Dependencies().Resolver.Entries(10000)
				if err != nil {
					return err
				}
				artifacts, err := localArtifactsForListJSON(app, entries)
				if err != nil {
					return err
				}
				return writeJSON(cmd.OutOrStdout(), "list", listDTO{
					Artifacts: artifacts,
					Results:   inventoryToSearchDTOs(items),
				})
			}
			return writeInventoryText(cmd.OutOrStdout(), items)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print local adversaries as JSON")
	cmd.Flags().StringVar(&opts.format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&opts.installed, "installed", false, "show only installed adversaries (includes outdated)")
	cmd.Flags().BoolVar(&opts.catalog, "catalog", false, "show only catalog adversaries that are not installed")
	cmd.Flags().BoolVar(&opts.outdated, "outdated", false, "show only outdated installed adversaries")
	return cmd
}
