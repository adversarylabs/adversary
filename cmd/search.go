package cmd

import (
	"fmt"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newSearchCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	var installed, catalog, outdated bool
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search adversaries available to you (local store and registry)",
		Long: `Search the local store and remote catalog you can access.

With no query, search lists the same combined inventory as adversary list.
With a query, results are filtered by name, version, reference, description, status, or digest.

Each name appears once. STATUS is installed, catalog, or outdated (see adversary list).

Flags filter after status is computed, so --installed still shows outdated rows.

Team-owned adversarylabs/* source packages are hidden from catalog inventory.
Promoted library/* packages appear under their catalog ids (go/cli,
security/secrets, …).

Remote entries require network access and, for private catalog results, login.
If the remote catalog is unavailable, local adversaries are still searched.`,
		Example: `  adversary search
  adversary search dockerfile
  adversary search go/cli
  adversary search --installed
  adversary search --catalog secrets
  adversary search --outdated`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, legacyJSON)
			if err != nil {
				return err
			}
			if legacyJSON {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			query := ""
			if len(args) > 0 {
				query = args[0]
			}
			scope := inventoryScope{
				Installed: installed,
				Catalog:   catalog,
				Outdated:  outdated,
			}
			items, err := collectInventory(cmd.Context(), app, valueOf(apiURL), valueOf(profile), query, cmd.ErrOrStderr(), scope)
			if err != nil {
				return err
			}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "search", searchDTO{Results: inventoryToSearchDTOs(items)})
			}
			return writeInventoryText(cmd.OutOrStdout(), items)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	cmd.Flags().BoolVar(&installed, "installed", false, "show only installed adversaries (includes outdated)")
	cmd.Flags().BoolVar(&catalog, "catalog", false, "show only catalog adversaries that are not installed")
	cmd.Flags().BoolVar(&outdated, "outdated", false, "show only outdated installed adversaries")
	return cmd
}
