package cmd

import (
	"fmt"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newSearchCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search adversaries available to you (local store and registry)",
		Long: `Search the local store and remote catalog you can access.

With no query, search lists the same combined inventory as adversary list.
With a query, results are filtered by name, version, reference, description, or digest.

Each name appears once with its newest version (semver). Older local installs
remain usable via an explicit reference; they are just omitted from this listing.

Retired official paths (…/adversarylabs/… and flat …/library/go-cli style
packs) are hidden. Domain catalog ids (go/cli, security/secrets, …) remain.

Remote entries require network access and, for private catalog results, login.
If the remote catalog is unavailable, local adversaries are still searched.`,
		Example: `  adversary search
  adversary search dockerfile
  adversary search security-reviewer
  adversary search go/cli`,
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
			items, err := collectInventory(cmd.Context(), app, valueOf(apiURL), valueOf(profile), query, cmd.ErrOrStderr())
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
	return cmd
}
