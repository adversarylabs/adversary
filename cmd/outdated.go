package cmd

import (
	"github.com/doomerlabs/doomer/internal/application"
	"github.com/spf13/cobra"
)

func newOutdatedCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "outdated",
		Short: "List installed adversaries with a newer catalog version",
		Long: `List adversaries that are installed locally but have a newer version in the remote catalog.

This is equivalent to doomer list --outdated. Requires network access to the
catalog API; if the remote catalog is unavailable, the list is empty (with a warning).

Upgrade with: doomer pull <name>`,
		Example: `  doomer outdated
  doomer outdated --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, false)
			if err != nil {
				return err
			}
			items, err := collectInventory(
				cmd.Context(),
				app,
				valueOf(apiURL),
				valueOf(profile),
				"",
				cmd.ErrOrStderr(),
				inventoryScope{Outdated: true},
			)
			if err != nil {
				return err
			}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "outdated", searchDTO{Results: inventoryToSearchDTOs(items)})
			}
			return writeInventoryText(cmd.OutOrStdout(), items)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}
