package cmd

import (
	"fmt"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newWhoamiCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the current Adversary Labs login",
		Example: `  adversary whoami
  adversary whoami --api-url http://localhost:3000/api`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := commandFormat(cmd, format, legacyJSON)
			if err != nil {
				return err
			}
			if legacyJSON {
				fmt.Fprintln(cmd.ErrOrStderr(), "Warning: --json is deprecated; use --format json.")
			}
			deps := app.Dependencies()
			store := deps.Auth
			auth, ok, err := scopedAuth(store, valueOf(apiURL), valueOf(profile), deps.RegistryHost)
			if err != nil {
				return err
			}
			if !ok {
				if resolved == "json" {
					return writeJSON(cmd.OutOrStdout(), "whoami", whoamiDTO{Authenticated: false})
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Not logged in.")
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout(), "Run `adversary login` to authenticate with Adversary Labs.")
				return nil
			}
			client := deps.API.New(valueOf(apiURL))
			account, err := client.Whoami(cmd.Context(), auth.Token)
			if err != nil {
				return err
			}
			if resolved == "json" {
				return writeJSON(cmd.OutOrStdout(), "whoami", whoamiData(account))
			}
			printWhoami(cmd.OutOrStdout(), account)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}
