package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newSearchCommand(app *application.App, apiURL, profile *string) *cobra.Command {
	var format string
	var legacyJSON bool
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search Adversary Labs adversaries",
		Example: `  adversary search dockerfile
  adversary search security-reviewer`,
		Args: cobra.ExactArgs(1),
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
			var token string
			auth, ok, err := scopedAuth(store, valueOf(apiURL), valueOf(profile), deps.RegistryHost)
			if err != nil {
				return err
			}
			if ok {
				token = auth.Token
			}
			client := deps.API.New(valueOf(apiURL))
			results, err := client.Search(cmd.Context(), args[0], token)
			if err != nil {
				return err
			}
			if resolved == "json" {
				items := make([]searchResultDTO, 0, len(results))
				for _, r := range results {
					items = append(items, searchResultDTO{r.Name, r.Version, r.Description, r.Reference})
				}
				return writeJSON(cmd.OutOrStdout(), "search", searchDTO{Results: items})
			}
			if len(results) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No adversaries found.")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tDESCRIPTION")
			for _, result := range results {
				name := result.Name
				if result.Reference != "" {
					name = result.Reference
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", sanitizeCell(name), sanitizeCell(result.Version), sanitizeCell(result.Description))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&legacyJSON, "json", false, "deprecated alias for --format json")
	return cmd
}
