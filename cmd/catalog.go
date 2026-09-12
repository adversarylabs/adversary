package cmd

import (
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/spf13/cobra"
)

func newCatalogCommand(app *application.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "catalog",
		Short: "Manage a private adversary catalog",
	}
	command.AddCommand(newCatalogInitCommand(app))
	return command
}

func newCatalogInitCommand(app *application.App) *cobra.Command {
	return &cobra.Command{
		Use:   "init [path]",
		Short: "Generate a private adversary catalog locally",
		Long: `Generate a private adversary catalog without connecting to GitHub or
uploading source code. The destination must not already exist.`,
		Example: `  adversary catalog init
  adversary catalog init adversary-catalog
  adversary catalog init ../security/private-adversaries`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			destination := "adversary-catalog"
			if len(args) == 1 {
				destination = args[0]
			}
			result, err := app.Dependencies().Projects.InitCatalog(application.CatalogInitOptions{
				Destination: destination,
			})
			if err != nil {
				return err
			}
			app.Dependencies().Projects.RenderCatalogInit(cmd.OutOrStdout(), result)
			return nil
		},
	}
}
