package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/adversarylabs/adversary/internal/application"
	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	traininbox "github.com/adversarylabs/adversary/internal/train/inbox"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/spf13/cobra"
)

func newCatalogCommand(app *application.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "catalog",
		Short: "Manage a private adversary catalog",
	}
	command.AddCommand(newCatalogInitCommand(app))
	command.AddCommand(newCatalogTrainCommand(app))
	return command
}

func newCatalogTrainCommand(app *application.App) *cobra.Command {
	command := newTrainRunCommand(app)
	command.Use = "train"
	command.Short = "Triage review history into the local catalog training inbox"
	command.Long = `Collect and triage human pull-request review history, discard conversation
noise, route reusable concerns to a private adversary when there is enough evidence, and save
plausible unmatched concerns as unassigned candidates in the catalog's private local SQLite inbox,
then exit without prompting. Discovery state is durable, so interrupted and repeated scans resume safely.

This command never uploads training evidence or creates issues. Review results
later with "adversary catalog train review".`
	command.Example = `  adversary catalog train
  adversary catalog train --source-repo acme/api --source-repo acme/web
  adversary catalog train --author alice --exclude-author dependabot[bot]
  adversary catalog train --max-prs 25
  adversary catalog train review`
	if flag := command.Flags().Lookup("no-issues"); flag != nil {
		_ = flag.Value.Set("true")
		flag.DefValue = "true"
		flag.Hidden = true
	}
	for _, name := range []string{"all-adversaries", "cycle-adversaries", "fixture", "owner", "pr", "repo"} {
		if flag := command.Flags().Lookup(name); flag != nil {
			flag.Hidden = true
		}
	}
	if flag := command.Flags().Lookup("path"); flag != nil {
		flag.Usage = "catalog workspace with adversary.train.yaml"
	}
	command.AddCommand(newCatalogTrainReviewCommand())
	command.AddCommand(newCatalogTrainInspectCommand())
	command.AddCommand(newCatalogTrainDecisionCommand("accept", results.Accept))
	command.AddCommand(newCatalogTrainDecisionCommand("dismiss", results.Dismiss))
	return command
}

func newCatalogTrainInspectCommand() *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   "inspect <id>",
		Short: "Show the triage evidence for one catalog candidate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			row, err := results.Get(state, args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), results.FormatCatalogInspect(row))
			return nil
		},
	}
	command.Flags().StringVar(&path, "path", "", "catalog workspace with adversary.train.yaml")
	return command
}

func newCatalogTrainReviewCommand() *cobra.Command {
	var path, pkg string
	var all bool
	command := &cobra.Command{
		Use:     "review",
		Aliases: []string{"list", "ls"},
		Short:   "List locally stored catalog training results awaiting review",
		RunE: func(cmd *cobra.Command, args []string) error {
			reviewPath := path
			state, err := resolveStateDir(path)
			if err != nil {
				if path != "" {
					return err
				}
				dataRoot, dataErr := internalpaths.DataDir()
				if dataErr != nil {
					return err
				}
				catalogs, pendingErr := traininbox.Pending(dataRoot)
				if pendingErr != nil || len(catalogs) == 0 {
					return err
				}
				if len(catalogs) > 1 {
					fmt.Fprintln(cmd.OutOrStdout(), "Training results are ready in multiple catalogs:")
					for _, catalog := range catalogs {
						fmt.Fprintf(cmd.OutOrStdout(), "  %d  %s\n", catalog.Pending, filepath.Dir(catalog.ConfigPath))
					}
					fmt.Fprintln(cmd.OutOrStdout(), "\nReview one with: adversary catalog train review --path <catalog>")
					return nil
				}
				state = catalogs[0].StateRoot
				reviewPath = filepath.Dir(catalogs[0].ConfigPath)
			}
			status := results.StatusNew
			if all {
				status = ""
			}
			rows, err := results.List(state, pkg, status)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprint(out, results.FormatCatalogListTable(rows))
			if len(rows) > 0 {
				pathFlag := ""
				if reviewPath != "" {
					pathFlag = fmt.Sprintf(" --path %q", reviewPath)
				}
				fmt.Fprintln(out, "Review without changing tracked catalog files:")
				fmt.Fprintf(out, "  adversary catalog train inspect <id>%s\n", pathFlag)
				fmt.Fprintf(out, "  adversary catalog train accept <id>%s\n", pathFlag)
				fmt.Fprintf(out, "  adversary catalog train dismiss <id>%s\n", pathFlag)
			}
			return nil
		},
	}
	command.Flags().StringVar(&path, "path", "", "catalog workspace with adversary.train.yaml")
	command.Flags().StringVar(&pkg, "adversary", "", "filter by private adversary id")
	command.Flags().BoolVar(&all, "all", false, "include accepted, dismissed, caught, and applied results")
	return command
}

func newCatalogTrainDecisionCommand(name string, decide func(string, string) error) *cobra.Command {
	var path string
	command := &cobra.Command{
		Use:   name + " <id> [<id>...]",
		Short: map[string]string{"accept": "Approve result(s) for a future catalog change", "dismiss": "Dismiss result(s) without changing the catalog"}[name],
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			for _, id := range args {
				if err := decide(state, id); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", id, name+"ed")
			}
			return nil
		},
	}
	command.Flags().StringVar(&path, "path", "", "catalog workspace with adversary.train.yaml")
	return command
}

func newCatalogInitCommand(app *application.App) *cobra.Command {
	return &cobra.Command{
		Use:   "init [path]",
		Short: "Generate a private adversary catalog locally",
		Long: `Generate a private adversary catalog without connecting to GitHub or
uploading source code. The catalog includes a focused set of editable starter
adversaries for common production concerns. The destination must not already
exist.`,
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
