package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	trainadversaries "github.com/adversarylabs/adversary/internal/train/adversaries"
	"github.com/adversarylabs/adversary/internal/train/catalogapply"
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

This command never uploads training evidence to Adversary Labs or creates issues.
It sends bounded review evidence to the model provider you configure for triage.
Review results later with "adversary catalog train review".`
	command.Example = `  adversary catalog train --model codex/gpt-5.6-luna
  adversary catalog train --source-repo acme/api --source-repo acme/web
  adversary catalog train --since 2025-09-12 --all-history
  adversary catalog train --model-provider cloudflare --model @cf/meta/llama-3.3-70b-instruct-fp8-fast
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
	command.AddCommand(newCatalogTrainInspectCommand(app))
	command.AddCommand(newCatalogTrainDecisionCommand("accept", results.Accept))
	command.AddCommand(newCatalogTrainDecisionCommand("dismiss", results.Dismiss))
	command.AddCommand(newTrainResetCommand(app))
	return command
}

func newCatalogTrainInspectCommand(app *application.App) *cobra.Command {
	var path string
	var all bool
	var modelProvider, model string
	command := &cobra.Command{
		Use:   "inspect [id]",
		Short: "Review candidates in a local browser or inspect one in the terminal",
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) != 0 {
					return fmt.Errorf("use either --all or one candidate id")
				}
				return nil
			}
			return cobra.MaximumNArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			if all {
				deps := app.Dependencies()
				if deps.TTY == nil || !deps.TTY.Interactive(cmd.InOrStdin()) {
					return fmt.Errorf("catalog train inspect --all requires an interactive terminal")
				}
				rows, err := results.List(state, "", results.StatusNew)
				if err != nil {
					return err
				}
				adversaryIDs, err := catalogAdversaryIDs(path)
				if err != nil {
					return err
				}
				return walkCatalogTrainCandidates(cmd, state, rows, adversaryIDs)
			}
			if len(args) == 0 {
				adversaryIDs, err := catalogAdversaryIDs(path)
				if err != nil {
					return err
				}
				reviewer, ok := app.Dependencies().Runtime.(application.CatalogReviewRuntime)
				if !ok {
					return fmt.Errorf("local browser review is unavailable in this runtime; use catalog train inspect --all")
				}
				var assist func(context.Context, application.CatalogAssistRequest) (application.CatalogAssistResult, error)
				var planner catalogapply.ChangePlanner
				if modelRuntime, ok := app.Dependencies().Runtime.(application.ModelReviewRuntime); ok {
					assist = catalogReviewAssist(modelRuntime, modelProvider, model)
					planner = catalogChangePlanner(modelRuntime, modelProvider, model)
				}
				configPath, cfg, err := resolveTrainConfig(path)
				if err != nil {
					return err
				}
				return reviewer.ReviewCatalog(cmd.Context(), application.CatalogReviewOptions{
					StateRoot: state, Adversaries: adversaryIDs, Output: cmd.OutOrStdout(),
					Assist: assist,
					Apply: func(ctx context.Context, id string) error {
						return catalogapply.ApplyPlanned(ctx, state, filepath.Dir(configPath), cfg, id, planner)
					},
					CreatePR: func(ctx context.Context, id string) error {
						return catalogapply.CreatePullRequestPlanned(ctx, state, filepath.Dir(configPath), cfg, id, planner)
					},
				})
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
	command.Flags().BoolVar(&all, "all", false, "walk interactively through every new candidate in the terminal")
	command.Flags().StringVar(&modelProvider, "model-provider", "", "AI assist model provider (or ADVERSARY_MODEL_PROVIDER)")
	command.Flags().StringVar(&model, "model", "", "AI assist model (or ADVERSARY_MODEL)")
	return command
}

func catalogAdversaryIDs(path string) ([]string, error) {
	configPath, cfg, err := resolveTrainConfig(path)
	if err != nil {
		return nil, err
	}
	root := cfg.Adversaries.Root
	if !filepath.IsAbs(root) {
		root = filepath.Join(filepath.Dir(configPath), root)
	}
	packages, err := trainadversaries.DiscoverCatalogRoot(root)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(packages))
	for _, pkg := range packages {
		ids = append(ids, pkg.ID)
	}
	sort.Strings(ids)
	return ids, nil
}

func walkCatalogTrainCandidates(cmd *cobra.Command, state string, rows []results.Result, adversaryIDs []string) error {
	out := cmd.OutOrStdout()
	if len(rows) == 0 {
		fmt.Fprintln(out, "No new catalog training candidates.")
		return nil
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	accepted, dismissed, skipped := 0, 0, 0
	for i, row := range rows {
		fmt.Fprintf(out, "\nCandidate %d of %d\n%s\n", i+1, len(rows), strings.Repeat("=", 72))
		fmt.Fprint(out, results.FormatCatalogInspect(row))
		for {
			fmt.Fprint(out, "\n[a]ccept  [d]ismiss  [r]eassign  [e]dit rule  [s]kip  [q]uit > ")
			choice, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(choice)) {
			case "a", "accept":
				if err := results.Accept(state, row.ID); err != nil {
					return err
				}
				accepted++
				fmt.Fprintln(out, "accepted")
			case "d", "dismiss":
				if err := results.Dismiss(state, row.ID); err != nil {
					return err
				}
				dismissed++
				fmt.Fprintln(out, "dismissed")
			case "r", "reassign":
				owner, err := promptCatalogAdversary(out, reader, adversaryIDs)
				if err != nil {
					return err
				}
				if owner == "" {
					fmt.Fprintln(out, "reassignment canceled")
					continue
				}
				if err := results.ReassignCatalogCandidate(state, row.ID, owner); err != nil {
					return err
				}
				row.Package = owner
				fmt.Fprintf(out, "reassigned to %s\n", owner)
				continue
			case "e", "edit":
				fmt.Fprintf(out, "Current rule: %s\nNew rule (single line; blank cancels) > ", row.ProposedRule)
				rule, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					return err
				}
				rule = strings.TrimSpace(rule)
				if rule == "" {
					fmt.Fprintln(out, "edit canceled")
					continue
				}
				if err := results.UpdateCatalogProposedRule(state, row.ID, rule); err != nil {
					return err
				}
				row.ProposedRule = rule
				fmt.Fprintln(out, "rule updated")
				continue
			case "s", "skip":
				skipped++
				fmt.Fprintln(out, "skipped")
			case "q", "quit":
				fmt.Fprintf(out, "\nStopped: %d accepted, %d dismissed, %d skipped, %d remaining.\n", accepted, dismissed, skipped, len(rows)-i)
				return nil
			default:
				if err == io.EOF {
					return fmt.Errorf("interactive input ended before candidate %s was reviewed", row.ID)
				}
				fmt.Fprintln(out, "Choose accept, dismiss, reassign, edit, skip, or quit.")
				continue
			}
			break
		}
	}
	fmt.Fprintf(out, "\nReview complete: %d accepted, %d dismissed, %d skipped.\n", accepted, dismissed, skipped)
	return nil
}

func promptCatalogAdversary(out io.Writer, reader *bufio.Reader, ids []string) (string, error) {
	fmt.Fprintln(out, "Available adversaries:")
	for i, id := range ids {
		fmt.Fprintf(out, "  %d. %s\n", i+1, id)
	}
	fmt.Fprint(out, "Choose number or adversary id (blank cancels) > ")
	choice, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return "", nil
	}
	if n, numberErr := strconv.Atoi(choice); numberErr == nil {
		if n < 1 || n > len(ids) {
			fmt.Fprintln(out, "Invalid adversary number.")
			return "", nil
		}
		return ids[n-1], nil
	}
	for _, id := range ids {
		if choice == id {
			return id, nil
		}
	}
	fmt.Fprintf(out, "Unknown adversary %q; reassignment canceled.\n", choice)
	return "", nil
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
				fmt.Fprintln(out, "Open the local browser review queue:")
				fmt.Fprintf(out, "  adversary catalog train inspect%s\n", pathFlag)
				fmt.Fprintln(out, "Terminal alternatives:")
				fmt.Fprintf(out, "  adversary catalog train inspect --all%s\n", pathFlag)
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
