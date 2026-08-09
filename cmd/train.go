package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/pipeline"
	"github.com/adversarylabs/adversary/internal/train/repos"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
	"github.com/spf13/cobra"
)

func newTrainCommand(app *application.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "train",
		Short: "Train adversary packages from PR review history (draft gaps; stateful)",
		Long: `Train walks your PR review history, grades local adversary packages against
human review comments, and drafts suggested improvements.

Workflow:
  adversary train run
  adversary train results ls
  adversary train results inspect <id>
  adversary train results apply <id>
  adversary train reset          # forget seen PRs and re-hunt

It does not fine-tune model weights. Official catalog packages (when enabled)
act as a read-only jury only.

Configure history sources and packages in adversary.train.yaml (see train init).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newTrainInitCommand(app))
	cmd.AddCommand(newTrainRunCommand(app))
	cmd.AddCommand(newTrainResultsCommand(app))
	cmd.AddCommand(newTrainResetCommand(app))
	cmd.AddCommand(newTrainStoryCommand(app))
	cmd.AddCommand(newTrainStatusCommand(app))
	cmd.AddCommand(newTrainIssuesCommand(app))
	return cmd
}

func newTrainInitCommand(app *application.App) *cobra.Command {
	var path string
	var force bool
	var single bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold adversary.train.yaml, state dir, and gitignore",
		Long: `Create a committed adversary.train.yaml stub and a gitignored
.adversary-train/ state directory. Edit the YAML to set sources (org/repos),
authors, local packages, and official jury include/exclude before train run.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := workspace.Init(workspace.InitOptions{
				Path:          path,
				Force:         force,
				SinglePackage: single,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.Created {
				fmt.Fprintf(out, "Created %s\n", res.Config)
			} else {
				fmt.Fprintf(out, "Kept existing %s (use --force to overwrite)\n", res.Config)
			}
			fmt.Fprintf(out, "State dir: %s\n", res.StateDir)
			fmt.Fprintf(out, "\nNext steps:\n")
			fmt.Fprintf(out, "  1. Edit %s — set sources.org and/or sources.repos\n", workspace.DefaultConfigName)
			fmt.Fprintf(out, "  2. Ensure local packages have docs/scope.md\n")
			fmt.Fprintf(out, "  3. adversary train run\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace directory (default: current directory)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing adversary.train.yaml")
	cmd.Flags().BoolVar(&single, "single-package", false, "stub config for a single package at workspace root")
	return cmd
}

func newTrainRunCommand(app *application.App) *cobra.Command {
	var (
		workspacePath  string
		adversaryOnly  string
		maxPRs         int
		maxTurns       int
		concurrency    int
		resetDiscovery bool
		fixture        bool
		pr             int
		owner          string
		repo           string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Walk history (or fixtures), grade packages, draft local improvements",
		Long: `Read adversary.train.yaml, resume discovery state, grade local packages
(and optional official jury), and write stories plus suggested issues under
the state directory. Drafts never target official package ids.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := workspacePath
			if ws == "" {
				wd, err := workspace.WorkingDir()
				if err != nil {
					return err
				}
				ws = wd
			}
			cfgPath, err := workspace.FindConfig(ws)
			if err != nil {
				return fmt.Errorf("%w (run: adversary train init)", err)
			}
			cfg, err := workspace.Load(cfgPath)
			if err != nil {
				return err
			}
			if !fixture {
				if err := cfg.Validate(); err != nil {
					return err
				}
			} else if strings.TrimSpace(cfg.Adversaries.Root) == "" && strings.TrimSpace(cfg.Adversaries.Path) == "" {
				return fmt.Errorf("adversaries.root or adversaries.path is required")
			}

			wsRoot := filepath.Dir(cfgPath)
			stateRoot := workspace.ResolveStateAbs(cfgPath, cfg.StateDirResolved())
			if err := workspace.EnsureStateDir(stateRoot); err != nil {
				return err
			}

			if maxPRs > 0 {
				cfg.Run.MaxPRs = maxPRs
			}
			if maxTurns > 0 {
				cfg.Run.MaxTurns = maxTurns
			}
			if concurrency > 0 {
				cfg.Run.Concurrency = concurrency
			}

			// History sources from config → pipeline catalog (repos mode).
			// author_reviews mode needs no catalog (GitHub search by login).
			discoveryMode := cfg.DiscoveryMode()
			var catalog []repos.Repo
			seenRepo := map[string]bool{}
			addCatalog := func(owner, name string) {
				owner, name = strings.TrimSpace(owner), strings.TrimSpace(name)
				if owner == "" || name == "" {
					return
				}
				key := strings.ToLower(owner + "/" + name)
				if seenRepo[key] {
					return
				}
				seenRepo[key] = true
				catalog = append(catalog, repos.Repo{
					Owner: owner, Name: name,
					Languages: cfg.Sources.Languages, Role: "discovery",
				})
			}
			for _, r := range cfg.Sources.Repos {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}
				parts := strings.SplitN(r, "/", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid sources.repos entry %q (want owner/name)", r)
				}
				addCatalog(parts[0], parts[1])
			}
			// Expand sources.org (and optional repos_allowlist) via gh for live runs.
			if discoveryMode == "repos" && !fixture && strings.TrimSpace(cfg.Sources.Org) != "" {
				orgRepos, err := collect.ListOrgRepos(cmd.Context(), cfg.Sources.Org, cfg.Sources.ReposAllowlist)
				if err != nil {
					return fmt.Errorf("expand sources.org %q: %w", cfg.Sources.Org, err)
				}
				for _, r := range orgRepos {
					addCatalog(r.Owner, r.Name)
				}
				if len(catalog) == 0 {
					return fmt.Errorf("sources.org %q expanded to zero repositories (check allowlist and access)", cfg.Sources.Org)
				}
			}
			if discoveryMode == "repos" && !fixture && len(catalog) == 0 {
				return fmt.Errorf("no repositories to hunt: set sources.repos and/or sources.org")
			}

			// Local packages: all under root (or single path)
			var localRoot string
			var localDirs []string
			var trainOnly []string
			if adversaryOnly != "" {
				trainOnly = []string{adversaryOnly}
			} else if len(cfg.Run.Only) > 0 {
				trainOnly = cfg.Run.Only
			}
			if cfg.Adversaries.Path != "" {
				p := cfg.Adversaries.Path
				if !filepath.IsAbs(p) {
					p = filepath.Join(wsRoot, p)
				}
				localDirs = []string{p}
			} else if cfg.Adversaries.Root != "" {
				localRoot = cfg.Adversaries.Root
				if !filepath.IsAbs(localRoot) {
					localRoot = filepath.Join(wsRoot, localRoot)
				}
			}

			// Local ids for draft filtering (package short ids: strip -adversary).
			var localIDs []string
			if localRoot != "" {
				if names, err := workspace.ListDir(localRoot); err == nil {
					for _, n := range names {
						if strings.HasPrefix(n, ".") {
							continue
						}
						localIDs = append(localIDs, strings.TrimSuffix(n, "-adversary"))
					}
				}
			}
			for _, d := range localDirs {
				base := filepath.Base(d)
				localIDs = append(localIDs, strings.TrimSuffix(base, "-adversary"))
			}

			// Official jury ids from include/exclude (exclude-only still marks known official)
			var officialIDs []string
			if cfg.OfficialEnabled() {
				// Explicit include list if set
				for _, id := range cfg.Official.Include {
					if cfg.OfficialIncluded(id) {
						officialIDs = append(officialIDs, id)
					}
				}
			}

			trainRoot := findTrainModuleRoot()
			advSource := ""
			if len(localDirs) == 1 {
				advSource = localDirs[0]
			} else if localRoot != "" && adversaryOnly != "" {
				advSource = filepath.Join(localRoot, adversaryOnly)
			} else if localRoot != "" {
				advSource = workspace.FirstScopedPackage(localRoot)
			}

			// Primary package label for hunt logs (derived further in pipeline from loaded packages).
			primaryName := ""
			if adversaryOnly != "" {
				primaryName = strings.TrimSuffix(adversaryOnly, "-adversary")
			} else if len(trainOnly) == 1 {
				primaryName = strings.TrimSuffix(trainOnly[0], "-adversary")
			} else if len(localIDs) == 1 {
				primaryName = localIDs[0]
			}

			authorOrgs := append([]string{}, cfg.Sources.Orgs...)
			if cfg.Sources.Org != "" {
				authorOrgs = append(authorOrgs, cfg.Sources.Org)
			}
			opts := pipeline.Options{
				Context:          cmd.Context(),
				DataRoot:         stateRoot,
				RepoRoot:         trainRoot,
				Fixture:          fixture,
				Live:             !fixture,
				AdversaryName:    primaryName,
				AdversarySource:  advSource,
				LocalPackageRoot: localRoot,
				LocalPackageDirs: localDirs,
				TrainOnlyIDs:     trainOnly,
				LocalIDs:         localIDs,
				OfficialIDs:      officialIDs,
				AuthorsOnly:      cfg.Sources.AuthorsOnly,
				AuthorsIgnore:    cfg.Sources.AuthorsIgnore,
				Languages:        cfg.Sources.Languages,
				CatalogRepos:     catalog,
				DiscoveryMode:    discoveryMode,
				AuthorRoles:      cfg.Sources.AuthorRoles,
				AuthorOrgs:       authorOrgs,
				AuthorSince:      cfg.Sources.Since,
				MaxPRs:           cfg.Run.MaxPRs,
				MaxTurns:         cfg.Run.MaxTurns,
				Concurrency:      cfg.Run.Concurrency,
				ResetDiscovery:   resetDiscovery,
				PR:               pr,
				Owner:            owner,
				Repo:             repo,
			}
			if opts.MaxPRs == 0 {
				opts.MaxPRs = 1
			}
			if opts.MaxTurns == 0 {
				opts.MaxTurns = 15
			}
			// Pin single repo from config when only one catalog entry and no CLI pin
			if opts.Owner == "" && opts.Repo == "" && len(catalog) == 1 {
				opts.Owner, opts.Repo = catalog[0].Owner, catalog[0].Name
			}

			stderr := cmd.ErrOrStderr()
			fmt.Fprintln(stderr, "adversary train run")
			fmt.Fprintf(stderr, "  config: %s\n", cfgPath)
			fmt.Fprintf(stderr, "  state:  %s\n", stateRoot)
			if fixture {
				fmt.Fprintln(stderr, "  mode:   fixture (hermetic)")
			} else {
				fmt.Fprintln(stderr, "  mode:   live history")
				fmt.Fprintf(stderr, "  discovery: %s\n", discoveryMode)
				if discoveryMode == "author_reviews" {
					fmt.Fprintf(stderr, "  authors: %v roles: %v orgs: %v\n",
						cfg.Sources.AuthorsOnly, cfg.Sources.AuthorRoles, authorOrgs)
				} else {
					fmt.Fprintf(stderr, "  sources.repos: %v org: %s\n", cfg.Sources.Repos, cfg.Sources.Org)
				}
			}
			if adversaryOnly != "" {
				fmt.Fprintf(stderr, "  local:  %s only\n", adversaryOnly)
			} else if localRoot != "" {
				fmt.Fprintf(stderr, "  locals: all under %s\n", localRoot)
			}
			if cfg.OfficialEnabled() && !fixture {
				fmt.Fprintln(stderr, "  official jury: enabled (drafts for locals only)")
			} else {
				fmt.Fprintln(stderr, "  official jury: disabled")
			}

			res, err := pipeline.Run(opts)
			out := cmd.OutOrStdout()
			// Always show progress toward results — including on interrupt (partial SQLite writes).
			if res != nil {
				if err != nil {
					fmt.Fprintf(out, "train run stopped\n")
				} else {
					fmt.Fprintf(out, "train run complete\n")
				}
				fmt.Fprintf(out, "  run:     %s\n", res.RunID)
				if res.Scorecard != nil {
					fmt.Fprintf(out, "  grade:   %d failure(s) scored\n", res.Scorecard.FailureCount)
				}
				fmt.Fprintf(out, "  results: %d row(s) written this run\n", res.ResultsAdded)
				fmt.Fprintf(out, "  next:    adversary train results ls\n")
				if res.HumanReport != nil && res.HumanReport.READMEPath != "" {
					fmt.Fprintf(out, "  story:   %s\n", res.HumanReport.READMEPath)
				}
				if res.Message != "" && err != nil {
					fmt.Fprintln(stderr, res.Message)
				}
				if err2 := workspace.RewriteTrainDrafts(stateRoot); err2 != nil {
					fmt.Fprintf(stderr, "warning: draft rewrite: %v\n", err2)
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&workspacePath, "path", "", "workspace with adversary.train.yaml")
	cmd.Flags().StringVar(&adversaryOnly, "adversary", "", "train only this local package id")
	cmd.Flags().IntVar(&maxPRs, "max-prs", 0, "override run.max_prs")
	cmd.Flags().IntVar(&maxTurns, "max-turns", 0, "override run.max_turns")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "override run.concurrency (parallel PR collect; default 2)")
	cmd.Flags().BoolVar(&resetDiscovery, "reset-discovery", false, "forget seen PRs before hunting")
	cmd.Flags().BoolVar(&fixture, "fixture", false, "hermetic fixture run (for tests/gates; ignores empty sources)")
	cmd.Flags().IntVar(&pr, "pr", 0, "pin a single PR number (debug)")
	cmd.Flags().StringVar(&owner, "owner", "", "GitHub owner with --pr/--repo")
	cmd.Flags().StringVar(&repo, "repo", "", "GitHub repo with --pr/--owner")
	return cmd
}

func newTrainResultsCommand(app *application.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "results",
		Aliases: []string{"result"},
		Short:   "List, inspect, and apply train result drafts",
		Long: `The results inbox is the primary train output.

  adversary train results ls
  adversary train results inspect <id>
  adversary train results apply <id> [<id>...]`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newTrainResultsLSCommand(app))
	cmd.AddCommand(newTrainResultsInspectCommand(app))
	cmd.AddCommand(newTrainResultsApplyCommand(app))
	cmd.AddCommand(newTrainResultsDismissCommand(app))
	return cmd
}

func newTrainResultsLSCommand(app *application.App) *cobra.Command {
	var path, pkg, status string
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List result inbox rows (summaries)",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			rows, err := results.List(state, pkg, status)
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), results.FormatListTable(rows))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	cmd.Flags().StringVar(&pkg, "package", "", "filter by package id")
	cmd.Flags().StringVar(&status, "status", "", "filter: new|applied|dismissed")
	return cmd
}

func newTrainResultsInspectCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "inspect <id>",
		Short: "Show full detail for one result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			r, err := results.Get(state, args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), results.FormatInspect(r))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	return cmd
}

func newTrainResultsApplyCommand(app *application.App) *cobra.Command {
	var path string
	var noGit, noIssue, applyAll, includeHumanIssues, includeIndividualIssues bool
	cmd := &cobra.Command{
		Use:   "apply [<id>...]",
		Short: "Apply train result(s): local evidence + eligible GitHub issues",
		Long: `Apply writes each result draft into the local adversary package under
docs/train-drafts/<id>.md and opens a GitHub issue on the package's git remote
with agent-ready context (goal, source PR, what to change, acceptance).

With explicit result ids, individual misses open issues. With --all, GitHub
issues are opened for clustered improvement drafts and false positives; the
individual miss and human-gold rows remain local evidence. This prevents one
implementation issue per reviewer comment. Use --include-individual-issues or
--include-human-issues to opt back into those issue kinds during bulk apply.

  adversary train results apply <id>
  adversary train results apply --all
  adversary train results apply --all --no-issue   # draft file only
  adversary train results apply --all --no-git     # skip branch/commit
  adversary train results apply --all --include-individual-issues
  adversary train results apply --all --include-human-issues

Requires ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN with issues:write
on the package repo (unless --no-issue). Does not open a PR.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if applyAll && len(args) > 0 {
				return fmt.Errorf("use either --all or explicit ids, not both")
			}
			if !applyAll && len(args) == 0 {
				return fmt.Errorf("provide result id(s) or --all (see: adversary train results ls)")
			}
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			cfgPath, cfg, err := resolveTrainConfig(path)
			if err != nil {
				return err
			}
			ids := args
			if applyAll {
				rows, err := results.List(state, "", results.StatusNew)
				if err != nil {
					return err
				}
				if len(rows) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "no new results to apply")
					return nil
				}
				ids = make([]string, 0, len(rows))
				for _, r := range rows {
					ids = append(ids, r.ID)
				}
			}
			wsRoot := filepath.Dir(cfgPath)
			out := cmd.OutOrStdout()
			for _, id := range ids {
				r, err := results.Get(state, id)
				if err != nil {
					return err
				}
				pkgPath, err := resolvePackagePath(wsRoot, cfg, r.Package)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				ar, err := results.Apply(state, id, results.ApplyOptions{
					PackagePath:             pkgPath,
					CreateBranch:            !noGit,
					CreateIssue:             !noIssue,
					IncludeHumanIssues:      includeHumanIssues,
					IncludeIndividualIssues: !applyAll || includeIndividualIssues,
					Context:                 cmd.Context(),
				})
				if err != nil {
					return err
				}
				if ar.AlreadyDone {
					fmt.Fprintf(out, "%s: already applied", id)
					if ar.IssueURL != "" {
						fmt.Fprintf(out, " → %s", ar.IssueURL)
					} else if ar.Path != "" {
						fmt.Fprintf(out, " → %s", ar.Path)
					}
					fmt.Fprintln(out)
					continue
				}
				fmt.Fprintf(out, "%s: wrote %s\n", id, ar.Path)
				if ar.IssueURL != "" {
					fmt.Fprintf(out, "       issue %s\n", ar.IssueURL)
				}
				if ar.Branch != "" {
					fmt.Fprintf(out, "       branch %s", ar.Branch)
					if ar.Committed {
						fmt.Fprintf(out, " (committed)")
					}
					fmt.Fprintln(out)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	cmd.Flags().BoolVar(&noGit, "no-git", false, "only write draft file; skip git branch/commit")
	cmd.Flags().BoolVar(&noIssue, "no-issue", false, "skip GitHub issue creation (local draft only)")
	cmd.Flags().BoolVar(&includeIndividualIssues, "include-individual-issues", false, "with --all, also open one issue per missed human concern")
	cmd.Flags().BoolVar(&includeHumanIssues, "include-human-issues", false, "also open GitHub issues for ungraded human-gold rows")
	cmd.Flags().BoolVar(&applyAll, "all", false, "apply all results with status=new")
	return cmd
}

func newTrainResultsDismissCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "dismiss <id> [<id>...]",
		Short: "Mark result(s) dismissed (not applied)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			for _, id := range args {
				if err := results.Dismiss(state, id); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: dismissed\n", id)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	return cmd
}

func newTrainResetCommand(app *application.App) *cobra.Command {
	var path string
	var all bool
	var resultsOnly bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Clear seen-PR discovery (re-hunt repos) and/or results inbox",
		Long: `By default clears discovery state only (which PRs train already tried),
so the next train run will re-examine the catalog repos.

  adversary train reset           # discovery only
  adversary train reset --results # clear results inbox only
  adversary train reset --all     # discovery + results`,
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if all {
				msg, err := results.ResetAll(state)
				if err != nil {
					return err
				}
				fmt.Fprintln(out, msg)
				return nil
			}
			if resultsOnly {
				n, err := results.ResetResults(state)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "cleared %d result file(s)\n", n)
				return nil
			}
			n, err := results.ResetDiscovery(state)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "cleared %d discovery file(s) — next train run will re-hunt repos\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	cmd.Flags().BoolVar(&all, "all", false, "clear discovery and results inbox")
	cmd.Flags().BoolVar(&resultsOnly, "results", false, "clear results inbox only")
	return cmd
}

func newTrainStoryCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "story",
		Short: "Print the latest train story (LATEST_STORY.md) — prefer results ls",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			story := filepath.Join(state, "LATEST_STORY.md")
			raw, err := workspace.ReadFile(story)
			if err != nil {
				return fmt.Errorf("no story at %s (run: adversary train run): %w", story, err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	return cmd
}

func newTrainIssuesCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "issues",
		Short: "Print draft suggested issues (prefer: train results ls)",
		RunE: func(cmd *cobra.Command, args []string) error {
			state, err := resolveStateDir(path)
			if err != nil {
				return err
			}
			_, raw, err := workspace.FindSuggestedIssues(state)
			if err != nil {
				return fmt.Errorf("%w (run: adversary train run)", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(raw))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	return cmd
}

func resolveTrainConfig(workspacePath string) (cfgPath string, cfg workspace.Config, err error) {
	ws := workspacePath
	if ws == "" {
		wd, e := workspace.WorkingDir()
		if e != nil {
			return "", workspace.Config{}, e
		}
		ws = wd
	}
	cfgPath, err = workspace.FindConfig(ws)
	if err != nil {
		return "", workspace.Config{}, err
	}
	cfg, err = workspace.Load(cfgPath)
	return cfgPath, cfg, err
}

// resolvePackagePath finds the local package directory for apply.
func resolvePackagePath(wsRoot string, cfg workspace.Config, packageID string) (string, error) {
	packageID = strings.TrimSpace(packageID)
	if cfg.Adversaries.Path != "" {
		p := cfg.Adversaries.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(wsRoot, p)
		}
		// Single-package workspace: path is the package itself.
		return p, nil
	}
	if cfg.Adversaries.Root != "" {
		root := cfg.Adversaries.Root
		if !filepath.IsAbs(root) {
			root = filepath.Join(wsRoot, root)
		}
		if packageID == "" {
			return "", fmt.Errorf("result has empty package id")
		}
		// Prefer exact id, then id-adversary folder name.
		for _, name := range []string{packageID, packageID + "-adversary"} {
			cand := filepath.Join(root, name)
			if workspace.DirExists(cand) {
				return cand, nil
			}
		}
		return "", fmt.Errorf("package %q not found under %s", packageID, root)
	}
	return "", fmt.Errorf("adversaries.path or adversaries.root required in config")
}

func newTrainStatusCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show train config summary, packages, and discovery state",
		RunE: func(cmd *cobra.Command, args []string) error {
			ws := path
			if ws == "" {
				wd, err := workspace.WorkingDir()
				if err != nil {
					return err
				}
				ws = wd
			}
			cfgPath, err := workspace.FindConfig(ws)
			if err != nil {
				return err
			}
			cfg, err := workspace.Load(cfgPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "config: %s\n", cfgPath)
			fmt.Fprintf(out, "state_dir: %s\n", cfg.StateDirResolved())
			fmt.Fprintf(out, "adversaries.root: %q path: %q\n", cfg.Adversaries.Root, cfg.Adversaries.Path)
			fmt.Fprintf(out, "official.enabled: %v\n", cfg.OfficialEnabled())
			if len(cfg.Official.Exclude) > 0 {
				fmt.Fprintf(out, "official.exclude: %v\n", cfg.Official.Exclude)
			}
			fmt.Fprintf(out, "sources.host: %s\n", cfg.Sources.Host)
			fmt.Fprintf(out, "sources.org: %s\n", cfg.Sources.Org)
			fmt.Fprintf(out, "sources.repos: %v\n", cfg.Sources.Repos)
			fmt.Fprintf(out, "sources.authors_only: %v\n", cfg.Sources.AuthorsOnly)
			fmt.Fprintf(out, "sources.authors_ignore: %v\n", cfg.Sources.AuthorsIgnore)
			fmt.Fprintf(out, "run.max_prs: %d max_turns: %d\n", cfg.Run.MaxPRs, cfg.Run.MaxTurns)
			if err := cfg.Validate(); err != nil {
				fmt.Fprintf(out, "validate: ERROR: %v\n", err)
			} else {
				fmt.Fprintf(out, "validate: ok\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "workspace with adversary.train.yaml")
	return cmd
}

func resolveStateDir(workspacePath string) (string, error) {
	ws := workspacePath
	if ws == "" {
		wd, err := workspace.WorkingDir()
		if err != nil {
			return "", err
		}
		ws = wd
	}
	cfgPath, err := workspace.FindConfig(ws)
	if err != nil {
		return "", err
	}
	cfg, err := workspace.Load(cfgPath)
	if err != nil {
		return "", err
	}
	return workspace.ResolveStateAbs(cfgPath, cfg.StateDirResolved()), nil
}

func findTrainModuleRoot() string {
	wd, err := workspace.WorkingDir()
	if err != nil {
		return "."
	}
	return workspace.FindTrainFixturesRoot(wd)
}
