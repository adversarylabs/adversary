package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/train/pipeline"
	"github.com/adversarylabs/adversary/internal/train/workspace"
	"github.com/spf13/cobra"
)

func newTrainCommand(app *application.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "train",
		Short: "Train adversary packages from PR review history (draft gaps; stateful)",
		Long: `Train walks your PR review history, grades local adversary packages against
human review comments, and drafts suggested improvements.

It does not fine-tune model weights or write a new model artifact. Official
catalog packages (when enabled) act as a read-only jury: if they catch a
concern, home-grown packages are not trained on that gold.

Configure history sources and packages in adversary.train.yaml (see train init).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newTrainInitCommand(app))
	cmd.AddCommand(newTrainRunCommand(app))
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

			advSource := resolveAdversarySource(wsRoot, cfg, adversaryOnly)
			trainRoot := findTrainModuleRoot()

			opts := pipeline.Options{
				DataRoot:        stateRoot,
				RepoRoot:        trainRoot,
				Fixture:         fixture,
				Live:            !fixture,
				AdversarySource: advSource,
				MaxPRs:          cfg.Run.MaxPRs,
				MaxTurns:        cfg.Run.MaxTurns,
				ResetDiscovery:  resetDiscovery,
				PR:              pr,
				Owner:           owner,
				Repo:            repo,
			}
			if opts.MaxPRs == 0 {
				opts.MaxPRs = 1
			}
			if opts.MaxTurns == 0 {
				opts.MaxTurns = 15
			}

			stderr := cmd.ErrOrStderr()
			fmt.Fprintln(stderr, "adversary train run")
			fmt.Fprintf(stderr, "  config: %s\n", cfgPath)
			fmt.Fprintf(stderr, "  state:  %s\n", stateRoot)
			if fixture {
				fmt.Fprintln(stderr, "  mode:   fixture (hermetic)")
			} else {
				fmt.Fprintln(stderr, "  mode:   live history")
			}
			if adversaryOnly != "" {
				fmt.Fprintf(stderr, "  local:  %s only\n", adversaryOnly)
			}
			if cfg.OfficialEnabled() && !fixture {
				fmt.Fprintln(stderr, "  official jury: enabled (drafts for locals only)")
			} else {
				fmt.Fprintln(stderr, "  official jury: disabled")
			}

			res, err := pipeline.Run(opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.HumanReport != nil && res.HumanReport.CLIBlock != "" {
				fmt.Fprint(out, res.HumanReport.CLIBlock)
			} else if res.HumanReport != nil && res.HumanReport.READMEPath != "" {
				fmt.Fprintf(out, "Story: %s\n", res.HumanReport.READMEPath)
			} else {
				fmt.Fprintf(out, "train run complete (run_id=%s)\n", res.RunID)
			}
			if err := workspace.RewriteTrainDrafts(stateRoot); err != nil {
				fmt.Fprintf(stderr, "warning: draft rewrite: %v\n", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&workspacePath, "path", "", "workspace with adversary.train.yaml")
	cmd.Flags().StringVar(&adversaryOnly, "adversary", "", "train only this local package id")
	cmd.Flags().IntVar(&maxPRs, "max-prs", 0, "override run.max_prs")
	cmd.Flags().IntVar(&maxTurns, "max-turns", 0, "override run.max_turns")
	cmd.Flags().BoolVar(&resetDiscovery, "reset-discovery", false, "forget seen PRs before hunting")
	cmd.Flags().BoolVar(&fixture, "fixture", false, "hermetic fixture run (for tests/gates; ignores empty sources)")
	cmd.Flags().IntVar(&pr, "pr", 0, "pin a single PR number (debug)")
	cmd.Flags().StringVar(&owner, "owner", "", "GitHub owner with --pr/--repo")
	cmd.Flags().StringVar(&repo, "repo", "", "GitHub repo with --pr/--owner")
	return cmd
}

func newTrainStoryCommand(app *application.App) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "story",
		Short: "Print the latest train story (LATEST_STORY.md)",
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
		Short: "Print draft suggested issues from the latest train run",
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

func resolveAdversarySource(wsRoot string, cfg workspace.Config, only string) string {
	if only != "" {
		if cfg.Adversaries.Root != "" {
			p := filepath.Join(wsRoot, cfg.Adversaries.Root, only)
			if workspace.DirExists(p) {
				return p
			}
			if workspace.DirExists(only) {
				return only
			}
		}
	}
	if cfg.Adversaries.Path != "" {
		p := cfg.Adversaries.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(wsRoot, p)
		}
		return p
	}
	if cfg.Adversaries.Root != "" {
		root := cfg.Adversaries.Root
		if !filepath.IsAbs(root) {
			root = filepath.Join(wsRoot, root)
		}
		return workspace.FirstScopedPackage(root)
	}
	return ""
}

func findTrainModuleRoot() string {
	wd, err := workspace.WorkingDir()
	if err != nil {
		return "."
	}
	return workspace.FindTrainFixturesRoot(wd)
}
