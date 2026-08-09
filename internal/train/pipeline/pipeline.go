package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/adversarylabs/adversary/internal/train/adversaries"
	"github.com/adversarylabs/adversary/internal/train/bundle"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/checkout"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/critic"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/experiment"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/normalize"
	"github.com/adversarylabs/adversary/internal/train/optimizer"
	"github.com/adversarylabs/adversary/internal/train/receipt"
	"github.com/adversarylabs/adversary/internal/train/report"
	"github.com/adversarylabs/adversary/internal/train/repos"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/runner"
	"github.com/adversarylabs/adversary/internal/train/scope"
	"github.com/adversarylabs/adversary/internal/train/score"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// Options for the first-slice end-to-end path.
type Options struct {
	// Context cancels the train run (Ctrl+C / SIGTERM via CLI). nil = background.
	Context  context.Context
	DataRoot string
	RepoRoot string // train engine root (fixtures)
	Fixture  bool   // tests only; production path is always live discovery
	Live     bool   // default true when Fixture is false
	Owner    string // optional single-repo pin (with Repo)
	Repo     string
	PR       int // optional single PR; 0 = discover live
	// ReposFile is path to repositories.json (default: <RepoRoot>/config/repositories.json).
	ReposFile string
	// CatalogRepos overrides the JSON catalog when non-empty (from adversary.train.yaml sources).
	CatalogRepos []repos.Repo
	// Languages filters the catalog (empty = any language; engineering-review uses any).
	// Example: []string{"go"} for go-security.
	Languages []string
	// AdversaryName is the primary package id for hunt logs, scorecards, and
	// empty-owner fallbacks. When empty, derived from loaded local packages
	// (or "engineering-review" only as a last-resort legacy default).
	AdversaryName string
	// MaxPRs is how many usable PRs we want to grade this run (default 1).
	MaxPRs int
	// MaxTurns is how many PRs we may attempt while hunting (default 15).
	// Each turn = try one not-yet-seen PR (collect + scope). Stops early when MaxPRs usable cases collected.
	MaxTurns int
	// Concurrency is how many PR collects may run in parallel (gh API). Default 4.
	// Local package `adversary run` stays serialized via a per-path lock.
	Concurrency int
	// ResetDiscovery clears seen-PR state for repos we touch before hunting.
	ResetDiscovery  bool
	AdversarySource string
	// LocalPackageDirs are all local package roots to load for routing/grading.
	// When set, DiscoverRoot/loadPackage is used instead of sibling *-adversary discovery only.
	LocalPackageDirs []string
	// LocalPackageRoot loads every child with docs/scope.md (workspace adversaries/).
	LocalPackageRoot string
	// TrainOnlyIDs limits train-eligible locals (empty = all locals).
	TrainOnlyIDs []string
	// LocalIDs marks package ids that may receive train drafts (home-grown).
	// If empty, inferred from LocalPackageDirs/Root.
	LocalIDs []string
	// OfficialIDs marks package ids that are official jury (never receive drafts).
	// Used by report draft filtering.
	OfficialIDs []string
	// AuthorsOnly / AuthorsIgnore filter gold authors (from train config).
	AuthorsOnly   []string
	AuthorsIgnore []string
	// DiscoveryMode: "repos" (default) or "author_reviews".
	DiscoveryMode string
	// AuthorRoles for author_reviews: reviewed-by, commenter, author.
	AuthorRoles []string
	// AuthorOrgs bounds author search (--owner).
	AuthorOrgs []string
	// AuthorSince optional date bound (merged-at >=).
	AuthorSince        string
	EngineeringFixture string
	BaselineFixture    string
	CaseFixtureDir     string
}

// Result of a full slice run.
type Result struct {
	RunID       string
	Receipt     *receipt.Receipt
	Scorecard   *score.Scorecard
	Failures    []judge.Failure
	Hypotheses  []critic.Hypothesis
	Proposal    *optimizer.Proposal
	Experiment  *optimizer.ExperimentRecord
	Report      *experiment.Report
	HumanReport *report.Result
	CaseIDs     []string
	// ResultsAdded is how many new inbox rows were written for train results ls.
	ResultsAdded int
	ExitCode     int
	Blocked      *dataroot.BlockedResult
	Message      string
}

// caseRuntime holds per-case artifacts needed for candidate re-run.
type caseRuntime struct {
	Case     *cases.Case
	Proj     *bundle.Projection
	RepoPath string
	BaseRef  string
	HeadRef  string
	BaseRaw  []byte
	EngRaw   []byte
	Judgment *judge.ReviewJudgment
	Norm     *normalize.Review
}

// Run executes the first usable slice (fixture or live).
func Run(opts Options) (*Result, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("train interrupted: %w", err)
	}
	if opts.DataRoot == "" {
		return nil, fmt.Errorf("data root required")
	}
	if err := securefs.MkdirAll(opts.DataRoot); err != nil {
		return nil, err
	}
	runID := fmt.Sprintf("slice-%d", time.Now().UTC().UnixNano())
	rcpt := receipt.New(runID)
	out := &Result{RunID: runID, Receipt: rcpt}

	// --- 1. Collect cases from live GitHub (default). Fixtures are tests-only. ---
	var caseList []*cases.Case
	var advPackages []adversaries.Package
	if opts.Fixture {
		cs, err := loadFixtureCases(opts)
		if err != nil {
			return nil, err
		}
		caseList = cs
		rcpt.SetStage("collect", dataroot.ClassFixture)
		rcpt.SetStage("reconstruct", dataroot.ClassFixture)
	} else {
		opts.Live = true
		targetPRs := opts.MaxPRs
		if targetPRs <= 0 {
			targetPRs = 1
		}
		maxTurns := opts.MaxTurns
		if maxTurns <= 0 {
			maxTurns = 15
		}

		// Build the set of repos to hunt across (config sources first).
		// Author-reviews mode does not need a catalog.
		authorMode := strings.EqualFold(opts.DiscoveryMode, "author_reviews") ||
			(opts.DiscoveryMode == "" && len(opts.AuthorsOnly) > 0 && len(opts.CatalogRepos) == 0 && opts.Owner == "" && opts.Repo == "")
		var catalogRepos []repos.Repo
		if !authorMode {
			if len(opts.CatalogRepos) > 0 {
				catalogRepos = opts.CatalogRepos
			} else if opts.Owner != "" && opts.Repo != "" {
				catalogRepos = []repos.Repo{{Owner: opts.Owner, Name: opts.Repo, Languages: opts.Languages, Role: "discovery"}}
			} else {
				catPath := opts.ReposFile
				if catPath == "" && opts.RepoRoot != "" {
					catPath = repos.DefaultPath(opts.RepoRoot)
				}
				if catPath == "" {
					return nil, fmt.Errorf("no repositories catalog (set sources.repos, or sources.authors_only with discovery: author_reviews)")
				}
				cat, err := repos.Load(catPath)
				if err != nil {
					return nil, err
				}
				catalogRepos = cat.Filter("discovery", opts.Languages)
				if len(catalogRepos) == 0 {
					return nil, fmt.Errorf("no repos in %s matching languages %v", catPath, opts.Languages)
				}
			}
		}

		// Discover local packages (workspace) and optional monorepo siblings.
		var scopeClf *scope.Classifier
		var commentRouter *scope.Router
		var siblingPkgs []adversaries.Package
		var loadErr error
		if opts.LocalPackageRoot != "" {
			siblingPkgs, loadErr = adversaries.DiscoverRoot(opts.LocalPackageRoot)
		} else if len(opts.LocalPackageDirs) > 0 {
			for _, d := range opts.LocalPackageDirs {
				pkg, err := adversaries.DiscoverRoot(d)
				if err != nil {
					// try load single package path
					if one, e2 := loadOnePackage(d); e2 == nil {
						siblingPkgs = append(siblingPkgs, one)
					}
					continue
				}
				siblingPkgs = append(siblingPkgs, pkg...)
			}
		} else {
			siblingPkgs, loadErr = adversaries.DiscoverSiblings(opts.RepoRoot)
		}
		if loadErr != nil || len(siblingPkgs) == 0 {
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "note: adversary discovery: %v (falling back to single source)\n", loadErr)
			}
			// Resolve name before scope classifier so we do not always label as eng-review.
			primary := resolvePrimaryAdversaryName(opts, siblingPkgs)
			opts.AdversaryName = primary
			scopeClf = &scope.Classifier{AdversaryName: primary, UseLLM: os.Getenv("OPENAI_API_KEY") != ""}
			srcForScope := opts.AdversarySource
			if srcForScope == "" && opts.RepoRoot != "" {
				// Prefer path matching primary name; eng-review only as last resort.
				for _, candName := range []string{primary + "-adversary", "engineering-review-adversary"} {
					cand := filepath.Join(filepath.Dir(opts.RepoRoot), candName)
					if st, err := os.Stat(cand); err == nil && st.IsDir() {
						srcForScope = cand
						break
					}
				}
			}
			if mission, _, err := scope.LoadMission(srcForScope, opts.RepoRoot, primary); err == nil {
				scopeClf.MissionMarkdown = mission
			}
			if srcForScope != "" {
				if one, err := loadOnePackage(srcForScope); err == nil {
					siblingPkgs = []adversaries.Package{one}
					opts.AdversaryName = resolvePrimaryAdversaryName(opts, siblingPkgs)
					scopeClf.AdversaryName = opts.AdversaryName
				}
			}
		} else {
			if len(opts.TrainOnlyIDs) > 0 {
				filtered := adversaries.FilterByIDs(siblingPkgs, opts.TrainOnlyIDs)
				if len(filtered) == 0 {
					fmt.Fprintf(os.Stderr, "note: run.only %v matched no loaded packages %v — keeping all loaded\n",
						opts.TrainOnlyIDs, packageIDs(siblingPkgs))
				} else {
					siblingPkgs = filtered
				}
			}
			if len(siblingPkgs) == 0 {
				return nil, fmt.Errorf("no local adversary packages loaded for train routing")
			}
			var cands []scope.Candidate
			for _, p := range siblingPkgs {
				cands = append(cands, scope.Candidate{
					ID: p.ID, AdversaryName: p.ID, Mission: p.ScopeMarkdown,
					Languages: p.Languages, FileGlobs: p.FileGlobs,
				})
			}
			commentRouter = &scope.Router{Candidates: cands, UseLLM: os.Getenv("OPENAI_API_KEY") != ""}
			fmt.Fprintf(os.Stderr, "Loaded %d adversaries for comment routing: %v\n", len(siblingPkgs), packageIDs(siblingPkgs))
			// Always expand each local package's adversary.yaml uses for product
			// grading. This is independent of official jury enable/disable —
			// uses are part of the package under train, not the catalog jury.
			for _, p := range siblingPkgs {
				if len(p.Uses) == 0 {
					continue
				}
				refs, err := adversaries.ExpandUsesRefs(p)
				if err != nil {
					fmt.Fprintf(os.Stderr, "note: composition expand for %s: %v\n", p.ID, err)
					continue
				}
				fmt.Fprintf(os.Stderr, "  composition %s uses: %s → %d run ref(s)\n",
					p.ID, adversaries.FormatUsesSummary(p), len(refs))
			}
		}
		// Hunt/scorecard primary: loaded packages, not a hard-coded eng-review default.
		opts.AdversaryName = resolvePrimaryAdversaryName(opts, siblingPkgs)
		advPackages = siblingPkgs

		var huntLog []string
		var logMu sync.Mutex
		progress := makeProgress(&huntLog, &logMu)

		// Persist gold into results.db as soon as each PR is kept (survives Ctrl+C).
		onKeep := func(kept []*cases.Case) int {
			added := 0
			for _, c := range kept {
				n, err := results.WriteKeptCase(opts.DataRoot, runID, c)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: results persist: %v\n", err)
					continue
				}
				added += n
			}
			if added > 0 {
				progress("  ↳ saved %d human-concern row(s) to results.db", added)
			}
			return added
		}

		var hunt huntOutcome
		if authorMode {
			hunt = runAuthorHunt(ctx, opts, opts.DataRoot, targetPRs, maxTurns, scopeClf, commentRouter, progress, onKeep)
		} else {
			hunt = runParallelHunt(ctx, opts, catalogRepos, opts.DataRoot, targetPRs, maxTurns, scopeClf, commentRouter, progress, onKeep)
		}
		out.ResultsAdded += hunt.resultsAdded
		rateLimited := hunt.interrupted != nil && collect.IsRateLimit(hunt.interrupted)
		if hunt.interrupted != nil && !rateLimited {
			// Ctrl+C / hard stop — gold already in SQLite.
			out.Message = fmt.Sprintf("train interrupted during hunt (%d result row(s) saved)\n  next: adversary train results ls", out.ResultsAdded)
			return out, hunt.interrupted
		}
		caseList = hunt.caseList
		if len(caseList) == 0 && len(hunt.fallbackCases) > 0 {
			caseList = hunt.fallbackCases
			progress("Using last out-of-scope-only PR for the story (no in-scope gold this hunt)")
		}
		if rateLimited {
			out.Message = fmt.Sprintf("GitHub rate limit during hunt (%d result row(s) saved)\n  wait for quota reset; use --concurrency 1 or 2\n  next: adversary train results ls", out.ResultsAdded)
			if len(caseList) > 0 {
				progress("rate limited — grading %d kept case(s) already collected (no more hunting)", len(caseList))
			}
		}
		if hunt.blocked != nil {
			out.Blocked = hunt.blocked
			_, _ = dataroot.WriteBlocked(opts.DataRoot, runID, *hunt.blocked)
		}
		if hunt.collectClass != "" {
			rcpt.SetStage("collect", hunt.collectClass)
			rcpt.SetStage("reconstruct", dataroot.ClassReal)
		}
		if len(caseList) == 0 {
			if rateLimited {
				rcpt.Finish("partial")
				_, _ = receipt.Save(opts.DataRoot, rcpt)
				out.ExitCode = dataroot.ExitPartial
				return out, nil // soft stop: keep partial results
			}
			if out.Blocked == nil {
				out.Blocked = &dataroot.BlockedResult{
					Dependency:     "github-api",
					Operation:      "collect",
					Classification: "missing-source",
					SanitizedError: fmt.Sprintf("no usable cases after %d turn(s); hunt: %s",
						hunt.turnsUsed, strings.Join(huntLog, "; ")),
					NextAction: "raise --max-turns, pass --pr N, expand config/repositories.json, or --reset-discovery",
					RetrySafe:  true,
				}
			}
			_, _ = dataroot.WriteBlocked(opts.DataRoot, runID, *out.Blocked)
			rcpt.SetStage("collect", dataroot.ClassPartial)
			rcpt.Finish("blocked")
			_, _ = receipt.Save(opts.DataRoot, rcpt)
			out.ExitCode = dataroot.ExitBlocked
			out.Message = out.Blocked.NextAction + "\n" + out.Blocked.SanitizedError
			if out.ResultsAdded > 0 {
				out.Message += fmt.Sprintf("\n%d result row(s) already in results.db — adversary train results ls\n", out.ResultsAdded)
			}
			return out, nil
		}
		rcpt.Notes = fmt.Sprintf("hunt turns=%d in_scope_prs=%d target_prs=%d max_turns=%d concurrency=%d repos=%d; %s",
			hunt.turnsUsed, hunt.prsWithInScope, targetPRs, maxTurns, normalizeConcurrency(opts.Concurrency), len(catalogRepos), strings.Join(huntLog, " | "))
	}

	casesDir := filepath.Join(opts.DataRoot, "runs", runID, "cases")
	_ = securefs.MkdirAll(casesDir)
	var usable []*cases.Case
	for _, c := range caseList {
		if c.Exclusion != nil && c.ReviewEvent.ReviewedSHA == "" {
			_ = cases.SaveJSON(filepath.Join(casesDir, c.ID+"-excluded.json"), c)
			continue
		}
		// Do not force-approve out-of-scope labels. Only in-scope gold counts.
		_ = cases.SaveJSON(filepath.Join(casesDir, c.ID+".json"), c)
		_ = cases.SaveJSON(filepath.Join(opts.DataRoot, "cases", "discovery", c.ID+".json"), c)
		usable = append(usable, c)
		out.CaseIDs = append(out.CaseIDs, c.ID)
	}
	if len(usable) == 0 {
		rcpt.Finish("failed")
		_, _ = receipt.Save(opts.DataRoot, rcpt)
		out.ExitCode = dataroot.ExitFailed
		out.Message = "no usable cases after reconstruction"
		return out, nil
	}

	// --- 2–4. Bundle, checkout, run base reviewers, judge ---
	judgments := map[string]*judge.ReviewJudgment{}
	var allFailures []judge.Failure
	var runtimes []caseRuntime
	runDir := filepath.Join(opts.DataRoot, "runs", runID)
	reviewBlocked := false

	pkgByID := adversaries.ByID(advPackages)
	primaryID := resolvePrimaryAdversaryName(opts, advPackages)
	opts.AdversaryName = primaryID
	// Default adversary path for fixture / fallback (local package, not always eng-review).
	defaultAdvRef := primaryID
	if opts.AdversarySource != "" {
		if abs, err := filepath.Abs(opts.AdversarySource); err == nil {
			if st, err := os.Stat(abs); err == nil && st.IsDir() {
				defaultAdvRef = abs
			}
		}
	} else if p, ok := pkgByID[primaryID]; ok {
		defaultAdvRef = p.Dir
	} else if p, ok := pkgByID["engineering-review"]; ok {
		defaultAdvRef = p.Dir
	}

	for i, c := range usable {
		if err := ctx.Err(); err != nil {
			fmt.Fprintln(os.Stderr, "train interrupted")
			rcpt.Finish("interrupted")
			_, _ = receipt.Save(opts.DataRoot, rcpt)
			out.ExitCode = 130
			out.Failures = allFailures
			out.Message = fmt.Sprintf("train interrupted during grade (%d result row(s) saved)\n  next: adversary train results ls", out.ResultsAdded)
			return out, fmt.Errorf("train interrupted: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Grading case %d/%d: %s\n", i+1, len(usable), c.ID)
		if c.Repository.URL != "" {
			fmt.Fprintf(os.Stderr, "  PR: %s\n", c.Repository.URL)
		}
		// Which adversaries own in-scope gold on this case?
		owners := map[string][]cases.ExpectedConcern{}
		for _, lab := range cases.ApprovedLabels(c.Labels.ExpectedConcerns) {
			own := lab.OwnerAdversary
			if own == "" {
				own = primaryID
			}
			owners[own] = append(owners[own], lab)
			fmt.Fprintf(os.Stderr, "  gold → %s: %s\n", own, softWrapOne(lab.Summary, 80))
		}
		if len(owners) == 0 {
			// Run loaded locals (or primary) for extras — not a hard-coded eng-review.
			if len(advPackages) > 0 {
				for _, p := range advPackages {
					owners[p.ID] = nil
				}
				fmt.Fprintf(os.Stderr, "  (no in-scope gold; still running %s for extras)\n", primaryID)
			} else {
				fmt.Fprintf(os.Stderr, "  (no in-scope gold; still running %s for extras)\n", primaryID)
				owners[primaryID] = nil
			}
		}

		man, err := bundle.BuildFromCase(c)
		if err != nil {
			return nil, err
		}
		_, _ = bundle.SaveManifest(opts.DataRoot, man)
		revProj, err := bundle.ProjectForRole(man, bundle.RoleReviewer)
		if err != nil {
			return nil, err
		}
		if err := bundle.AssertReviewerIsolation(revProj); err != nil {
			return nil, err
		}
		matDir := filepath.Join(runDir, "materialized", c.ID, "reviewer")
		if err := bundle.MaterializeReviewerInput(revProj, matDir); err != nil {
			return nil, err
		}
		rcpt.SetStage("bundle", stageClass(opts))

		owner, repoName := c.Repository.Owner, c.Repository.Name
		if owner == "" {
			owner = opts.Owner
		}
		if repoName == "" {
			repoName = opts.Repo
		}
		co := checkout.PrepareForCaseContext(
			ctx,
			opts.DataRoot, owner, repoName, c.ID,
			c.PullRequest.BaseSHA, c.ReviewEvent.ReviewedSHA,
			opts.Fixture && !opts.Live,
		)
		baseRef, headRef := checkout.ResolveBaseHeadRefs(co)
		repoPath := co.Path

		revOut := filepath.Join(runDir, "reviews", c.ID)
		baseFix := opts.BaselineFixture
		if opts.Fixture && !opts.Live && baseFix == "" {
			baseFix = filepath.Join(opts.RepoRoot, "fixtures", "reviews", "baseline.json")
		}

		bRes, err := runner.RunBaseline(revProj, revOut, baseFix)
		if err != nil {
			return nil, err
		}
		if opts.Live && repoPath == "" {
			bl := &dataroot.BlockedResult{
				Dependency: "git-checkout", Operation: "run-adversary", Classification: "missing-source",
				SanitizedError: co.Error, StagesNotRun: []string{"review"}, RetrySafe: true,
				NextAction: "ensure network access to GitHub for base/head SHAs",
			}
			out.Blocked = bl
			_, _ = dataroot.WriteBlocked(opts.DataRoot, runID, *bl)
			reviewBlocked = true
			rcpt.SetStage("review", dataroot.ClassPartial)
			runtimes = append(runtimes, caseRuntime{Case: c, Proj: revProj})
			continue
		}

		// Run each owning adversary; judge only against its gold labels.
		var combinedFails []judge.Failure
		var primaryNorm *normalize.Review
		var primaryJ *judge.ReviewJudgment
		var lastRaw []byte
		for ownerID, gold := range owners {
			advRef := defaultAdvRef
			if p, ok := pkgByID[ownerID]; ok {
				advRef = p.Dir
			} else if ownerID == primaryID || ownerID == "engineering-review" {
				advRef = defaultAdvRef
			} else {
				fmt.Fprintf(os.Stderr, "  skip %s: package not found as sibling\n", ownerID)
				// Still record misses for missing package
				if len(gold) > 0 {
					fake := &normalize.Review{ReviewerID: ownerID, Findings: nil}
					j := judge.JudgeReview(fake, gold)
					for _, f := range judge.ExtractFailures(c.ID, j) {
						f.ReviewerID = ownerID
						f.Detail = f.Detail + " [owner=" + ownerID + "]"
						combinedFails = append(combinedFails, f)
					}
				}
				continue
			}
			fixturePath := ""
			if opts.Fixture && !opts.Live && ownerID == "engineering-review" {
				fixturePath = filepath.Join(opts.RepoRoot, "fixtures", "reviews", "engineering-review.json")
			}
			if p, ok := pkgByID[ownerID]; ok && len(p.Uses) > 0 {
				fmt.Fprintf(os.Stderr, "  running adversary %s (with composition uses) …\n", ownerID)
			} else {
				fmt.Fprintf(os.Stderr, "  running adversary %s …\n", ownerID)
			}
			// Product run expands adversary.yaml uses via CLI (not gated by official jury).
			eRes, err := runner.RunEngineeringReviewContext(ctx, revProj, revOut, repoPath, baseRef, headRef, advRef, fixturePath)
			if err != nil {
				return nil, err
			}
			if eRes.Blocked != nil && opts.Live {
				out.Blocked = eRes.Blocked
				_, _ = dataroot.WriteBlocked(opts.DataRoot, runID, *eRes.Blocked)
				reviewBlocked = true
				// Count all gold as misses for this owner
				fake := &normalize.Review{ReviewerID: ownerID}
				j := judge.JudgeReview(fake, gold)
				for _, f := range judge.ExtractFailures(c.ID, j) {
					f.ReviewerID = ownerID
					combinedFails = append(combinedFails, f)
				}
				continue
			}
			rcpt.Reviewers = append(rcpt.Reviewers,
				receipt.ReviewerReceipt{Identity: bRes.ReviewerID, Kind: bRes.Kind, ExecutionClass: bRes.ExecutionClass, LatencyMS: bRes.LatencyMS, Artifact: bRes.ArtifactPath},
				receipt.ReviewerReceipt{Identity: ownerID, Kind: "adversary", ExecutionClass: eRes.ExecutionClass, ExitCode: eRes.ExitCode, LatencyMS: eRes.LatencyMS, Artifact: eRes.ArtifactPath},
			)
			if !looksJSON(eRes.RawJSON) {
				reviewBlocked = true
				fake := &normalize.Review{ReviewerID: ownerID}
				j := judge.JudgeReview(fake, gold)
				for _, f := range judge.ExtractFailures(c.ID, j) {
					f.ReviewerID = ownerID
					combinedFails = append(combinedFails, f)
				}
				continue
			}
			nRev, err := normalize.FromAnyJSON(ownerID, eRes.RawJSON)
			if err != nil {
				return nil, fmt.Errorf("normalize review for %s on case %s: %w", ownerID, c.ID, err)
			}
			nRev.ReviewerID = ownerID
			normPath := filepath.Join(runDir, "normalized", c.ID+"-"+ownerID+".json")
			_ = securefs.MkdirAll(filepath.Dir(normPath))
			rawN, _ := normalize.ToJSON(nRev)
			_ = securefs.WriteFile(normPath, rawN)
			// Judge only this owner's gold (may be empty → only extras matter)
			j := judge.JudgeReview(nRev, gold)
			j.ReviewerID = ownerID
			for _, f := range judge.ExtractFailures(c.ID, j) {
				f.ReviewerID = ownerID
				f.Detail = f.Detail + " [owner=" + ownerID + "]"
				combinedFails = append(combinedFails, f)
			}
			jPath := filepath.Join(runDir, "judgments", c.ID+"-"+ownerID+".json")
			_ = securefs.MkdirAll(filepath.Dir(jPath))
			jr, _ := json.MarshalIndent(j, "", "  ")
			_ = securefs.WriteFile(jPath, jr)
			if primaryNorm == nil {
				primaryNorm = nRev
				primaryJ = j
				lastRaw = eRes.RawJSON
			}
			rcpt.SetStage("review", eRes.ExecutionClass)
			rcpt.SetStage("normalize", eRes.ExecutionClass)
			rcpt.SetStage("judge", dataroot.ClassFixture)
			_ = lastRaw
		}

		// Merge judgments for scorecard: use primary + all failures
		if primaryJ == nil {
			primaryJ = &judge.ReviewJudgment{ReviewerID: "multi"}
		}
		// Recompute expected missed from combined fails for scorecard-friendly judgment
		judgments[c.ID] = primaryJ
		allFailures = append(allFailures, combinedFails...)
		runtimes = append(runtimes, caseRuntime{
			Case: c, Proj: revProj, RepoPath: repoPath, BaseRef: baseRef, HeadRef: headRef,
			BaseRaw: bRes.RawJSON, EngRaw: lastRaw, Judgment: primaryJ, Norm: primaryNorm,
		})

		// Progressive results: upgrade gold → miss/caught immediately after each case.
		if n, err := results.WriteGradedCase(opts.DataRoot, runID, c, combinedFails); err != nil {
			fmt.Fprintf(os.Stderr, "warning: results grade persist: %v\n", err)
		} else if n > 0 {
			out.ResultsAdded += n
			fmt.Fprintf(os.Stderr, "  ↳ updated %d result row(s) in results.db\n", n)
		}
	}

	if len(judgments) == 0 && reviewBlocked {
		// Still write a story so the user sees real PR links and what blocked the grade.
		blockedNote := primaryID + " did not produce a usable review for grading."
		if out.Blocked != nil {
			blockedNote = out.Blocked.SanitizedError + " — next: " + out.Blocked.NextAction
		}
		expDir := filepath.Join(opts.DataRoot, "experiments", runID)
		_ = securefs.MkdirAll(expDir)
		locIDs, offIDs := trainDraftContext(opts, advPackages)
		human, err := report.Write(report.Input{
			RunID: runID, DataRoot: opts.DataRoot, RunDir: runDir, ExperimentDir: expDir,
			Live: true, Cases: usable, BlockedNote: blockedNote,
			LocalIDs: locIDs, OfficialIDs: offIDs,
		})
		if err == nil {
			out.HumanReport = human
			out.Message = human.CLIBlock + "\nBlocked before grading:\n  " + blockedNote + "\n"
		} else {
			out.Message = blockedNote
		}
		rcpt.Finish("blocked")
		_, _ = receipt.Save(opts.DataRoot, rcpt)
		out.ExitCode = dataroot.ExitBlocked
		return out, nil
	}

	if len(allFailures) == 0 && len(judgments) > 0 {
		// Honest empty-failure list — do not invent placeholder failures that skew critic.
		// Critic still needs at least one signal if scorecard is perfect; emit scorecard-only path.
	}

	sc := score.Aggregate(primaryID, judgments, allFailures)
	scoreDir := filepath.Join(runDir, "reports")
	if err := score.Save(scoreDir, sc); err != nil {
		return nil, err
	}
	_ = score.Save(filepath.Join(opts.DataRoot, "reports", runID), sc)
	rcpt.SetStage("scorecard", dataroot.ClassFixture)
	out.Scorecard = sc
	out.Failures = allFailures

	// --- 5. Critic (only when there are real failures) ---
	expDir := filepath.Join(opts.DataRoot, "experiments", runID)
	var hyps []critic.Hypothesis
	var prop *optimizer.Proposal
	var rec *optimizer.ExperimentRecord
	if len(allFailures) > 0 {
		hyps = critic.AnalyzeFailures(allFailures, primaryID)
		out.Hypotheses = hyps
		hypPath := filepath.Join(runDir, "critic", "hypotheses.json")
		_ = securefs.MkdirAll(filepath.Dir(hypPath))
		hr, _ := json.MarshalIndent(hyps, "", "  ")
		_ = securefs.WriteFile(hypPath, hr)
		rcpt.SetStage("critic", dataroot.ClassFixture)

		// --- 6. Optimizer propose ---
		var err error
		prop, rec, err = optimizer.Propose(hyps, primaryID, "local", out.CaseIDs, expDir)
		if err != nil {
			return nil, err
		}
	} else {
		// Clean run: no critic/optimizer noise.
		_ = securefs.MkdirAll(expDir)
		rcpt.SetStage("critic", dataroot.ClassFixture)
		rec = &optimizer.ExperimentRecord{
			ID:              fmt.Sprintf("exp-%d-clean", time.Now().UTC().Unix()),
			Status:          "proposed",
			TargetAdversary: primaryID,
			Hypothesis:      "No in-scope misses this run; no improvement proposal.",
			CaseIDs:         out.CaseIDs,
			CreatedAt:       time.Now().UTC(),
		}
		prop = &optimizer.Proposal{ID: rec.ID, PatchPath: "", Status: "proposed"}
	}
	if prop == nil {
		prop = &optimizer.Proposal{ID: "none", Status: "proposed"}
	}
	if rec == nil {
		rec = &optimizer.ExperimentRecord{ID: "none", Status: "proposed", TargetAdversary: primaryID}
	}
	out.Proposal = prop
	out.Experiment = rec
	rcpt.SetStage("propose", dataroot.ClassFixture)

	// --- 7. Candidate build + remeasure (or honest identical_to_base) ---
	var build experiment.BuildResult
	var rep *experiment.Report
	mode := "identical_to_base"
	remeasuredClass := dataroot.ClassFixture
	if prop.PatchPath != "" {
		improvementMD, _ := os.ReadFile(filepath.Join(expDir, prop.ID+"-IMPROVEMENT.md"))
		src := opts.AdversarySource
		if src == "" {
			if p, ok := pkgByID[primaryID]; ok {
				src = p.Dir
			} else {
				for _, candName := range []string{primaryID + "-adversary", "engineering-review-adversary"} {
					cand := filepath.Join(filepath.Dir(opts.RepoRoot), candName)
					if st, err := os.Stat(cand); err == nil && st.IsDir() {
						src = cand
						break
					}
				}
			}
		}
		var err error
		build, err = experiment.ApplyProposalToWorktree(opts.DataRoot, src, string(improvementMD), rec.ID)
		if err != nil {
			return nil, err
		}
		var candSC *score.Scorecard
		candSC, mode, remeasuredClass = remeasureCandidate(opts, runDir, build, runtimes)
		if candSC == nil {
			candSC = experiment.CopyScorecardAsCandidate(sc)
			mode = "identical_to_base"
		}
		rep = experiment.AssembleReport(rec, sc, candSC, build, mode)
	} else {
		build = experiment.BuildResult{OK: true, Method: "skipped-no-proposal"}
		rep = experiment.AssembleReport(rec, sc, experiment.CopyScorecardAsCandidate(sc), build, "identical_to_base")
	}
	repDir := filepath.Join(expDir, "report")
	if err := experiment.SaveReport(repDir, rep); err != nil {
		return nil, err
	}
	out.Report = rep
	rcpt.SetStage("experiment", remeasuredClass)

	// --- 8. Human-readable report (README.md in the run directory) ---
	normByCase := map[string]*normalize.Review{}
	for _, rt := range runtimes {
		if rt.Case != nil && rt.Norm != nil {
			normByCase[rt.Case.ID] = rt.Norm
		}
	}
	blockedNote := ""
	if out.Blocked != nil {
		blockedNote = out.Blocked.SanitizedError + " — next: " + out.Blocked.NextAction
	}
	locIDs, offIDs := trainDraftContext(opts, advPackages)
	// Also compute official catches from judgments (matching findings on gold).
	officialCatch := map[string]string{}
	for caseID, j := range judgments {
		if j == nil {
			continue
		}
		for _, mid := range j.ExpectedMatched {
			// If primary reviewer was official and matched, record catch.
			rev := j.ReviewerID
			if rev != "" && offIDs[strings.ToLower(rev)] {
				officialCatch[mid] = rev
			}
			// Any matched concern by an official-owned judgment path
			_ = caseID
		}
	}
	// From failures: if a concern was matched by official in another judgment, suppress.
	// When owner of gold is official and they have matches elsewhere, still no local draft (handled in report).

	human, err := report.Write(report.Input{
		RunID:                  runID,
		DataRoot:               opts.DataRoot,
		RunDir:                 runDir,
		ExperimentDir:          expDir,
		Fixture:                opts.Fixture,
		Live:                   opts.Live,
		Scorecard:              sc,
		Cases:                  usable,
		Judgments:              judgments,
		NormReviews:            normByCase,
		Hypotheses:             hyps,
		Experiment:             rep,
		ProposalPatch:          prop.PatchPath,
		BlockedNote:            blockedNote,
		LocalIDs:               locIDs,
		OfficialIDs:            offIDs,
		OfficialCatchByConcern: officialCatch,
	})
	if err != nil {
		return nil, err
	}
	out.HumanReport = human

	// Inbox rows for: adversary train results ls / inspect / apply
	var issues []report.SuggestedIssue
	if human != nil {
		issues = human.Issues
	}
	if n, err := results.WriteFromRun(opts.DataRoot, results.WriteInput{
		RunID:    runID,
		Cases:    usable,
		Failures: allFailures,
		Issues:   issues,
	}); err == nil {
		out.ResultsAdded = n
	} else {
		fmt.Fprintf(os.Stderr, "warning: results index: %v\n", err)
	}

	status := "success"
	exit := dataroot.ExitSuccess
	if out.Blocked != nil || reviewBlocked {
		status = "partial"
		exit = dataroot.ExitPartial
	}
	rcpt.CaseIDs = out.CaseIDs
	rcpt.Finish(status)
	if err := receipt.Verify(rcpt); err != nil {
		return nil, err
	}
	if _, err := receipt.Save(opts.DataRoot, rcpt); err != nil {
		return nil, err
	}
	out.ExitCode = exit
	// Message is the full plain-English CLI block only.
	out.Message = human.CLIBlock
	return out, nil
}

// remeasureCandidate re-runs engineering-review from the candidate worktree when possible.
// Returns scorecard, mode ("remeasured"|"identical_to_base"), and execution class for the stage.
func remeasureCandidate(opts Options, runDir string, build experiment.BuildResult, runtimes []caseRuntime) (*score.Scorecard, string, dataroot.ExecutionClass) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx // used by RunEngineeringReviewContext below
	// Need a candidate package path and at least one case with a repo path for real remeasure.
	if !build.OK || build.WorktreePath == "" {
		return nil, "identical_to_base", dataroot.ClassFixture
	}

	// Fixture mode with fixture reviews: re-running adversary may work on synthetic checkout,
	// but if EngineeringFixture was used for base, candidate remeasure must not re-read the same
	// fixture and claim improvement. Prefer real CLI against candidate path when no fixture forced.
	useFixture := opts.Fixture && !opts.Live && opts.EngineeringFixture == "" &&
		fileExists(filepath.Join(opts.RepoRoot, "fixtures", "reviews", "engineering-review.json"))

	// If we only ever had fixture reviews and no real path, remeasure with same fixture would
	// fabricate no delta only if we treat as identical — use real adversary on worktree when checkout exists.
	candJudgments := map[string]*judge.ReviewJudgment{}
	var candFailures []judge.Failure
	anyReal := false
	anyRun := false

	for _, rt := range runtimes {
		if rt.Case == nil || rt.Proj == nil {
			continue
		}
		if rt.RepoPath == "" {
			continue
		}
		outDir := filepath.Join(runDir, "reviews-candidate", rt.Case.ID)
		// Point adversary at local candidate project.
		ref := build.WorktreePath
		var engFix string
		// Never pass the base fixture as candidate "remeasure" — that would fake independence.
		// Only use fixture for candidate if explicitly requested via EngineeringFixture empty + fixture mode
		// AND we intentionally skip remeasure (identical). Prefer CLI.
		_ = useFixture
		eRes, err := runner.RunEngineeringReviewContext(ctx, rt.Proj, outDir, rt.RepoPath, rt.BaseRef, rt.HeadRef, ref, engFix)
		if err != nil || eRes == nil {
			continue
		}
		if eRes.Blocked != nil || len(eRes.RawJSON) == 0 {
			continue
		}
		anyRun = true
		if eRes.ExecutionClass == dataroot.ClassReal {
			anyReal = true
		}
		nRev, err := normalize.FromAnyJSON("engineering-review-candidate", eRes.RawJSON)
		if err != nil {
			continue
		}
		j := judge.JudgeReview(nRev, rt.Case.Labels.ExpectedConcerns)
		candJudgments[rt.Case.ID] = j
		candFailures = append(candFailures, judge.ExtractFailures(rt.Case.ID, j)...)
	}

	if !anyRun || len(candJudgments) == 0 {
		return nil, "identical_to_base", dataroot.ClassFixture
	}
	sc := score.Aggregate("engineering-review-candidate", candJudgments, candFailures)
	class := dataroot.ClassFixture
	if anyReal {
		class = dataroot.ClassReal
	}
	return sc, "remeasured", class
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func workspaceAuthorOK(login string, only, ignore []string) bool {
	// Inline to avoid import cycle with workspace; mirrors workspace.AuthorAllowed.
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return false
	}
	for _, ig := range ignore {
		if login == strings.ToLower(strings.TrimSpace(ig)) {
			return false
		}
	}
	if len(only) == 0 {
		return true
	}
	for _, o := range only {
		if login == strings.ToLower(strings.TrimSpace(o)) {
			return true
		}
	}
	return false
}

func loadOnePackage(dir string) (adversaries.Package, error) {
	pkgs, err := adversaries.DiscoverRoot(dir)
	if err != nil {
		return adversaries.Package{}, err
	}
	if len(pkgs) == 0 {
		return adversaries.Package{}, fmt.Errorf("no package at %s", dir)
	}
	// Prefer exact dir match
	for _, p := range pkgs {
		if p.Dir == dir {
			return p, nil
		}
	}
	return pkgs[0], nil
}

func packageIDs(pkgs []adversaries.Package) []string {
	ids := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.ID != "" {
			ids = append(ids, p.ID)
		} else if p.DirName != "" {
			ids = append(ids, p.DirName)
		}
	}
	return ids
}

// resolvePrimaryAdversaryName picks the hunt/scorecard package id.
// Prefers an explicit Options.AdversaryName, then loaded local packages,
// then AdversarySource basename, then engineering-review as last resort.
func resolvePrimaryAdversaryName(opts Options, pkgs []adversaries.Package) string {
	if name := strings.TrimSpace(opts.AdversaryName); name != "" {
		// Multi-package labels from a prior resolve are fine to keep.
		return name
	}
	if len(opts.TrainOnlyIDs) == 1 {
		id := strings.TrimSpace(opts.TrainOnlyIDs[0])
		if id != "" {
			return packageIDFromName(id)
		}
	}
	if len(pkgs) == 1 {
		return pkgs[0].ID
	}
	if len(pkgs) > 1 {
		var ids []string
		for _, p := range pkgs {
			if p.ID != "" {
				ids = append(ids, p.ID)
			}
		}
		if len(ids) == 1 {
			return ids[0]
		}
		if len(ids) > 1 {
			// Stable multi-package hunt label (not eng-review).
			sort.Strings(ids)
			return strings.Join(ids, "+")
		}
	}
	if opts.AdversarySource != "" {
		return packageIDFromName(filepath.Base(opts.AdversarySource))
	}
	if len(opts.LocalIDs) == 1 {
		return packageIDFromName(opts.LocalIDs[0])
	}
	if len(opts.LocalPackageDirs) == 1 {
		return packageIDFromName(filepath.Base(opts.LocalPackageDirs[0]))
	}
	return "engineering-review"
}

// packageIDFromName normalizes a directory or package name to a short id
// (go-concurrency-adversary → go-concurrency).
func packageIDFromName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "/")
	name = filepath.Base(name)
	return strings.TrimSuffix(name, "-adversary")
}

// trainDraftContext builds local/official id sets for report draft filtering.
// Composition members are not loaded into pkgs, so only explicit local package
// roots can become draft targets.
func trainDraftContext(opts Options, pkgs []adversaries.Package) (localIDs, officialIDs map[string]bool) {
	localIDs = map[string]bool{}
	officialIDs = map[string]bool{}
	for _, id := range opts.LocalIDs {
		id = packageIDFromName(id)
		if id != "" {
			localIDs[strings.ToLower(id)] = true
		}
	}
	for _, id := range opts.OfficialIDs {
		officialIDs[strings.ToLower(id)] = true
	}
	// Merge loaded **local** package ids so drafts match router owner ids
	// (e.g. go-concurrency) even when CLI LocalIDs used directory basenames.
	for _, p := range pkgs {
		localIDs[strings.ToLower(p.ID)] = true
		if p.ManifestName != "" {
			localIDs[strings.ToLower(p.ManifestName)] = true
		}
		if p.DirName != "" {
			localIDs[strings.ToLower(packageIDFromName(p.DirName))] = true
		}
	}
	// Explicit official list only; unknowns default to local when listed as packages.
	return localIDs, officialIDs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func softWrapOne(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func looksJSON(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func stageClass(opts Options) dataroot.ExecutionClass {
	if opts.Live && !opts.Fixture {
		return dataroot.ClassReal
	}
	return dataroot.ClassFixture
}

func weakestClass(a, b dataroot.ExecutionClass) dataroot.ExecutionClass {
	rank := map[dataroot.ExecutionClass]int{
		dataroot.ClassReal: 5, dataroot.ClassReplayed: 4, dataroot.ClassFixture: 3,
		dataroot.ClassPartial: 2, dataroot.ClassMock: 1,
	}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

func loadFixtureCases(opts Options) ([]*cases.Case, error) {
	dir := opts.CaseFixtureDir
	if dir == "" {
		dir = filepath.Join(opts.RepoRoot, "fixtures", "cases")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*cases.Case
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		c, err := cases.Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no fixture cases in %s", dir)
	}
	return out, nil
}
