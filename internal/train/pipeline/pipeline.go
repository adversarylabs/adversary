package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/adversarylabs/adversary/internal/train/runner"
	"github.com/adversarylabs/adversary/internal/train/scope"
	"github.com/adversarylabs/adversary/internal/train/score"
	"github.com/adversarylabs/adversary/internal/train/state"
)

// Options for the first-slice end-to-end path.
type Options struct {
	DataRoot           string
	RepoRoot           string // factory repo root
	Fixture            bool   // tests only; production path is always live discovery
	Live               bool   // default true when Fixture is false
	Owner              string // optional single-repo pin (with Repo)
	Repo               string
	PR                 int // optional single PR; 0 = discover live
	// ReposFile is path to repositories.json (default: <RepoRoot>/config/repositories.json).
	ReposFile string
	// Languages filters the catalog (empty = any language; engineering-review uses any).
	// Example: []string{"go"} for go-security.
	Languages []string
	// AdversaryName for scope docs and future language defaults (default engineering-review).
	AdversaryName string
	// MaxPRs is how many usable PRs we want to grade this run (default 1).
	MaxPRs int
	// MaxTurns is how many PRs we may attempt while hunting (default 15).
	// Each turn = try one not-yet-seen PR (collect + scope). Stops early when MaxPRs usable cases collected.
	MaxTurns int
	// ResetDiscovery clears seen-PR state for repos we touch before hunting.
	ResetDiscovery bool
	AdversarySource    string
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
	ExitCode    int
	Blocked     *dataroot.BlockedResult
	Message     string
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
	if opts.DataRoot == "" {
		return nil, fmt.Errorf("data root required")
	}
	if err := os.MkdirAll(opts.DataRoot, 0o755); err != nil {
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
		if opts.AdversaryName == "" {
			opts.AdversaryName = "engineering-review"
		}
		targetPRs := opts.MaxPRs
		if targetPRs <= 0 {
			targetPRs = 1
		}
		maxTurns := opts.MaxTurns
		if maxTurns <= 0 {
			maxTurns = 15
		}

		// Build the set of repos to hunt across.
		var catalogRepos []repos.Repo
		if opts.Owner != "" && opts.Repo != "" {
			catalogRepos = []repos.Repo{{Owner: opts.Owner, Name: opts.Repo, Languages: opts.Languages, Role: "discovery"}}
		} else {
			catPath := opts.ReposFile
			if catPath == "" && opts.RepoRoot != "" {
				catPath = repos.DefaultPath(opts.RepoRoot)
			}
			if catPath == "" {
				return nil, fmt.Errorf("no repositories catalog (set RepoRoot or ReposFile)")
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

		// Discover sibling adversaries and build multi-scope router.
		var scopeClf *scope.Classifier
		var commentRouter *scope.Router
		siblingPkgs, err := adversaries.DiscoverSiblings(opts.RepoRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "note: sibling adversary discovery: %v (falling back to engineering-review only)\n", err)
			scopeClf = &scope.Classifier{AdversaryName: "engineering-review", UseLLM: os.Getenv("OPENAI_API_KEY") != ""}
			srcForScope := opts.AdversarySource
			if srcForScope == "" && opts.RepoRoot != "" {
				cand := filepath.Join(filepath.Dir(opts.RepoRoot), "engineering-review-adversary")
				if st, err := os.Stat(cand); err == nil && st.IsDir() {
					srcForScope = cand
				}
			}
			if mission, _, err := scope.LoadMission(srcForScope, opts.RepoRoot, "engineering-review"); err == nil {
				scopeClf.MissionMarkdown = mission
			}
		} else {
			var cands []scope.Candidate
			for _, p := range siblingPkgs {
				cands = append(cands, scope.Candidate{
					ID: p.ID, AdversaryName: p.ID, Mission: p.ScopeMarkdown,
					Languages: p.Languages, FileGlobs: p.FileGlobs,
				})
			}
			commentRouter = &scope.Router{Candidates: cands, UseLLM: os.Getenv("OPENAI_API_KEY") != ""}
			fmt.Fprintf(os.Stderr, "Loaded %d sibling adversaries for comment routing\n", len(siblingPkgs))
		}
		advPackages = siblingPkgs

		// Per-repo discovery stores (skip already-seen PRs).
		stores := map[string]*state.DiscoveryStore{}
		storeFor := func(owner, name string) (*state.DiscoveryStore, error) {
			key := owner + "/" + name
			if s, ok := stores[key]; ok {
				return s, nil
			}
			s, err := state.LoadDiscovery(opts.DataRoot, owner, name)
			if err != nil {
				return nil, err
			}
			if opts.ResetDiscovery {
				s.PRs = map[string]state.PRRecord{}
				_ = s.Save()
			}
			stores[key] = s
			return s, nil
		}

		huntLog := []string{}
		turnsUsed := 0
		prsWithInScope := 0
		var fallbackCases []*cases.Case

		progress := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			fmt.Fprintln(os.Stderr, msg)
			huntLog = append(huntLog, strings.TrimSpace(msg))
		}

		tryPR := func(owner, name string, ref collect.PRRef, store *state.DiscoveryStore, pinned bool) {
			turnsUsed++
			title := ref.Title
			if title == "" {
				title = "(title loading…)"
			}
			url := ref.URL
			if url == "" {
				url = fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, name, ref.Number)
			}
			progress("→ turn %d/%d: trying %s/%s#%d — %s", turnsUsed, maxTurns, owner, name, ref.Number, title)
			progress("  %s", url)
			progress("  collecting reviews and comments…")

			cres, err := collect.CollectPRWithOptions(opts.DataRoot, owner, name, ref.Number, collect.CollectOptions{
				Scope:  scopeClf,
				Router: commentRouter,
			})
			if err != nil {
				store.Record(ref.Number, ref.Title, ref.URL, state.OutcomeBlocked, err.Error())
				_ = store.Save()
				progress("  ✗ collect error: %v", err)
				return
			}
			if cres.Blocked != nil {
				out.Blocked = cres.Blocked
				_, _ = dataroot.WriteBlocked(opts.DataRoot, runID, *cres.Blocked)
				store.Record(ref.Number, ref.Title, ref.URL, state.OutcomeBlocked, cres.Blocked.SanitizedError)
				_ = store.Save()
				progress("  ✗ blocked (%s): %s", cres.Blocked.Classification, cres.Blocked.SanitizedError)
				return
			}
			var kept []*cases.Case
			inScopeN := 0
			outScopeN := 0
			for _, c := range cres.CaseCandidates {
				if c.Exclusion != nil && c.ReviewEvent.ReviewedSHA == "" {
					continue
				}
				kept = append(kept, c)
				inScopeN += len(cases.ApprovedLabels(c.Labels.ExpectedConcerns))
				outScopeN += len(cases.OutOfScopeLabels(c.Labels.ExpectedConcerns))
			}
			if len(kept) == 0 {
				store.Record(ref.Number, ref.Title, ref.URL, state.OutcomeNoCases, "no reconstructable review rounds")
				_ = store.Save()
				progress("  ✗ no usable review rounds — skip")
				return
			}
			rcpt.SetStage("collect", cres.ExecutionClass)
			rcpt.SetStage("reconstruct", dataroot.ClassReal)
			outcome := state.OutcomeNoInScope
			note := "out of scope only — keep hunting"
			if inScopeN > 0 {
				caseList = append(caseList, kept...)
				outcome = state.OutcomeGraded
				note = fmt.Sprintf("%d in-scope concern(s) — keep", inScopeN)
				prsWithInScope++
				progress("  ✓ keep: %d in-scope, %d out-of-scope human comment(s)", inScopeN, outScopeN)
			} else {
				fallbackCases = kept
				progress("  · no in-scope comments (%d out-of-scope) — keep hunting", outScopeN)
			}
			if pinned {
				outcome = state.OutcomePinned
				if inScopeN == 0 {
					caseList = append(caseList, kept...)
				}
			}
			store.Record(ref.Number, ref.Title, ref.URL, outcome, note)
			_ = store.Save()
		}

		if opts.PR > 0 {
			owner, name := opts.Owner, opts.Repo
			if owner == "" || name == "" {
				if len(catalogRepos) > 0 {
					owner, name = catalogRepos[0].Owner, catalogRepos[0].Name
				} else {
					return nil, fmt.Errorf("--pr requires --owner and --repo (or a non-empty catalog)")
				}
			}
			store, err := storeFor(owner, name)
			if err != nil {
				return nil, err
			}
			progress("Pinned PR mode: %s/%s#%d", owner, name, opts.PR)
			ref := collect.PRRef{
				Number: opts.PR,
				URL:    fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, name, opts.PR),
			}
			tryPR(owner, name, ref, store, true)
		} else {
			langNote := "any language"
			if len(opts.Languages) > 0 {
				langNote = "languages=" + strings.Join(opts.Languages, ",")
			}
			progress("Hunting across %d repos (%s) for %s", len(catalogRepos), langNote, opts.AdversaryName)
			progress("max-turns=%d, target in-scope PRs=%d", maxTurns, targetPRs)

			// Round-robin repos so we don't burn all turns on one project.
			repoIdx := 0
			for turnsUsed < maxTurns && prsWithInScope < targetPRs {
				if len(catalogRepos) == 0 {
					break
				}
				// Try each repo once per outer cycle until a PR is attempted.
				started := repoIdx
				attempted := false
				for {
					r := catalogRepos[repoIdx%len(catalogRepos)]
					repoIdx++
					store, err := storeFor(r.Owner, r.Name)
					if err != nil {
						progress("  state error for %s: %v", r.FullName(), err)
						if repoIdx%len(catalogRepos) == started%len(catalogRepos) {
							break
						}
						continue
					}
					progress("Looking for new PRs in %s (seen %d)…", r.FullName(), len(store.SeenSet()))
					found, err := collect.DiscoverPRsWithOpts(r.Owner, r.Name, collect.DiscoverOpts{
						Limit: 3,
						Skip:  store.SeenSet(),
					})
					if err != nil {
						progress("  no new PRs in %s: %v", r.FullName(), err)
						if repoIdx%len(catalogRepos) == started%len(catalogRepos) && !attempted {
							// Full cycle with no candidates anywhere.
							progress("All catalog repos exhausted of new PRs this cycle")
							goto huntDone
						}
						continue
					}
					for _, ref := range found {
						if turnsUsed >= maxTurns || prsWithInScope >= targetPRs {
							break
						}
						if store.Seen(ref.Number) {
							continue
						}
						store.Record(ref.Number, ref.Title, ref.URL, state.OutcomeAttempted, "in progress")
						_ = store.Save()
						tryPR(r.Owner, r.Name, ref, store, false)
						attempted = true
						// One PR per repo visit, then rotate.
						break
					}
					if attempted || turnsUsed >= maxTurns || prsWithInScope >= targetPRs {
						break
					}
					if repoIdx%len(catalogRepos) == started%len(catalogRepos) {
						progress("Cycled all repos without a new attempt — stopping")
						goto huntDone
					}
				}
				if !attempted {
					progress("No progress this cycle — stopping hunt")
					break
				}
			}
		huntDone:
			progress("Hunt finished: turns=%d, in-scope PRs kept=%d", turnsUsed, prsWithInScope)
		}
		if len(caseList) == 0 && len(fallbackCases) > 0 {
			caseList = fallbackCases
			progress("Using last out-of-scope-only PR for the story (no in-scope gold this hunt)")
		}
		for _, s := range stores {
			_ = s.Save()
		}

		if len(caseList) == 0 {
			if out.Blocked == nil {
				out.Blocked = &dataroot.BlockedResult{
					Dependency:     "github-api",
					Operation:      "collect",
					Classification: "missing-source",
					SanitizedError: fmt.Sprintf("no usable cases after %d turn(s); hunt: %s",
						turnsUsed, strings.Join(huntLog, "; ")),
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
			return out, nil
		}
		rcpt.Notes = fmt.Sprintf("hunt turns=%d in_scope_prs=%d target_prs=%d max_turns=%d repos=%d; %s",
			turnsUsed, prsWithInScope, targetPRs, maxTurns, len(catalogRepos), strings.Join(huntLog, " | "))
	}

	casesDir := filepath.Join(opts.DataRoot, "runs", runID, "cases")
	_ = os.MkdirAll(casesDir, 0o755)
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
	// Default eng-review path for fixture / fallback.
	defaultAdvRef := "engineering-review"
	if opts.AdversarySource != "" {
		if abs, err := filepath.Abs(opts.AdversarySource); err == nil {
			if st, err := os.Stat(abs); err == nil && st.IsDir() {
				defaultAdvRef = abs
			}
		}
	} else if p, ok := pkgByID["engineering-review"]; ok {
		defaultAdvRef = p.Dir
	}

	for i, c := range usable {
		fmt.Fprintf(os.Stderr, "Grading case %d/%d: %s\n", i+1, len(usable), c.ID)
		if c.Repository.URL != "" {
			fmt.Fprintf(os.Stderr, "  PR: %s\n", c.Repository.URL)
		}
		// Which adversaries own in-scope gold on this case?
		owners := map[string][]cases.ExpectedConcern{}
		for _, lab := range cases.ApprovedLabels(c.Labels.ExpectedConcerns) {
			own := lab.OwnerAdversary
			if own == "" {
				own = "engineering-review"
			}
			owners[own] = append(owners[own], lab)
			fmt.Fprintf(os.Stderr, "  gold → %s: %s\n", own, softWrapOne(lab.Summary, 80))
		}
		if len(owners) == 0 {
			fmt.Fprintf(os.Stderr, "  (no in-scope gold; still running engineering-review for extras)\n")
			owners["engineering-review"] = nil
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
		co := checkout.PrepareForCase(
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
			} else if ownerID == "engineering-review" {
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
			fmt.Fprintf(os.Stderr, "  running adversary %s …\n", ownerID)
			eRes, err := runner.RunEngineeringReview(revProj, revOut, repoPath, baseRef, headRef, advRef, fixturePath)
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
				reviewBlocked = true
				continue
			}
			nRev.ReviewerID = ownerID
			normPath := filepath.Join(runDir, "normalized", c.ID+"-"+ownerID+".json")
			_ = os.MkdirAll(filepath.Dir(normPath), 0o755)
			rawN, _ := normalize.ToJSON(nRev)
			_ = os.WriteFile(normPath, rawN, 0o644)
			// Judge only this owner's gold (may be empty → only extras matter)
			j := judge.JudgeReview(nRev, gold)
			j.ReviewerID = ownerID
			for _, f := range judge.ExtractFailures(c.ID, j) {
				f.ReviewerID = ownerID
				f.Detail = f.Detail + " [owner=" + ownerID + "]"
				combinedFails = append(combinedFails, f)
			}
			jPath := filepath.Join(runDir, "judgments", c.ID+"-"+ownerID+".json")
			_ = os.MkdirAll(filepath.Dir(jPath), 0o755)
			jr, _ := json.MarshalIndent(j, "", "  ")
			_ = os.WriteFile(jPath, jr, 0o644)
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
	}

	if len(judgments) == 0 && reviewBlocked {
		// Still write a story so the user sees real PR links and what blocked the grade.
		blockedNote := "engineering-review did not produce a usable review for grading."
		if out.Blocked != nil {
			blockedNote = out.Blocked.SanitizedError + " — next: " + out.Blocked.NextAction
		}
		expDir := filepath.Join(opts.DataRoot, "experiments", runID)
		_ = os.MkdirAll(expDir, 0o755)
		human, err := report.Write(report.Input{
			RunID: runID, DataRoot: opts.DataRoot, RunDir: runDir, ExperimentDir: expDir,
			Live: true, Cases: usable, BlockedNote: blockedNote,
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

	sc := score.Aggregate("engineering-review", judgments, allFailures)
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
		hyps = critic.AnalyzeFailures(allFailures, "engineering-review")
		out.Hypotheses = hyps
		hypPath := filepath.Join(runDir, "critic", "hypotheses.json")
		_ = os.MkdirAll(filepath.Dir(hypPath), 0o755)
		hr, _ := json.MarshalIndent(hyps, "", "  ")
		_ = os.WriteFile(hypPath, hr, 0o644)
		rcpt.SetStage("critic", dataroot.ClassFixture)

		// --- 6. Optimizer propose ---
		var err error
		prop, rec, err = optimizer.Propose(hyps, "engineering-review", "local", out.CaseIDs, expDir)
		if err != nil {
			return nil, err
		}
	} else {
		// Clean run: no critic/optimizer noise.
		_ = os.MkdirAll(expDir, 0o755)
		rcpt.SetStage("critic", dataroot.ClassFixture)
		rec = &optimizer.ExperimentRecord{
			ID:              fmt.Sprintf("exp-%d-clean", time.Now().UTC().Unix()),
			Status:          "proposed",
			TargetAdversary: "engineering-review",
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
		rec = &optimizer.ExperimentRecord{ID: "none", Status: "proposed", TargetAdversary: "engineering-review"}
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
			cand := filepath.Join(filepath.Dir(opts.RepoRoot), "engineering-review-adversary")
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				src = cand
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
	human, err := report.Write(report.Input{
		RunID:         runID,
		DataRoot:      opts.DataRoot,
		RunDir:        runDir,
		ExperimentDir: expDir,
		Fixture:       opts.Fixture,
		Live:          opts.Live,
		Scorecard:     sc,
		Cases:         usable,
		Judgments:     judgments,
		NormReviews:   normByCase,
		Hypotheses:    hyps,
		Experiment:    rep,
		ProposalPatch: prop.PatchPath,
		BlockedNote:   blockedNote,
	})
	if err != nil {
		return nil, err
	}
	out.HumanReport = human

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
		eRes, err := runner.RunEngineeringReview(rt.Proj, outDir, rt.RepoPath, rt.BaseRef, rt.HeadRef, ref, engFix)
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
