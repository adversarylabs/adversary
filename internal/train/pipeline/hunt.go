package pipeline

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/repos"
	"github.com/adversarylabs/adversary/internal/train/scope"
	"github.com/adversarylabs/adversary/internal/train/state"
)

// Default / caps for parallel PR collect (gh API). Authenticated gh is typically
// fine at small fan-out; keep the default conservative to spare rate limits.
const (
	defaultHuntConcurrency = 2
	maxHuntConcurrency     = 8
)

// huntJob is one PR to collect during live discovery.
type huntJob struct {
	owner  string
	name   string
	ref    collect.PRRef
	store  *state.DiscoveryStore
	pinned bool
	turn   int
}

// huntOutcome is the shared result of a parallel hunt.
type huntOutcome struct {
	caseList       []*cases.Case
	fallbackCases  []*cases.Case
	turnsUsed      int
	prsWithInScope int
	blocked        *dataroot.BlockedResult
	collectClass   dataroot.ExecutionClass
	interrupted    error
	// resultsAdded counts progressive SQLite writes during hunt (kept gold).
	resultsAdded int
}

// keepPersist is called under the hunt mutex when a PR has in-scope gold.
// Used to flush gold into results.db immediately (interrupt-safe).
type keepPersist func(kept []*cases.Case) int

// normalizeConcurrency clamps worker count for parallel collect.
func normalizeConcurrency(n int) int {
	if n <= 0 {
		return defaultHuntConcurrency
	}
	if n > maxHuntConcurrency {
		return maxHuntConcurrency
	}
	return n
}

// runParallelHunt discovers and collects PRs across catalog repos with a
// bounded worker pool. GitHub traffic is limited by concurrency; local package
// execution is not done here (grading serializes via runner package locks).
func runParallelHunt(
	ctx context.Context,
	opts Options,
	catalogRepos []repos.Repo,
	dataRoot string,
	targetPRs, maxTurns int,
	scopeClf *scope.Classifier,
	commentRouter *scope.Router,
	progress func(format string, args ...any),
	onKeep keepPersist, // may be nil
) huntOutcome {
	out := huntOutcome{}
	concurrency := normalizeConcurrency(opts.Concurrency)
	githubEventsMode := strings.EqualFold(opts.DiscoveryMode, "github_events")

	if opts.PR > 0 {
		// Pinned PR stays single-flight (debug path).
		owner, name := opts.Owner, opts.Repo
		if owner == "" || name == "" {
			if len(catalogRepos) > 0 {
				owner, name = catalogRepos[0].Owner, catalogRepos[0].Name
			} else {
				out.interrupted = fmt.Errorf("--pr requires --owner and --repo (or a non-empty catalog)")
				return out
			}
		}
		store, err := state.LoadDiscoveryForTarget(dataRoot, opts.DiscoveryNamespace, owner, name)
		if err != nil {
			out.interrupted = err
			return out
		}
		progress("Pinned PR mode: %s/%s#%d", owner, name, opts.PR)
		ref := collect.PRRef{
			Number: opts.PR,
			URL:    fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, name, opts.PR),
		}
		store.Record(ref.Number, ref.Title, ref.URL, state.OutcomeAttempted, "in progress")
		_ = store.Save()
		res := collectOnePR(ctx, opts, dataRoot, huntJob{
			owner: owner, name: name, ref: ref, store: store, pinned: true, turn: 1,
		}, scopeClf, commentRouter, progress)
		accepted := applyCollectResult(&out, res, true, targetPRs)
		if accepted && onKeep != nil {
			out.resultsAdded += onKeep(res.kept)
		}
		if err := ctx.Err(); err != nil {
			out.interrupted = fmt.Errorf("train interrupted: %w", err)
		}
		out.turnsUsed = 1
		return out
	}

	langNote := "any language"
	if len(opts.Languages) > 0 {
		langNote = "languages=" + strings.Join(opts.Languages, ",")
	}
	totalCatalogRepos := len(catalogRepos)
	cursorTarget := opts.DiscoveryNamespace
	if strings.TrimSpace(cursorTarget) == "" {
		cursorTarget = opts.AdversaryName
	}
	windowStart, windowCount, err := state.TakeCatalogWindow(
		dataRoot, cursorTarget, totalCatalogRepos, maxTurns,
	)
	if err != nil {
		out.interrupted = fmt.Errorf("reserve catalog discovery window: %w", err)
		return out
	}
	catalogRepos = catalogRepoWindow(catalogRepos, windowStart, windowCount)
	progress("Hunting across %d repos (%s) for %s", totalCatalogRepos, langNote, opts.AdversaryName)
	if windowCount < totalCatalogRepos {
		progress("Discovery window: %d/%d repos starting at catalog index %d; next run continues from index %d",
			windowCount, totalCatalogRepos, windowStart, (windowStart+windowCount)%totalCatalogRepos)
	}
	progress("max-turns=%d, target in-scope PRs=%d, concurrency=%d", maxTurns, targetPRs, concurrency)

	var mu sync.Mutex
	stores := map[string]*state.DiscoveryStore{}
	storeFor := func(owner, name string) (*state.DiscoveryStore, error) {
		key := owner + "/" + name
		mu.Lock()
		defer mu.Unlock()
		if s, ok := stores[key]; ok {
			return s, nil
		}
		s, err := state.LoadDiscoveryForTarget(dataRoot, opts.DiscoveryNamespace, owner, name)
		if err != nil {
			return nil, err
		}
		stores[key] = s
		return s, nil
	}

	jobs := make(chan huntJob, concurrency*2)
	var wg sync.WaitGroup

	// Workers: parallel gh collect (rate-limited by concurrency).
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					// Drain remaining jobs without more network after interrupt.
					continue
				}
				res := collectOnePR(ctx, opts, dataRoot, job, scopeClf, commentRouter, progress)
				if ctx.Err() != nil {
					// Still persist any in-scope gold from a finished collect.
					if res.inScopeN > 0 && len(res.kept) > 0 {
						mu.Lock()
						accepted := applyCollectResult(&out, res, job.pinned, targetPRs)
						if accepted && onKeep != nil {
							out.resultsAdded += onKeep(res.kept)
						}
						mu.Unlock()
					}
					continue
				}
				mu.Lock()
				accepted := applyCollectResult(&out, res, job.pinned, targetPRs)
				if accepted && onKeep != nil {
					out.resultsAdded += onKeep(res.kept)
				}
				mu.Unlock()
			}
		}()
	}

	// Feeder: discover one bounded, durable catalog window, then enqueue jobs.
	// The default repo mode spends one GitHub list request per repository. The
	// github_events mode replaces that wave with one public ClickHouse query, but
	// selected candidates are still hydrated by the canonical GitHub collector.
	// A per-target cursor lets later runs resume at the next window while a shared
	// seed staggers different targets' first run. Collect workers already run up
	// to `concurrency` PRs at once.
feedLoop:
	for {
		if err := ctx.Err(); err != nil {
			mu.Lock()
			out.interrupted = fmt.Errorf("train interrupted: %w", err)
			mu.Unlock()
			break
		}
		mu.Lock()
		done := out.turnsUsed >= maxTurns || out.prsWithInScope >= targetPRs
		mu.Unlock()
		if done {
			break
		}
		if len(catalogRepos) == 0 {
			break
		}

		// Discover one candidate PR per catalog repo this wave.
		type discHit struct {
			repo  repos.Repo
			store *state.DiscoveryStore
			ref   collect.PRRef
			ok    bool
		}
		hits := make([]discHit, len(catalogRepos))
		if githubEventsMode {
			repoNames := make([]string, 0, len(catalogRepos))
			for _, r := range catalogRepos {
				repoNames = append(repoNames, r.FullName())
			}
			progress("Querying public GitHub Events mirror for %d repositories…", len(repoNames))
			foundByRepo, err := collect.DiscoverPRsFromGitHubEvents(repoNames, collect.GitHubEventsOpts{
				Context:      ctx,
				Endpoint:     opts.GitHubEventsURL,
				Since:        opts.AuthorSince,
				PerRepoLimit: opts.GitHubEventsPerRepo,
				Client:       opts.GitHubEventsClient,
			})
			if err != nil {
				mu.Lock()
				out.interrupted = err
				mu.Unlock()
				progress("  GitHub Events discovery failed: %v", err)
				break feedLoop
			}
			for i, r := range catalogRepos {
				store, err := storeFor(r.Owner, r.Name)
				if err != nil {
					mu.Lock()
					out.interrupted = err
					mu.Unlock()
					progress("  state error for %s: %v", r.FullName(), err)
					break feedLoop
				}
				candidates := foundByRepo[r.FullName()]
				progress("Mirror candidates in %s: %d (seen %d)", r.FullName(), len(candidates), len(store.SeenSet()))
				for _, ref := range candidates {
					if store.Seen(ref.Number) {
						continue
					}
					hits[i] = discHit{repo: r, store: store, ref: ref, ok: true}
					break
				}
			}
		} else {
			var discWG sync.WaitGroup
			sem := make(chan struct{}, concurrency)
			for i, r := range catalogRepos {
				discWG.Add(1)
				go func(i int, r repos.Repo) {
					defer discWG.Done()
					if ctx.Err() != nil {
						return
					}
					// Never block forever on the semaphore after Ctrl+C.
					select {
					case sem <- struct{}{}:
						defer func() { <-sem }()
					case <-ctx.Done():
						return
					}

					store, err := storeFor(r.Owner, r.Name)
					if err != nil {
						progress("  state error for %s: %v", r.FullName(), err)
						return
					}
					progress("Looking for new PRs in %s (seen %d)…", r.FullName(), len(store.SeenSet()))
					found, err := collect.DiscoverPRsWithOpts(r.Owner, r.Name, collect.DiscoverOpts{
						Context: ctx,
						Limit:   3,
						Skip:    store.SeenSet(),
					})
					if err != nil {
						if ctx.Err() != nil {
							return
						}
						if collect.IsRateLimit(err) {
							progress("  rate limited on %s: %v", r.FullName(), err)
							mu.Lock()
							if out.interrupted == nil {
								// Preserve typed RateLimitError for collect.IsRateLimit.
								out.interrupted = err
							}
							mu.Unlock()
							return
						}
						progress("  no new PRs in %s: %v", r.FullName(), err)
						return
					}
					for _, ref := range found {
						if store.Seen(ref.Number) {
							continue
						}
						hits[i] = discHit{repo: r, store: store, ref: ref, ok: true}
						return
					}
				}(i, r)
			}
			// Wait for discover wave, but don't hang if something ignored cancel.
			discDone := make(chan struct{})
			go func() {
				discWG.Wait()
				close(discDone)
			}()
			select {
			case <-discDone:
			case <-ctx.Done():
				progress("interrupted — stopping discover wave…")
				<-discDone // still wait for goroutines to release after gh kill
				mu.Lock()
				out.interrupted = fmt.Errorf("train interrupted: %w", ctx.Err())
				mu.Unlock()
				break feedLoop
			}
		}

		// If any discover hit rate limit, stop the whole hunt (results already saved).
		mu.Lock()
		rateStop := out.interrupted != nil && collect.IsRateLimit(out.interrupted)
		mu.Unlock()
		if rateStop {
			progress("GitHub rate limit — stopping hunt (partial results kept in results.db)")
			break feedLoop
		}

		enqueuedThisWave := 0
		for _, h := range hits {
			if !h.ok {
				continue
			}
			if err := ctx.Err(); err != nil {
				mu.Lock()
				out.interrupted = fmt.Errorf("train interrupted: %w", err)
				mu.Unlock()
				break feedLoop
			}
			mu.Lock()
			if out.turnsUsed >= maxTurns || out.prsWithInScope >= targetPRs {
				mu.Unlock()
				break feedLoop
			}
			// Re-check seen under turn reservation (another wave shouldn't double).
			if h.store.Seen(h.ref.Number) {
				mu.Unlock()
				continue
			}
			out.turnsUsed++
			turn := out.turnsUsed
			h.store.Record(h.ref.Number, h.ref.Title, h.ref.URL, state.OutcomeAttempted, "in progress")
			_ = h.store.Save()
			mu.Unlock()

			job := huntJob{
				owner: h.repo.Owner, name: h.repo.Name, ref: h.ref, store: h.store,
				pinned: false, turn: turn,
			}
			select {
			case jobs <- job:
				enqueuedThisWave++
			case <-ctx.Done():
				mu.Lock()
				out.interrupted = fmt.Errorf("train interrupted: %w", ctx.Err())
				mu.Unlock()
				break feedLoop
			}
		}

		if enqueuedThisWave == 0 {
			progress("No new PR candidates in this catalog window — stopping hunt")
		}
		break
	}

	close(jobs)
	// Wait for workers; bound wait so a stuck gh cannot pin the process forever.
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-ctx.Done():
		progress("interrupted — waiting for in-flight collects to stop…")
		select {
		case <-workersDone:
		case <-time.After(8 * time.Second):
			progress("interrupted — giving up on hung workers")
		}
	}

	if out.interrupted == nil {
		if err := ctx.Err(); err != nil {
			out.interrupted = fmt.Errorf("train interrupted: %w", err)
		}
	}
	if out.interrupted != nil {
		progress("Hunt interrupted: turns=%d, in-scope PRs kept=%d", out.turnsUsed, out.prsWithInScope)
		return out
	}
	progress("Hunt finished: turns=%d, in-scope PRs kept=%d (concurrency=%d)", out.turnsUsed, out.prsWithInScope, concurrency)
	return out
}

func catalogRepoWindow(catalog []repos.Repo, start, count int) []repos.Repo {
	if len(catalog) == 0 || count <= 0 {
		return nil
	}
	if count > len(catalog) {
		count = len(catalog)
	}
	if start < 0 || start >= len(catalog) {
		start = 0
	}
	out := make([]repos.Repo, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, catalog[(start+i)%len(catalog)])
	}
	return out
}

type collectResult struct {
	kept      []*cases.Case
	inScopeN  int
	outScopeN int
	blocked   *dataroot.BlockedResult
	execClass dataroot.ExecutionClass
	err       error
	owner     string
	name      string
	ref       collect.PRRef
	store     *state.DiscoveryStore
	pinned    bool
	turn      int
	noCases   bool
}

func collectOnePR(
	ctx context.Context,
	opts Options,
	dataRoot string,
	job huntJob,
	scopeClf *scope.Classifier,
	commentRouter *scope.Router,
	progress func(format string, args ...any),
) collectResult {
	res := collectResult{
		owner: job.owner, name: job.name, ref: job.ref, store: job.store,
		pinned: job.pinned, turn: job.turn,
	}
	if err := ctx.Err(); err != nil {
		res.err = err
		return res
	}
	title := job.ref.Title
	if title == "" {
		title = "(title loading…)"
	}
	url := job.ref.URL
	if url == "" {
		url = fmt.Sprintf("https://github.com/%s/%s/pull/%d", job.owner, job.name, job.ref.Number)
	}
	progress("→ turn %d: trying %s/%s#%d — %s", job.turn, job.owner, job.name, job.ref.Number, title)
	progress("  %s", url)
	progress("  collecting reviews and comments…")

	var authorOK collect.AuthorFilter
	if len(opts.AuthorsOnly) > 0 || len(opts.AuthorsIgnore) > 0 {
		only, ignore := opts.AuthorsOnly, opts.AuthorsIgnore
		authorOK = func(login string) bool {
			return workspaceAuthorOK(login, only, ignore)
		}
	}
	cres, err := collect.CollectPRWithOptions(dataRoot, job.owner, job.name, job.ref.Number, collect.CollectOptions{
		Context:  ctx,
		Scope:    scopeClf,
		Router:   commentRouter,
		AuthorOK: authorOK,
	})
	if err != nil {
		job.store.Record(job.ref.Number, job.ref.Title, job.ref.URL, state.OutcomeBlocked, err.Error())
		_ = job.store.Save()
		progress("  ✗ collect error: %v", err)
		res.err = err
		return res
	}
	if cres.Blocked != nil {
		job.store.Record(job.ref.Number, job.ref.Title, job.ref.URL, state.OutcomeBlocked, cres.Blocked.SanitizedError)
		_ = job.store.Save()
		progress("  ✗ blocked (%s): %s", cres.Blocked.Classification, cres.Blocked.SanitizedError)
		res.blocked = cres.Blocked
		res.execClass = cres.ExecutionClass
		return res
	}
	if cres.CacheReused {
		progress("  ↺ GitHub rate-limited; replaying the complete cached PR snapshot")
	}
	restrictGoldToSelectedTarget(opts, cres.CaseCandidates)
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
		job.store.Record(job.ref.Number, job.ref.Title, job.ref.URL, state.OutcomeNoCases, "no reconstructable review rounds")
		_ = job.store.Save()
		progress("  ✗ no usable review rounds — skip")
		res.noCases = true
		res.execClass = cres.ExecutionClass
		return res
	}
	res.kept = kept
	res.inScopeN = inScopeN
	res.outScopeN = outScopeN
	res.execClass = cres.ExecutionClass

	outcome := state.OutcomeNoInScope
	note := "out of scope only — keep hunting"
	if inScopeN > 0 {
		outcome = state.OutcomeGraded
		note = fmt.Sprintf("%d in-scope concern(s) — keep", inScopeN)
		progress("  ✓ keep: %d in-scope, %d out-of-scope human comment(s)", inScopeN, outScopeN)
	} else {
		progress("  · no in-scope comments (%d out-of-scope) — keep hunting", outScopeN)
	}
	if job.pinned {
		outcome = state.OutcomePinned
	}
	job.store.Record(job.ref.Number, job.ref.Title, job.ref.URL, outcome, note)
	_ = job.store.Save()
	return res
}

func restrictGoldToSelectedTarget(opts Options, candidates []*cases.Case) {
	if !opts.targetAdversaryOnly {
		return
	}
	for _, c := range candidates {
		restrictGoldToTrainingTarget(c, opts.AdversaryName)
	}
}

// restrictGoldToTrainingTarget preserves the global router's ownership decision
// while ensuring a target-scoped run can only make progress on its selected
// adversary. Sibling-owned comments remain auditable evidence, but are not gold
// for this run and cannot stop discovery early or be persisted for the target.
func restrictGoldToTrainingTarget(c *cases.Case, target string) {
	if c == nil || strings.TrimSpace(target) == "" {
		return
	}
	target = strings.TrimSpace(target)
	for i := range c.Labels.ExpectedConcerns {
		label := &c.Labels.ExpectedConcerns[i]
		if !label.Approved || (label.Scope != "" && label.Scope != "in_scope") {
			continue
		}
		owner := strings.TrimSpace(label.OwnerAdversary)
		if strings.EqualFold(owner, target) {
			continue
		}
		label.Approved = false
		label.Scope = "out_of_scope"
		if owner == "" {
			owner = "no adversary"
		}
		reason := fmt.Sprintf("routed to %s, not selected cycle target %s", owner, target)
		if previous := strings.TrimSpace(label.ScopeReason); previous != "" {
			reason += ": " + previous
		}
		label.ScopeReason = reason
	}
}

// applyCollectResult admits one finished collection into the hunt outcome.
// Callers serialize this operation with the hunt mutex. The limit must be
// checked here, not only by the feeder: buffered and in-flight jobs can finish
// after the feeder has admitted the target number of PRs.
//
// The return value reports whether an in-scope PR was admitted and should be
// persisted to results.db.
func applyCollectResult(out *huntOutcome, res collectResult, pinned bool, targetPRs int) bool {
	if res.blocked != nil && out.blocked == nil {
		out.blocked = res.blocked
	}
	if res.execClass != "" {
		out.collectClass = res.execClass
	}
	if res.err != nil || res.noCases || len(res.kept) == 0 {
		return false
	}
	if res.inScopeN > 0 {
		if targetPRs > 0 && out.prsWithInScope >= targetPRs {
			return false
		}
		out.caseList = append(out.caseList, res.kept...)
		out.prsWithInScope++
		return true
	}
	out.fallbackCases = res.kept
	if pinned {
		// Pinned debug path: still grade even without in-scope gold.
		out.caseList = append(out.caseList, res.kept...)
	}
	return false
}

// progressMu wraps stderr progress for concurrent workers.
func makeProgress(log *[]string, mu *sync.Mutex) func(format string, args ...any) {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		mu.Lock()
		fmt.Fprintln(os.Stderr, msg)
		*log = append(*log, msg)
		mu.Unlock()
	}
}
