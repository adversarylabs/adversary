package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/scope"
	"github.com/adversarylabs/adversary/internal/train/state"
)

// runAuthorHunt discovers PRs via GitHub search (reviewed-by / commenter)
// without requiring a repo catalog. Uses per-repo discovery state for skip.
func runAuthorHunt(
	ctx context.Context,
	opts Options,
	dataRoot string,
	targetPRs, maxTurns int,
	scopeClf *scope.Classifier,
	commentRouter *scope.Router,
	progress func(format string, args ...any),
	onKeep keepPersist,
) huntOutcome {
	out := huntOutcome{}
	concurrency := normalizeConcurrency(opts.Concurrency)
	authors := opts.AuthorsOnly
	if len(authors) == 0 {
		out.interrupted = fmt.Errorf("author_reviews discovery requires sources.authors_only")
		return out
	}
	roles := opts.AuthorRoles
	if len(roles) == 0 {
		roles = []string{"reviewed-by"}
	}
	lang := ""
	if len(opts.Languages) > 0 {
		lang = opts.Languages[0]
	}

	progress("Hunting by author activity for %s", opts.AdversaryName)
	progress("authors=%v roles=%v orgs=%v", authors, roles, opts.AuthorOrgs)
	progress("max-turns=%d, target in-scope PRs=%d, concurrency=%d", maxTurns, targetPRs, concurrency)

	fetchLimit := maxTurns * 3
	if fetchLimit < 50 {
		fetchLimit = 50
	}
	if fetchLimit > 200 {
		fetchLimit = 200
	}

	hits, err := collect.DiscoverPRsByAuthor(collect.AuthorSearchOpts{
		Context:    ctx,
		Authors:    authors,
		Roles:      roles,
		Orgs:       opts.AuthorOrgs,
		MergedOnly: true,
		Limit:      fetchLimit,
		ListLimit:  fetchLimit,
		Language:   lang,
		Since:      opts.AuthorSince,
	})
	if err != nil {
		if ctx.Err() != nil {
			out.interrupted = fmt.Errorf("train interrupted: %w", ctx.Err())
			return out
		}
		out.interrupted = err
		if collect.IsRateLimit(err) {
			progress("rate limited during author search: %v", err)
		} else {
			progress("author search failed: %v", err)
		}
		return out
	}
	progress("author search returned %d candidate PR(s)", len(hits))

	var mu sync.Mutex
	stores := map[string]*state.DiscoveryStore{}
	storeFor := func(owner, name string) (*state.DiscoveryStore, error) {
		key := owner + "/" + name
		mu.Lock()
		defer mu.Unlock()
		if s, ok := stores[key]; ok {
			return s, nil
		}
		s, err := state.LoadDiscovery(dataRoot, owner, name)
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

	var pending []huntJob
	for _, h := range hits {
		if err := ctx.Err(); err != nil {
			out.interrupted = fmt.Errorf("train interrupted: %w", err)
			break
		}
		store, err := storeFor(h.Owner, h.Repo)
		if err != nil {
			progress("  state error %s/%s: %v", h.Owner, h.Repo, err)
			continue
		}
		if store.Seen(h.Number) {
			continue
		}
		pending = append(pending, huntJob{
			owner: h.Owner, name: h.Repo,
			ref: h.PRRef(), store: store, pinned: false,
		})
		if len(pending) >= maxTurns {
			break
		}
	}
	if len(pending) == 0 {
		progress("no new PRs after discovery skip-set (all seen or empty)")
		return out
	}
	progress("queued %d new PR(s) to collect", len(pending))

	jobs := make(chan huntJob, concurrency*2)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				res := collectOnePR(ctx, opts, dataRoot, job, scopeClf, commentRouter, progress)
				if ctx.Err() != nil {
					if res.inScopeN > 0 && len(res.kept) > 0 {
						mu.Lock()
						applyCollectResult(&out, res, job.pinned)
						if onKeep != nil {
							out.resultsAdded += onKeep(res.kept)
						}
						mu.Unlock()
					}
					continue
				}
				mu.Lock()
				applyCollectResult(&out, res, job.pinned)
				if res.inScopeN > 0 && onKeep != nil && len(res.kept) > 0 {
					out.resultsAdded += onKeep(res.kept)
				}
				if out.interrupted == nil {
					if collect.IsRateLimit(res.err) {
						out.interrupted = res.err
					} else if res.blocked != nil && res.blocked.Classification == "rate-limit" {
						out.interrupted = &collect.RateLimitError{Message: res.blocked.SanitizedError}
					}
				}
				mu.Unlock()
			}
		}()
	}

	for _, job := range pending {
		if err := ctx.Err(); err != nil {
			out.interrupted = fmt.Errorf("train interrupted: %w", err)
			break
		}
		mu.Lock()
		if out.turnsUsed >= maxTurns || out.prsWithInScope >= targetPRs {
			mu.Unlock()
			break
		}
		if out.interrupted != nil && collect.IsRateLimit(out.interrupted) {
			mu.Unlock()
			break
		}
		out.turnsUsed++
		turn := out.turnsUsed
		job.turn = turn
		job.store.Record(job.ref.Number, job.ref.Title, job.ref.URL, state.OutcomeAttempted, "in progress")
		_ = job.store.Save()
		mu.Unlock()

		select {
		case jobs <- job:
		case <-ctx.Done():
			out.interrupted = fmt.Errorf("train interrupted: %w", ctx.Err())
			goto drain
		}
	}
drain:
	close(jobs)
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-ctx.Done():
		progress("interrupted — waiting for in-flight collects…")
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
		progress("Author hunt stopped: turns=%d, in-scope PRs kept=%d (%v)", out.turnsUsed, out.prsWithInScope, out.interrupted)
		return out
	}
	progress("Author hunt finished: turns=%d, in-scope PRs kept=%d", out.turnsUsed, out.prsWithInScope)
	return out
}
