# Repository index for adversary runs

Status: implemented (v1 CLI + SDK + go/security consumer)  
Audience: CLI + TypeScript SDK

## Summary

**Yes — this makes sense.** Best-in-class generic review agents need **repo navigation**, not only the PR diff. The CLI should ensure a **local filesystem index** of the target repository at `adversary run` time; the SDK should expose **read-only query APIs** so every adversary (specialist) can use the same graph without re-walking the tree ad hoc.

Caching between runs is optional for correctness but **worth doing**: same worktree, same content → skip rebuild. Defer CI action caches until local behavior is solid.

This doc describes the intended split of responsibility, cache layout, invalidation, index contents (v1), SDK surface, and non-goals.

## Why

High-signal automated review typically requires more than a changed-file dump:

- Many important findings are **multi-hop** (authz middleware + route groups, incomplete twin paths, cross-file contracts).
- Specialists already own domains; they lack a **shared navigation plane**.
- One-shot “prepare N file excerpts” loses when the bug is “who calls this” / “which group wraps this handler.”

The product shape stays specialist-first. The platform provides the map; adversaries provide judgment and CHECKS.

## Ownership

| Component | Owns |
| --- | --- |
| **CLI** | When to build/refresh the index; where it lives on disk; invalidation; attaching index location/handle to the run |
| **SDK** | Query API for adversaries during `run` / `runFromEnvironment` (read-only); typed results; no silent network |
| **Adversaries** | What to ask the index; deterministic detectors; model tools that *call* SDK helpers; still own findings |

Adversaries must not invent their own long-lived caches of the target repo. They may keep in-memory structures for a single run derived from SDK queries.

## Lifecycle at `adversary run`

```text
adversary run [refs…] --path <repo>
  1. Resolve review scope (base/head/all-files/worktree)  [existing]
  2. EnsureRepoIndex(repoPath) → IndexHandle
       - compute fingerprint of target tree state
       - if cache hit and schema version matches → load
       - else build (or incremental update) → write cache → load
  3. Materialize adversary runtime input (existing change context, etc.)
  4. Inject index access into the child environment / protocol
  5. Run selected adversaries (each uses SDK to query)
  6. Collect findings  [existing]
```

Index ensure runs **once per process** for a given `--path`, shared across multi-adversary selection in the same invocation.

## Cache location (XDG)

Use the **cache** hierarchy (rebuildable), not the artifact **data** store:

| Platform | Default root |
| --- | --- |
| Linux | `$XDG_CACHE_HOME/adversary/repo-index` or `~/.cache/adversary/repo-index` |
| macOS | `~/Library/Caches/adversary/repo-index` (Go `os.UserCacheDir`) |
| Windows | `%LocalAppData%\adversary\repo-index` |

Override (optional later): `ADVERSARY_REPO_INDEX_DIR`.

Do **not** put the index under `ADVERSARY_DATA_DIR` (OCI store / installed packages). Indexes are derived from the **target** workspace, not the catalog store.

### Per-repo layout

```text
{cacheRoot}/
  v1/
    {repoKey}/
      meta.json          # schemaVersion, fingerprint, builtAt, stats
      files.jsonl        # or sqlite: path, language, size, hash
      edges.jsonl        # import/require/package edges (v1)
      symbols.jsonl      # optional v1.1: exported symbols per file
```

**`repoKey`:** stable hash of the absolute cleaned `repoPath` (and volume id if needed), **not** the git remote URL alone (same clone path = same cache; two worktrees = two keys unless we later add git-common-dir sharing).

## Fingerprint / when to rebuild

Branch name alone is **not** enough (two branches can share a tree; dirty trees differ from HEAD).

**v1 fingerprint inputs (ordered):**

1. Index schema version (`v1`)
2. Absolute `repoPath`
3. If git repo:
   - `HEAD` commit OID (or empty if unborn)
   - **Dirty worktree fingerprint**: sorted list of `(path, blob_oid or mtime+size)` for tracked+untracked relevant files, or a single `git write-tree` / `git status --porcelain=v2` digest  
4. If not git: recursive content hash of included paths (or mtime+size fallback with documented caveats)

**Hit:** fingerprint matches `meta.json` and files exist.  
**Miss:** full rebuild (v1).  
**Later:** incremental update when only a small set of paths changed.

CLI may log one stderr line on rebuild vs hit (debug/verbose). No interactive prompt.

### Dirty worktrees (local `adversary run .`)

Local development **must** see uncommitted changes. The index always reflects the **current worktree content** used for review, not only last commit. That is the main reason fingerprint ≠ `HEAD` alone.

## What v1 indexes (keep small)

Ship a **useful minimal graph**, not embeddings.

| Layer | v1 | Notes |
| --- | --- | --- |
| File inventory | yes | path, language guess, size, content hash |
| Import / package edges | yes (**Go and TypeScript** in the initial pass) | Go: `import` / package clause. TS/TSX (and JS as needed): `import` / `export` / `require` → edge list |
| Symbol table | optional v1.1 | exports + rough defs for Go and TypeScript |
| Full call graph | no | later |
| Embeddings / semantic search | no | later |
| Sandboxed execution of the target | no | out of scope |

**Language priority (v1):** **Go and TypeScript together** on day one — both are first-class for inventory + import edges. That matches catalog specialists and the TypeScript SDK ecosystem. Other languages: file inventory always; edges best-effort only when cheap.

**Exclude by default:** `node_modules`, `vendor` (optional flag later), `.git`, build outputs (`dist`, `bin`), large binaries — same spirit as pack ignore rules where applicable.

## SDK surface (adversary-facing)

Adversaries obtain an index client from the rule context (name TBD), e.g.:

```ts
// Illustrative — exact names follow SDK conventions
const index = ctx.repoIndex; // null if unavailable

await index.listFiles({ glob: "**/*.go", limit: 5000 });
await index.importsOf("pkg/hub/server.go");
await index.importersOf("pkg/hub/server.go");
await index.file("pkg/hub/server.go"); // metadata + optional hash
// later: index.symbolsIn / index.definition / index.references
```

**Properties:**

- Read-only  
- Fail closed with clear errors if index missing (CLI should always ensure before launch when feature is on)  
- Bounded results (limits) so models cannot dump the monorepo  
- No network  
- Citations: prefer returning **paths + line ranges** that plug into existing evidence / `read_file` flows

**Injection into the child process:**

- Prefer extending the existing run protocol (e.g. path to index dir or socket in `ADVERSARY_INPUT` / env) rather than re-parsing git inside every adversary.  
- Details belong in a follow-on CLI/SDK protocol change; this doc only requires that the CLI **builds** and the SDK **reads** the same on-disk format.

## CLI flags / config (suggested)

| Control | Default | Purpose |
| --- | --- | --- |
| Index on run | **on** (once shipped) | Feature flag during rollout: `--repo-index=auto\|off\|force` |
| `auto` | rebuild on fingerprint miss | normal |
| `force` | rebuild always | debugging |
| `off` | no index; SDK returns unavailable | emergency / benchmarks |

No CI-specific flags in v1.

## Performance expectations (local)

| Target tree | Cold build (order of magnitude) | Warm hit |
| --- | --- | --- |
| Small (`adversary`) | seconds | &lt;100ms load |
| Medium (`elasticclaw`) | tens of seconds | &lt;100ms–1s |
| Large monorepos | minutes if naïve full walk | must use exclude lists + later incremental |

If cold builds are painful on large trees, **v1.1 incremental** is the fix—not dropping cache.

## Relationship to review scope

- **Diff / change context** remains the primary *focus* of the review (what changed).  
- **Index** answers *where else to look* (callers, importers, twins).  
- Automatic detection and specialist selection stay as today; index does not replace detection globs.

## Security and trust

- Index is a **derived view of local/trusted checkout content**. It does not grant host execution trust to packages.  
- Treat indexed source as **untrusted data** for model prompts (same as today’s excerpts).  
- Cache files: user-only permissions (0700/0600) like other CLI state.  
- Do not upload the index anywhere.

## Rollout plan

1. **On-disk format + CLI ensure/load** with fingerprint (no SDK yet) — unit tests on hit/miss/dirty.  
2. **SDK read API** + fixture index in tests.  
3. **Wire specialists** that exercise both languages on day one — `go/security` **and** `lang/typescript` — to use `importersOf` / `importsOf` in deterministic navigation (and later model tools). Both languages get import edges from the CLI builder; specialists only *query*.  
4. Measure against a private held-out set of multi-hop review findings (offline).  
5. Turn on by default; document in CLI/runtime docs.  
6. CI action cache — later, separate change.

## Non-goals (v1)

- Persistent SaaS / remote index service  
- Full monorepo semantic search  
- Replacing specialist tree-sitter passes entirely on day one  
- Guaranteeing index completeness for every language  
- Caching in GitHub Actions  
- Product knowledge bases (Cursor rules, internal docs) — orthogonal layer  

## Pushbacks / refinements (accepted into design)

| Idea | Refinement |
| --- | --- |
| “Cache by branch” | Use **content fingerprint** (HEAD + dirty); branch is debug metadata only |
| “Always full repo” | Full *inventory* is fine; deep graphs may be **incremental / Go+TS-first** |
| “SDK builds the index” | **No** — CLI builds; SDK only queries (one writer, many readers) |
| “Skip cache” | Correctness OK without cache; **still implement cache** — low cost, big local UX win |
| “Store under data dir” | Prefer **cache dir**; data dir stays for OCI/artifacts |

## Open questions (resolve at implement)

1. Exact protocol field: env path vs embedded in `ADVERSARY_INPUT`.  
2. SQLite vs JSONL for v1 (SQLite better for queries; JSONL simpler to debug).  
3. Whether `go list` / module graph is used for Go edges vs pure tree-sitter; for TypeScript, whether `tsconfig` path aliases / project references are resolved in v1 or deferred.  
4. Feature flag default during beta (`off` vs `auto`).

## Success criteria

- Second `adversary run` on an unchanged worktree does **not** rebuild (observable via verbose log or test).  
- Dirty edit to a tracked file **does** invalidate.  
- An SDK test adversary can resolve importers of a fixture file via the index API.  
- No public dependency on CI caches for correctness.

## Related

- Trust model: host execution still signature/path based; index is not trust  
- Automatic detection: `docs/automatic-detection.md` (scope remains separate)
