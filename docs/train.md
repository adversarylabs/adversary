# Private catalog training

`adversary catalog train` mines human pull-request review comments into a
local, reviewable inbox for a private adversary catalog. It does not fine-tune
model weights, upload review evidence to Adversary Labs, modify catalog files,
or create pull requests.

The former top-level `adversary train` package-training interface has been
removed from the public CLI. Its implementation remains an internal engine
used by catalog training.

## Run a scan

Create a starter catalog and configure repositories in
`adversary.train.yaml`:

```sh
adversary catalog init my-private-adversaries
cd my-private-adversaries
adversary catalog train --model codex/gpt-5.6-luna
```

You can also select repositories and reviewers for one run:

```sh
adversary catalog train \
  --source-repo acme/api \
  --source-repo acme/web \
  --author alice \
  --exclude-author release-bot \
  --model-provider cloudflare \
  --model @cf/meta/llama-3.3-70b-instruct-fp8-fast
```

The command runs in the foreground without prompting and checkpoints
discovery state as it works. It searches successive PR waves until it reaches
the configured result target or turn limit, or exhausts unseen candidates.

Live catalog training requires model-backed triage. Use `--model-provider` and
`--model`, or set `ADVERSARY_MODEL_PROVIDER` and `ADVERSARY_MODEL`. It supports
the same OpenAI, Cloudflare, Anthropic, Fireworks, Camel, and Codex providers as
`adversary run`. The model separates noise and broadly applicable public
concerns from codebase-specific private candidates, chooses an existing private
adversary or suggests a new one, and drafts a generalized rule for review.

For example, Camel can be configured once in the shell:

```sh
export CAMEL_API_KEY='qaml_live_...'
export ADVERSARY_MODEL_PROVIDER=camel
export ADVERSARY_MODEL=auto
adversary catalog train
```

Training evidence is not uploaded to Adversary Labs. Bounded comment, thread,
review-summary, and diff evidence is sent to the model provider selected by the
user, so teams should choose a provider and retention policy appropriate for
their private source code.

An active `gh auth login` session is used automatically. Explicit credentials
may instead be supplied with `ADVERSARY_GITHUB_TOKEN`, `GITHUB_TOKEN`, or
`GH_TOKEN`.

For every merged PR in a date-bounded repository window, configure:

```yaml
sources:
  discovery: repos
  since: "2025-09-12"
run:
  all_history: true
```

This ignores `max_prs` and `max_turns`, paginates until the date boundary, and
keeps normal per-PR discovery checkpoints. GitHub rate limits pause the scan
until the advertised reset; secondary limits without a reset use a conservative
backoff. Ctrl-C remains immediate, and rerunning resumes from the seen-PR state.

## Review candidates

```sh
adversary catalog train review
adversary catalog train inspect
adversary catalog train inspect --all
adversary catalog train inspect <id>
adversary catalog train accept <id>
adversary catalog train dismiss <id>
```

Bare `inspect` starts a token-authenticated server on a random localhost port
and opens the browser review queue. Its left nav includes new, accepted, and
dismissed candidates. The detail view shows PR and comment authors and supports
the source file and diff hunk with the reviewer comment attached. Findings are
grouped by source repository in the navigation. Inline expansion controls load
real adjacent lines from the exact GitHub revision referenced by the comment;
an active `gh` login or token is required when those controls are used. It supports
editing the proposed rule, assigning an existing or new private adversary,
and asking the configured model
to draft a missing rule. New-adversary proposals use a dedicated modal and
remain local until later catalog publication. The workspace also supports
accepting, dismissing, and reopening decisions. **Apply to working tree** writes
the model-generated adversary change into the current checkout and leaves git
untouched. A change is refused unless it updates the operative policy and adds
regression coverage; executable adversaries must also update their implementation.
**Create catalog PR**
fetches the remote default branch, creates an isolated temporary worktree and a
candidate-specific branch, asks the configured model to integrate the rule and
create positive and negative regression cases, validates the shape of that
change, commits it, pushes the branch, and opens a GitHub pull request with `gh`;
it never switches or writes catalog files in the current checkout. Selecting a
finding updates the browser URL, so refresh and browser back/forward preserve
your place. **Approve for later** records the decision in SQLite for a later
batch. Applying a proposed new adversary creates its policy directory and
manifest entry. No third-party assets are loaded.

`inspect --all` walks the new-candidate queue in the terminal. Accept and dismiss
decisions are saved immediately; skip leaves a candidate new, and quit leaves
the remaining queue untouched so review can resume later.

Results live in a gitignored SQLite database under `.adversary-train` by
default. Comments confidently owned by a starter adversary are assigned to it.
Plausible independent human comments that do not match one confidently are
kept as `unassigned` candidates instead of being discarded. Bot output,
conversation artifacts, empty approvals, withdrawn concerns, and comments
explicitly deferred beyond the reviewed change remain excluded.

Catalog discovery has its own seen-PR namespace, isolated from the internal
executable-adversary training engine. Running one workflow therefore cannot
consume the other workflow's discovery history.

To rebuild the local inbox with newly collected presentation metadata while
retaining the downloaded GitHub cache, run:

```sh
adversary catalog train reset --all
adversary catalog train
```

Results approved for later record a decision in the local inbox only. Applying
to the working tree updates tracked catalog files but performs no Git operation.
Creating a catalog PR requires a configured `origin`, an authenticated `gh`
session, and permission to push a branch and open a pull request. Neither path
publishes an adversary package; merge and release remain explicit later steps.

For older product context, see the
[historical customer-training sketch](train/customer-train-cli.md).
