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
the source file and diff hunk with the reviewer comment attached. It supports
editing the proposed rule, assigning an existing or new private adversary,
accepting, dismissing, and reopening decisions. No third-party assets are loaded.

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

Accepted results currently record a decision in the local inbox only. Editing
an adversary and publishing the catalog through Git remains an explicit later
step.

For older product context, see the
[historical customer-training sketch](train/customer-train-cli.md).
