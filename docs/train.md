# Private catalog training

`adversary catalog train` mines human pull-request review comments into a
local, reviewable inbox for a private adversary catalog. It does not fine-tune
model weights, upload review evidence, modify catalog files, or create pull
requests.

The former top-level `adversary train` package-training interface has been
removed from the public CLI. Its implementation remains an internal engine
used by catalog training.

## Run a scan

Create a starter catalog and configure repositories in
`adversary.train.yaml`:

```sh
adversary catalog init my-private-adversaries
cd my-private-adversaries
adversary catalog train
```

You can also select repositories and reviewers for one run:

```sh
adversary catalog train \
  --source-repo acme/api \
  --source-repo acme/web \
  --author alice \
  --exclude-author release-bot
```

The command runs in the foreground without prompting and checkpoints
discovery state as it works. It searches successive PR waves until it reaches
the configured result target or turn limit, or exhausts unseen candidates.

An active `gh auth login` session is used automatically. Explicit credentials
may instead be supplied with `ADVERSARY_GITHUB_TOKEN`, `GITHUB_TOKEN`, or
`GH_TOKEN`.

## Review candidates

```sh
adversary catalog train review
adversary catalog train inspect <id>
adversary catalog train accept <id>
adversary catalog train dismiss <id>
```

Results live in a gitignored SQLite database under `.adversary-train` by
default. Comments confidently owned by a starter adversary are assigned to it.
Plausible independent human comments that do not match one confidently are
kept as `unassigned` candidates instead of being discarded. Bot output,
conversation artifacts, empty approvals, withdrawn concerns, and comments
explicitly deferred beyond the reviewed change remain excluded.

Catalog discovery has its own seen-PR namespace, isolated from the internal
executable-adversary training engine. Running one workflow therefore cannot
consume the other workflow's discovery history.

Accepted results currently record a decision in the local inbox only. Editing
an adversary and publishing the catalog through Git remains an explicit later
step.

For older product context, see the
[historical customer-training sketch](train/customer-train-cli.md).
