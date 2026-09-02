# Learn from GitHub review replies

`adversary feedback ingest` turns a human reply to an Adversary inline review
comment into an auditable improvement candidate. It does not fine-tune a model,
edit a package, suppress a rule, or publish a release automatically.

When a trusted pull-request author, repository owner, member, or collaborator
explains why a finding is not an issue, the command:

1. Verifies the root comment was produced by Adversary.
2. Reconstructs the complete inline thread.
3. Stores a versioned JSON feedback record.
4. Opens a deduplicated issue in the owning `*-adversary` repository when the
   reply contains a substantive technical rationale.
5. Replies in the thread: “Thanks — we’ve learned from this and recorded it to
   improve future reviews.”

The acknowledgement is only posted after durable capture and successful issue
handoff. It intentionally does not claim that a new package version is already
released.

## GitHub Actions workflow

Run feedback ingestion in a separate workflow. Do not check out or execute pull
request code for this event.

```yaml
name: Adversary feedback

on:
  pull_request_review_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: adversary-feedback-${{ github.event.comment.id }}
  cancel-in-progress: false

jobs:
  feedback:
    runs-on: ubuntu-latest
    steps:
      - name: Install Adversary CLI
        # Use the same pinned installation mechanism as the review workflow.
        run: |
          # install pinned adversary release here
          adversary version

      - name: Capture reply
        env:
          # A token that can read/reply in this repository and open issues in
          # the owning adversary repository. Prefer a narrowly scoped GitHub App
          # installation token rather than a personal access token.
          ADVERSARY_GITHUB_TOKEN: ${{ secrets.ADVERSARY_FEEDBACK_TOKEN }}
        run: |
          adversary feedback ingest \
            --event-path "$GITHUB_EVENT_PATH" \
            --state-dir "$RUNNER_TEMP/adversary-feedback"
```

For a private or home-built adversary, pass its issue repository explicitly:

```sh
adversary feedback ingest --issue-repository acme/my-policy-adversary
```

Use `--create-issue=false --acknowledge=false` for capture-only rollout. The
record remains suitable for artifact upload or a customer-local training loop.

## Trust and privacy

- Bot replies and untrusted outside replies are recorded as `needs-triage` and
  never create an improvement issue or acknowledgement.
- A raw human comment is untrusted evidence. It is quoted in the issue but is
  never copied directly into a runtime prompt or suppression list.
- Private customer feedback should stay in a repository or store with the same
  access boundary. Do not route private source discussion into a public package
  issue without explicit authorization. The CLI refuses cross-repository issue
  handoff for private PRs unless
  `--allow-private-cross-repository-feedback` is explicitly set.
- The owning adversary engineer must verify the explanation, add a clean
  regression fixture, preserve a nearby positive case, pass evaluation, and use
  the normal review and release process.

## Idempotency

The feedback record ID is derived from repository, pull request, root comment,
and reply IDs. Issues and acknowledgements contain hidden markers using that
identity, so repeated webhook deliveries reuse existing side effects.
