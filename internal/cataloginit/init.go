package cataloginit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Options struct {
	Destination string
}

type Result struct {
	Location string
}

type starterAdversary struct {
	Slug      string
	Title     string
	Summary   string
	ReviewFor []string
}

var starterAdversaries = []starterAdversary{
	{
		Slug:    "data-integrity",
		Title:   "Data integrity",
		Summary: "Protect application invariants and durable state across writes.",
		ReviewFor: []string{
			"Broken invariants across related writes, transactions, and database constraints.",
			"Partial updates, stale derived values, incorrect counters, and lost state transitions.",
			"Ordering, uniqueness, and consistency assumptions that the implementation does not enforce.",
		},
	},
	{
		Slug:    "migrations-and-backfills",
		Title:   "Migrations and backfills",
		Summary: "Keep schema and data changes safe during real deployments.",
		ReviewFor: []string{
			"Changes that are unsafe while old and new application versions run together.",
			"Backfills that are not bounded, resumable, idempotent, or verifiable.",
			"Locking, rollout, rollback, and large-table risks introduced by migrations.",
		},
	},
	{
		Slug:    "tenant-and-access-boundaries",
		Title:   "Tenant and access boundaries",
		Summary: "Keep authorization and customer data boundaries explicit.",
		ReviewFor: []string{
			"Tenant scope derived from untrusted input instead of authenticated identity.",
			"Reads or mutations that occur before authorization is established.",
			"Cross-tenant data exposure, object-existence leaks, and unintended privilege changes.",
		},
	},
	{
		Slug:    "reliability-and-concurrency",
		Title:   "Reliability and concurrency",
		Summary: "Make retry, concurrency, and failure behavior deliberate.",
		ReviewFor: []string{
			"Retries without idempotency, deduplication, or bounded retry policy.",
			"Races, lost updates, duplicate delivery, and unsafe concurrent writers.",
			"Timeout, cancellation, cleanup, and partial-failure paths that leave inconsistent state.",
		},
	},
	{
		Slug:    "compatibility",
		Title:   "Compatibility",
		Summary: "Preserve contracts while clients and stored data evolve.",
		ReviewFor: []string{
			"Breaking API, event, configuration, CLI output, or persisted-data changes.",
			"Old and new readers or writers that cannot safely coexist during rollout.",
			"Default changes and removals without a migration, deprecation, or rollback path.",
		},
	},
	{
		Slug:    "operability",
		Title:   "Operability",
		Summary: "Make failures clear to users and observable to operators through actionable errors, logs, metrics, and traces.",
		ReviewFor: []string{
			"User-facing errors that do not say what failed, preserve safe relevant context, or offer a concrete recovery step.",
			"Errors that discard the underlying cause, leak secrets, or report success before work is durable.",
			"Missing or misleading logs, metrics, and traces at important asynchronous and failure boundaries.",
			"Logs that omit the operation and identifiers operators need to diagnose a failure, or use a severity that hides or overstates it.",
			"Health and recovery paths that cannot distinguish degraded, blocked, and failed work.",
		},
	},
	{
		Slug:    "engineering-conventions",
		Title:   "Engineering conventions",
		Summary: "Preserve the codebase-specific standards that make changes consistent and maintainable.",
		ReviewFor: []string{
			"Naming, layout, API, testing, logging, and error-handling patterns established by the team.",
			"Local idioms or required abstractions that a change bypasses without a concrete reason.",
			"Repeated reviewer guidance and documented standards, without inventing a rule from one isolated example.",
		},
	},
}

const readmeHeader = `# Private adversary catalog

This repository is the source of truth for your organization's private
AdversaryLabs adversaries. AdversaryLabs proposes learned changes through pull
requests so your team can review, test, merge, and revert them with normal Git
workflows.

## Layout

- **adversarylabs.yaml** declares the catalog and its adversaries.
- **adversaries/** contains one directory per private adversary.
- **evaluations/** contains regression examples used to validate proposals.
- **exceptions/** contains explicitly scoped exceptions to learned rules.

## Starter adversaries

The initializer includes a small set of editable seeds for concerns shared by
most production systems. Each is a runnable model-backed adversary whose README
is its operative private review policy, not a claim about your architecture.
Keep the relevant ones, remove the others, and let accepted review examples
make them specific to your team:

`

const readmeFooter = `
Each starter brief requires evidence in the changed code. It should not produce
generic best-practice comments without a concrete failure path or violated
contract.

Connect this private repository from the Private library in AdversaryLabs.

## Repository automation

The generated GitHub Actions setup reviews only changed adversary packages, bumps each
merged package's patch version in a serialized [skip-ci] commit, and dispatches
an OIDC publish for that exact commit. Configure these repository settings:

- Secret CAMEL_API_KEY for the adversary-authoring review on pull requests.
- Variable ADVERSARY_REGISTRY_NAMESPACE with your AdversaryLabs team slug.
- An OIDC trust for this GitHub repository in that team.
`

const trainConfig = `# Local training policy. Review evidence remains in .adversary-train/.
version: 1

adversaries:
  root: ./adversaries

# Public adversaries are reserved as a read-only coverage jury. Training never
# writes private evidence into them or recreates them as private catalog entries.
official:
  enabled: true

sources:
  host: github.com
  # discovery: repos
  # Add one or more repositories whose human review history should be learned.
  repos: []
  # since: "2025-09-12"
  # authors_only: [staff-eng-alice]
  # authors_ignore: [automation-account]

run:
  max_prs: 50
  max_turns: 200
  # all_history: true # requires sources.since; ignores max_prs/max_turns
  concurrency: 4

# Catalog training is local-only. Publishing accepted changes is a separate,
# explicit catalog pull-request step.
issues:
  enabled: false

state_dir: .adversary-train
`

func catalogFiles() map[string]string {
	manifest := strings.Builder{}
	manifest.WriteString("apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nmetadata:\n  name: private-adversaries\nspec:\n  adversaries:\n")
	readme := strings.Builder{}
	readme.WriteString(readmeHeader)
	files := map[string]string{
		".gitignore":                                catalogGitignore,
		".github/workflows/adversary-review.yml":    catalogReviewWorkflow,
		".github/workflows/version-adversaries.yml": catalogVersionWorkflow,
		".github/workflows/publish-adversary.yml":   catalogPublishWorkflow,
		"adversary.train.yaml":                      trainConfig,
		"evaluations/.gitkeep":                      "",
		"exceptions/.gitkeep":                       "",
	}
	for _, adversary := range starterAdversaries {
		fmt.Fprintf(&manifest, "    - id: %s\n      path: adversaries/%s\n      summary: %s\n", adversary.Slug, adversary.Slug, adversary.Summary)
		fmt.Fprintf(&readme, "- [%s](adversaries/%s/README.md) — %s\n", adversary.Title, adversary.Slug, adversary.Summary)
		prefix := filepath.ToSlash(filepath.Join("adversaries", adversary.Slug))
		for name, content := range runnableAdversaryFiles(adversary.Slug, adversary.Summary, renderStarterAdversary(adversary)) {
			files[prefix+"/"+name] = content
		}
	}
	readme.WriteString(readmeFooter)
	files["adversarylabs.yaml"] = manifest.String()
	files["README.md"] = readme.String()
	return files
}

const catalogGitignore = `.adversary-train/
node_modules/
.adversary/
`

const catalogReviewWorkflow = `name: Adversary review

on:
  pull_request:
    paths:
      - "adversaries/**"

permissions:
  contents: read

concurrency:
  group: adversary-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  changes:
    name: Find changed adversaries
    runs-on: ubuntu-24.04
    outputs:
      adversaries: ${{ steps.changes.outputs.adversaries }}
    steps:
      - name: Check out source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Build changed-adversary matrix
        id: changes
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          node <<'NODE'
          const { execFileSync } = require("node:child_process");
          const fs = require("node:fs");
          const changed = execFileSync("git", ["diff", "--name-only", process.env.BASE_SHA, process.env.HEAD_SHA], {encoding: "utf8"});
          const adversaries = [...new Set(changed.split("\n").map((path) => path.match(/^adversaries\/([^/]+)\//)?.[1]).filter(Boolean))].sort();
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "adversaries=" + JSON.stringify(adversaries) + "\n");
          NODE

  review:
    name: Review ${{ matrix.adversary }}
    needs: changes
    if: needs.changes.outputs.adversaries != '[]'
    strategy:
      fail-fast: false
      matrix:
        adversary: ${{ fromJSON(needs.changes.outputs.adversaries) }}
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
      pull-requests: write
    steps:
      - name: Check out source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Review adversary package
        uses: adversarylabs/actions/run@v1
        with:
          adversaries: adversarylabs/adversary
          path: adversaries/${{ matrix.adversary }}
          force: true
          model-provider: camel
          model: auto
          model-api-key: ${{ secrets.CAMEL_API_KEY }}
          include-summary: false
`

const catalogVersionWorkflow = `name: Version changed adversaries

on:
  push:
    branches: [main]
    paths:
      - "adversaries/**"
      - "!adversaries/**/adversary.yaml"
      - "!adversaries/**/package.json"
      - "!adversaries/**/package-lock.json"
      - "!adversaries/**/dist/**"
  workflow_dispatch:
    inputs:
      adversaries:
        description: JSON array of adversary directory names still to version
        required: true
        type: string

permissions:
  actions: write
  contents: write

concurrency:
  group: version-adversaries
  cancel-in-progress: false

jobs:
  version:
    name: Version next changed adversary
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Check out source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Select next changed adversary
        id: select
        env:
          EVENT_NAME: ${{ github.event_name }}
          SUPPLIED_ADVERSARIES: ${{ inputs.adversaries }}
          BEFORE_SHA: ${{ github.event.before }}
          HEAD_SHA: ${{ github.sha }}
        run: |
          node <<'NODE'
          const { execFileSync } = require("node:child_process");
          const fs = require("node:fs");
          let adversaries;
          if (process.env.EVENT_NAME === "workflow_dispatch") {
            adversaries = JSON.parse(process.env.SUPPLIED_ADVERSARIES);
          } else {
            const before = !process.env.BEFORE_SHA || /^0+$/.test(process.env.BEFORE_SHA) ? process.env.HEAD_SHA + "^" : process.env.BEFORE_SHA;
            const changed = execFileSync("git", ["diff", "--name-only", before, process.env.HEAD_SHA], {encoding: "utf8"});
            adversaries = [...new Set(changed.split("\n").map((path) => path.match(/^adversaries\/([^/]+)\//)?.[1]).filter(Boolean))].sort();
          }
          if (!Array.isArray(adversaries) || adversaries.some((name) => typeof name !== "string" || !/^[a-z0-9][a-z0-9-]*$/.test(name))) {
            throw new Error("adversaries must be a JSON array of lowercase directory names");
          }
          const [adversary, ...remaining] = [...new Set(adversaries)];
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "empty=" + String(!adversary) + "\n");
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "adversary=" + (adversary || "") + "\n");
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "path=" + (adversary ? "adversaries/" + adversary : "") + "\n");
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "remaining=" + JSON.stringify(remaining) + "\n");
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "has-more=" + String(remaining.length > 0) + "\n");
          NODE

      - name: Set up Node.js
        if: steps.select.outputs.empty == 'false'
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: ${{ steps.select.outputs.path }}/package-lock.json

      - name: Select next patch version
        if: steps.select.outputs.empty == 'false'
        id: next
        env:
          MANIFEST: ${{ steps.select.outputs.path }}/adversary.yaml
        run: |
          node <<'NODE'
          const fs = require("node:fs");
          const manifest = fs.readFileSync(process.env.MANIFEST, "utf8");
          const current = manifest.match(/^version:\s*(\d+)\.(\d+)\.(\d+)\s*$/m);
          if (!current) throw new Error("No stable semantic version found in " + process.env.MANIFEST);
          fs.appendFileSync(process.env.GITHUB_OUTPUT, "tag=v" + current[1] + "." + current[2] + "." + (Number(current[3]) + 1) + "\n");
          NODE

      - name: Synchronize release metadata
        if: steps.select.outputs.empty == 'false'
        id: version
        # The v1 action commits synchronized metadata with [skip-ci].
        uses: adversarylabs/actions/version@v1
        with:
          tag: ${{ steps.next.outputs.tag }}
          path: ${{ steps.select.outputs.path }}
          branch: main
          token: ${{ github.token }}
          sync-npm: auto

      - name: Dispatch OIDC publish
        if: steps.select.outputs.empty == 'false'
        env:
          GH_TOKEN: ${{ github.token }}
          ADVERSARY_PATH: ${{ steps.select.outputs.path }}
          VERSION_COMMIT: ${{ steps.version.outputs.commit }}
        run: gh workflow run publish-adversary.yml --ref main -f path="$ADVERSARY_PATH" -f commit="$VERSION_COMMIT"

      - name: Continue serial versioning
        if: steps.select.outputs.has-more == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
          REMAINING: ${{ steps.select.outputs.remaining }}
        run: gh workflow run version-adversaries.yml --ref main -f adversaries="$REMAINING"
`

const catalogPublishWorkflow = `name: Publish adversary

on:
  workflow_dispatch:
    inputs:
      path:
        description: Catalog-relative adversary directory
        required: true
        type: string
      commit:
        description: Exact version commit to publish
        required: true
        type: string

permissions:
  contents: read
  id-token: write

concurrency:
  group: publish-${{ inputs.path }}
  cancel-in-progress: false

jobs:
  publish:
    name: Publish ${{ inputs.path }}
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - name: Check out versioned source
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ inputs.commit }}
          fetch-depth: 0
          persist-credentials: false

      - name: Verify publish target
        env:
          ADVERSARY_PATH: ${{ inputs.path }}
          VERSION_COMMIT: ${{ inputs.commit }}
        run: |
          if [[ ! "$ADVERSARY_PATH" =~ ^adversaries/[a-z0-9][a-z0-9-]*$ ]]; then
            echo "Invalid adversary path: $ADVERSARY_PATH" >&2
            exit 1
          fi
          if [[ ! "$VERSION_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
            echo "Publish commit must be a full Git SHA" >&2
            exit 1
          fi
          git merge-base --is-ancestor "$VERSION_COMMIT" origin/main
          test -f "$ADVERSARY_PATH/adversary.yaml"

      - name: Set up Node.js
        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: 22
          cache: npm
          cache-dependency-path: ${{ inputs.path }}/package-lock.json

      - name: Publish adversary
        id: publish
        uses: adversarylabs/actions/push@v1
        with:
          path: ${{ inputs.path }}
          auth-mode: oidc
          registry-namespace: ${{ vars.ADVERSARY_REGISTRY_NAMESPACE }}
          push-latest: true

      - name: Report published digest
        env:
          PUBLISHED_REFERENCE: ${{ steps.publish.outputs.reference }}
          PUBLISHED_DIGEST: ${{ steps.publish.outputs.digest }}
        run: echo "Published $PUBLISHED_REFERENCE at $PUBLISHED_DIGEST"
`

func renderStarterAdversary(adversary starterAdversary) string {
	brief := strings.Builder{}
	fmt.Fprintf(&brief, "# %s\n\n> Starter adversary — edit this policy as your team accepts and rejects review findings.\n\n## Purpose\n\n%s\n\n## Review for\n\n", adversary.Title, adversary.Summary)
	for _, check := range adversary.ReviewFor {
		fmt.Fprintf(&brief, "- %s\n", check)
	}
	brief.WriteString("\n## Evidence standard\n\nReport only when the changed code contains a concrete failure path or violates an identifiable contract. Do not report generic best practices, speculative architecture, or concerns already enforced by the code.\n\n## Learning notes\n\nAdversaryLabs can add accepted examples, rejected examples, and tested implementation changes here through reviewed pull requests.\n")
	return brief.String()
}

func Create(opts Options) (Result, error) {
	destination := strings.TrimSpace(opts.Destination)
	if destination == "" {
		destination = "adversary-catalog"
	}
	if _, err := os.Lstat(destination); err == nil {
		return Result{}, fmt.Errorf("destination already exists: %s", destination)
	} else if !os.IsNotExist(err) {
		return Result{}, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, fmt.Errorf("create destination parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".adversary-catalog-init-*")
	if err != nil {
		return Result{}, fmt.Errorf("create catalog staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	for name, content := range catalogFiles() {
		target := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return Result{}, fmt.Errorf("write %s: %w", name, err)
		}
	}
	if err := os.Rename(staging, destination); err != nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			return Result{}, fmt.Errorf("destination already exists: %s", destination)
		}
		return Result{}, fmt.Errorf("publish generated catalog: %w", err)
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return Result{}, err
	}
	return Result{Location: abs}, nil
}

func RenderSuccess(w io.Writer, result Result, platform string) {
	fmt.Fprintln(w, "Creating private adversary catalog...")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "✓ Generated catalog with %d starter adversaries\n", len(starterAdversaries))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Location")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", result.Location)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Next steps")
	fmt.Fprintln(w)
	if platform == "windows" {
		fmt.Fprintf(w, "  Set-Location -LiteralPath %s\n", powershellQuote(result.Location))
	} else {
		fmt.Fprintf(w, "  cd %s\n", shellQuote(result.Location))
	}
	fmt.Fprintln(w, "  git init")
	fmt.Fprintln(w, "  git add .")
	fmt.Fprintln(w, `  git commit -m "Initialize private adversary catalog"`)
	fmt.Fprintln(w, "  Create a private GitHub repository, push this directory, then link it from /library.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Train from human review history")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Edit adversary.train.yaml and add the source repositories to scan.")
	fmt.Fprintln(w, "  adversary catalog train --model codex/gpt-5.6-luna")
	fmt.Fprintln(w, "  adversary catalog train review")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
