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
		Summary: "Make production failures visible, diagnosable, and recoverable.",
		ReviewFor: []string{
			"Errors that discard actionable context or report success before work is durable.",
			"Missing metrics, logs, or traces at important asynchronous and failure boundaries.",
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
most production systems. They are starting policies, not claims about your
architecture. Keep the relevant ones, remove the others, and let accepted
review examples make them specific to your team:

`

const readmeFooter = `
Each starter brief requires evidence in the changed code. It should not produce
generic best-practice comments without a concrete failure path or violated
contract.

Connect this private repository from the Private library in AdversaryLabs.
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
  # Add one or more repositories whose human review history should be learned.
  repos: []
  # authors_only: [staff-eng-alice]
  # authors_ignore: [automation-account]

run:
  max_prs: 50
  max_turns: 200
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
		".gitignore":           ".adversary-train/\n",
		"adversary.train.yaml": trainConfig,
		"evaluations/.gitkeep": "",
		"exceptions/.gitkeep":  "",
	}
	for _, adversary := range starterAdversaries {
		fmt.Fprintf(&manifest, "    - id: %s\n      path: adversaries/%s\n      summary: %s\n", adversary.Slug, adversary.Slug, adversary.Summary)
		fmt.Fprintf(&readme, "- [%s](adversaries/%s/README.md) — %s\n", adversary.Title, adversary.Slug, adversary.Summary)
		files[filepath.ToSlash(filepath.Join("adversaries", adversary.Slug, "README.md"))] = renderStarterAdversary(adversary)
	}
	readme.WriteString(readmeFooter)
	files["adversarylabs.yaml"] = manifest.String()
	files["README.md"] = readme.String()
	return files
}

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
	fmt.Fprintln(w, "  adversary catalog train")
	fmt.Fprintln(w, "  adversary catalog train review")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
