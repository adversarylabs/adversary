# Comment voice

**Voice** is how the CLI turns deterministic finding text into GitHub pull request
comments that sound like a product or persona (for example a blunt maintainer),
without hard-coding review strings in detection rules.

| Concern | Where it lives |
|---------|----------------|
| **What** is found | Package rules / model review (`src/`, specialists via `uses`) |
| **How** it sounds | Package `agent/voice.md` (+ example bank) and CLI rewrite |
| **When** to fire | Scope, train “when to post”, detection heuristics |

Voice does **not** invent technical depth. If the finding summary is empty of
mechanism, rewrite can only sound blunt about a shallow claim. Put evidence and
reasoning in the finding; put cadence and bans in voice.

## When voice runs

```sh
adversary run ./my-adversary --path ./app \
  --github-review \
  --model-provider openai --model …
```

1. Adversaries produce findings (template bodies).
2. If a model provider is configured, the CLI **rewrites** each planned comment
   with a prompt built from the resolved voice document.
3. On rewrite failure or missing credentials, the **template** body is kept.

Without `--github-review`, voice files are unused for posting (findings still
print to the terminal / JSON as usual).

## Resolving the voice file

First hit wins:

1. **Adversary package roots** (local path args that look like packages: have
   `adversary.yaml` or `agent/scope.md` / `docs/scope.md`), in CLI order:
   - `agent/voice.md` (preferred)
   - `train/voice.md`
   - `voice.md`
   - `VOICE.md` (legacy)
2. **Review target** (`--path`), same relative names
3. Else the **CLI-embedded** default prompt

Examples:

```sh
# Voice from torvalds package (entry), not from each specialist
adversary run ./torvalds-adversary --path ../app --github-review

# Composition: entry package still owns voice
adversary run lang/go --path ./service --github-review
# → findings from go/* members; rewrite voice from lang/go if it has agent/voice.md
```

With **composition** (`uses`), prefer putting persona voice on the package you
**name on the CLI**. Member packages’ voice files are not used for rewrite when
they are only pulled in as members. See [composition](./composition.md).

Core voice files are size-capped (~**32 KiB**) when loaded from disk.

## Package layout (`agent/voice.md`)

`adversary init` scaffolds `agent/voice.md` with:

1. **Core voice** — persona rules, length, bans, output shape  
2. **Example maintainer comments (style only)** — few-shot bank with spirit
   subsections  
3. **Output** — “return only the PR comment body”

### Core voice

Edit this for product tone:

- Lead with the issue; mechanism over attitude  
- Confidence honesty; no invented files/APIs  
- Length targets (often ~2–6 short sentences)  
- Hard bans (corporate padding, praise sandwiches, etc. for a Torvalds-style pack)

### Example bank (style few-shots)

Under a heading exactly:

```markdown
## Example maintainer comments (style only)
```

use subsections:

| Subsection | Spirit |
|------------|--------|
| `### Ship / OK` | Landable / LGTM-class signals |
| `### Design / technical judgment` | Brittle or wrong approach |
| `### Defects / correctness` | Real bugs / invariants |
| `### Nits / style` | Non-blocking taste |

Bank **real human** review excerpts as blockquotes (train apply issues spell this
out). Rules for the model (also enforced in the CLI rewrite preamble):

- Match **cadence and bluntness**, not copy the quote  
- Re-ground every claim in the **current** finding’s evidence  
- **Never** emit an example quote unchanged as the PR comment  
- **Never** invent facts from examples that are not in the finding  

Optional one-line source note after a quote:

```markdown
> Looks all reasonable to me
>
> _(source: https://github.com/org/repo/pull/71 — style only)_
```

### Optional section files (large corpora)

For large persona banks, packages may also keep spirit-class files next to core
voice (for example `agent/voice-ship.md`, `voice-design.md`, `voice-defects.md`,
`voice-nits.md`, plus optional `voice-ship-1.md` shards). That keeps **core rules
small** and growth in bank files.

Today the CLI rewrite loads the **core** voice path (`agent/voice.md`) as one
document (plus rewrite instructions). Keep active few-shots **inside** that file
(or under the example-bank heading) so rewrite sees them. Use separate section
files as the authoring/target layout train apply points at when packages adopt
split banks; see package READMEs (e.g. torvalds-adversary).

## Rewrite pipeline

```text
finding → template body
       → BuildRewritePrompt(voice.md + task preamble)
       → model (JSON { "body": "…" })
       → tracking marker appended
       → GitHub comment
```

The rewrite task preamble tells the model to treat the example bank as few-shot
style only. JSON input includes severity, title, template body, path/line, and
`exampleBankHint` (preferred subsection: Ship / OK, Design, Defects, or Nits).

**Model flags** (shared with analysis when configured):

- `--model-provider` (`openai` | `anthropic` | `fireworks`)  
- `--model`  

Env overrides: `ADVERSARY_MODEL_PROVIDER`, `ADVERSARY_MODEL`.

## Train: banking gold

`adversary train results apply` opens issues that require, for **human** miss/human
rows:

1. Teach **detection** for the spirit class (when to post)  
2. Bank the **human** excerpt into the package voice example bank  

Do **not** bank synthetic draft titles or package-generated text. Detection strings
in `src/` stay generic; wording variance comes from rewrite + the bank.

## Authoring checklist

- [ ] `agent/voice.md` exists for persona / product packages  
- [ ] Core rules match the product (bans, length, structure)  
- [ ] Example bank heading + spirit subsections present  
- [ ] Gold is short, human, deduped  
- [ ] Findings carry enough mechanism for rewrite to stay honest  
- [ ] With composition, voice lives on the **entry** package you run  

## Related

- [Train home-built adversaries](./train.md) — grade locals; bank gold on apply  
- [GitHub PR review posting](./github-review-posting.md) — flags, auth, placement  
- [Composition (`uses`)](./composition.md) — entry package owns voice under multi-run  
- [Automatic detection](./automatic-detection.md) — who runs; separate from voice  
