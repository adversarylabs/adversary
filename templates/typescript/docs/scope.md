# {{name}} — mission and scope

Source of truth for what this adversary is *for*.

Consumers:

- **This package** — prompts, rules, and review behavior should stay aligned with this doc.
- **adversary factory** (and multi-adversary routing) — when grading human PR comments as gold, only **in-scope** comments count as fair misses for this package.

Edit this file before relying on factory or multi-adversary routing. Replace the placeholders below with a real mission.

## Package

- **Name:** `local/{{name}}` (keep in sync with `adversary.yaml`)
- **Factory routing:** human PR comments are attributed here only when they match **In scope**.
- **Languages / surfaces:** _(e.g. Go `*.go`, TypeScript, Dockerfiles, GitHub Actions — list them)_

## Mission

_(One or two sentences: what staff-level question does this adversary answer?)_

Example: Review this change for incomplete remediation and maintainability risk in application code.

## In scope (fair miss if humans raised it and we did not)

- _(Concrete defect classes this package should catch)_
- _(e.g. races, secrets, wrong error handling — be specific)_

## Out of scope (not a miss for this adversary)

- Pure documentation / comment wording / style nits
- Bot / automated reviewer comments (Copilot, dependabot, etc.)
- Concerns owned by a more specific specialist when one exists
- _(Add domains you deliberately leave to other packages)_

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading (avoid false product failures)

## Notes for authors

- Prefer **lower false-positive rates** over aggressive detection when writing rules.
- Keep mission narrow enough that factory routing can distinguish this package from siblings.
- When you change behavior in `src/`, update this file in the same change.
