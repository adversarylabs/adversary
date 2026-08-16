# {{name}}

{{description}}

## Goals

This adversary turns a focused review policy into deterministic, actionable
findings backed by repository evidence. It is intended to stay quiet when the
available evidence does not justify a finding.

## Scope

The starter implementation checks that a repository has a root `README.md`.
Replace or extend that rule to match the review responsibility documented in
[`docs/scope.md`](docs/scope.md).

The complete detector inventory is maintained in [CHECKS.md](CHECKS.md).
Review-comment tone and presentation guidance lives in
[`agent/voice.md`](agent/voice.md).

## Boundaries

The starter does not judge README quality, documentation completeness, or any
other repository property. Keep [`CHECKS.md`](CHECKS.md) synchronized with the
implemented rules as the adversary evolves. Author setup, testing, validation,
and packaging instructions live in [CONTRIBUTING.md](CONTRIBUTING.md).
