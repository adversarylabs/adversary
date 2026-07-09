# AGENTS.md

## Purpose

This repository contains an Adversary Labs adversary.

An adversary analyzes a repository and emits structured findings.

The adversary should be deterministic, safe to run repeatedly, and produce stable output.

## Project Layout

- `src/` contains the adversary implementation.
- `test/` contains unit and integration tests.
- `fixtures/` contains repositories used by tests.
- `adversary.yaml` describes runtime metadata.

## Design Principles

- Parse files once whenever practical.
- Keep rules independent.
- One responsibility per rule.
- Produce deterministic findings.
- Include evidence with every finding.
- Include actionable recommendations.
- Never modify the scanned repository.
- Prefer lower false-positive rates over aggressive detection.

## SDK

Prefer SDK APIs over direct runtime implementation details.

When the SDK provides helpers, use them instead of custom implementations.

## Testing

Whenever adding or modifying a rule:

- Add or update fixtures.
- Add or update unit tests.
- Update snapshot tests if expected findings change.

All tests should pass before changes are considered complete.

## Code Style

- Favor readability over cleverness.
- Keep modules small.
- Avoid duplicated parsing logic.
- Keep parser logic separate from rule logic.
- Keep findings deterministic.

## Goal

The repository should remain an excellent reference implementation for authors building new adversaries.
