# Changelog

This project uses CalVer (`YYYY.M.D`) releases. Until the first release notes
are imported, GitHub Releases are the authoritative per-release changelog.

Every release note groups user-visible additions, fixes, security changes,
deprecations, and known limitations. Breaking schema or CLI changes identify
the compatibility window and migration path. Security-driven exceptions are
explicit. Tags are immutable; corrections use a new tag rather than moving an
existing one.

## Unreleased

- `adversary run` now defaults to the `review/code` composition. The generalist
  reviews the full change while manifest-matched specialists run concurrently
  on scoped changed files with repository-graph context.
- Composed reviews now emit one conservatively deduplicated result and retain
  every contributing reviewer in finding metadata. `--no-compose` remains
  supported for controlled evaluation but is hidden from normal help.
- Packing preserves self-contained JavaScript bundles instead of appending the
  installed SDK dependency closure when no unresolved SDK import remains.
- Model provider and model can be selected per run with flags, and Fireworks is
  supported through its structured Chat Completions API.
- Model-backed adversaries can request a CLI-owned, authenticated review broker
  with provider credentials kept out of the adversary process.
- CLI audit remediation is being delivered as dependency-ordered pull requests.
- Release artifacts now include deterministic archives, checksums, SPDX SBOM,
  and GitHub build provenance attestations.
