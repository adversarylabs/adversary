# Changelog

This project uses CalVer (`YYYY.M.D`) releases. Until the first release notes
are imported, GitHub Releases are the authoritative per-release changelog.

Every release note groups user-visible additions, fixes, security changes,
deprecations, and known limitations. Breaking schema or CLI changes identify
the compatibility window and migration path. Security-driven exceptions are
explicit. Tags are immutable; corrections use a new tag rather than moving an
existing one.

## Unreleased

- GitHub reviews register posted inline findings with Adversary Labs, retrieve
  repository-scoped maintainer feedback before later model-backed reviews, and
  embed provenance-rich v2 markers for SaaS polling.
- Packing preserves self-contained JavaScript bundles instead of appending the
  installed SDK dependency closure when no unresolved SDK import remains.
- Model provider and model can be selected per run with flags, and Fireworks is
  supported through its structured Chat Completions API.
- Model-backed adversaries can request a CLI-owned, authenticated review broker
  with provider credentials kept out of the adversary process.
- CLI audit remediation is being delivered as dependency-ordered pull requests.
- Release artifacts now include deterministic archives, checksums, SPDX SBOM,
  and GitHub build provenance attestations.
