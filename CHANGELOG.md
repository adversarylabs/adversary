# Changelog

This project uses CalVer (`YYYY.M.D`) releases. Until the first release notes
are imported, GitHub Releases are the authoritative per-release changelog.

Every release note groups user-visible additions, fixes, security changes,
deprecations, and known limitations. Breaking schema or CLI changes identify
the compatibility window and migration path. Security-driven exceptions are
explicit. Tags are immutable; corrections use a new tag rather than moving an
existing one.

## Unreleased

- Model-backed adversaries can request a CLI-owned, authenticated review broker
  with OpenAI or Anthropic credentials kept out of the adversary process.
- CLI audit remediation is being delivered as dependency-ordered pull requests.
- Release artifacts now include deterministic archives, checksums, SPDX SBOM,
  and GitHub build provenance attestations.
