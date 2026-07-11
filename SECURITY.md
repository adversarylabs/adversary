# Security policy

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting for `adversarylabs/adversary`; if it is unavailable,
contact the repository owners privately through the organization profile.
Include affected versions, reproduction steps, impact, and suggested
mitigations. Do not include live credentials or third-party data.

The latest release and `main` receive security fixes. The team will acknowledge
a report within five business days, assess severity, coordinate a disclosure
date, and publish a GitHub security advisory and patched release when warranted.
Dependencies are monitored by Dependabot; maintainers run `govulncheck ./...`
during release review and after dependency advisories. Security fixes
may bypass normal deprecation windows but never required tests or review.

The host runner is intentionally not a sandbox. Behavior explicitly described
in [docs/trust-model.md](docs/trust-model.md) is a known limitation unless an
enforcement boundary fails closed contrary to that contract.
