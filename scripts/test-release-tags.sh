#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q
git -C "$tmp" -c user.name='Release test' -c user.email='release@example.test' commit -q --allow-empty -m fixture
git -C "$tmp" update-ref refs/remotes/origin/main HEAD

for tag in 2026.9.20 2026.9.20-beta.1; do
  git -C "$tmp" tag "$tag"
  (cd -P "$tmp" && GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$tag" bash "$root/scripts/verify-release-ref.sh")
done

for tag in 2026.9.19.2 2026.9.19.2-beta.1; do
  if (cd -P "$tmp" && GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$tag" bash "$root/scripts/verify-release-ref.sh") >"$tmp/error" 2>&1; then
    echo "release verifier accepted four-part tag: $tag" >&2
    exit 1
  fi
  grep -Fq 'invalid release tag' "$tmp/error"
  if (cd "$root" && RELEASE_MODE=build bash scripts/publish-homebrew.sh "$tag") >"$tmp/error" 2>&1; then
    echo "release publisher accepted four-part tag: $tag" >&2
    exit 1
  fi
  grep -Fq 'invalid CalVer tag' "$tmp/error"
done

echo "release tag tests passed"
