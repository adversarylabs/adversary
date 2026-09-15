#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'release ref: %s\n' "$*" >&2; exit 1; }
tag="${GITHUB_REF_NAME:-}"
[[ "${GITHUB_REF_TYPE:-tag}" == tag ]] || fail 'workflow ref is not a tag'
[[ "$tag" =~ ^20[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || fail "invalid release tag: $tag"
git_root="$(git rev-parse --show-toplevel)" || fail 'not a Git checkout'
[[ "$PWD" == "$git_root" ]] || fail 'release must run at the Git root'
tag_commit="$(git rev-parse "refs/tags/${tag}^{commit}")" || fail 'tag is absent'
head_commit="$(git rev-parse HEAD)"
[[ "$head_commit" == "$tag_commit" ]] || fail "HEAD $head_commit is not tag commit $tag_commit"
main_commit="$(git rev-parse 'refs/remotes/origin/main^{commit}')" || fail 'origin/main is absent from release checkout'
git merge-base --is-ancestor "$tag_commit" "$main_commit" || fail "tag commit $tag_commit is not reachable from origin/main"
git diff --quiet --ignore-submodules -- || fail 'tracked checkout is dirty'
git diff --cached --quiet --ignore-submodules -- || fail 'index is dirty'
[[ -z "$(git ls-files --others --exclude-standard)" ]] || fail 'checkout has untracked files'
