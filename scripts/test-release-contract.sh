#!/usr/bin/env bash
set -euo pipefail

# The contract supplies synthetic credentials only to the channel-isolation
# cases below; ambient CLI credentials must not affect local verification.
unset GITHUB_TOKEN HOMEBREW_TAP_TOKEN GH_TOKEN

fail() { printf 'release contract: %s\n' "$*" >&2; exit 1; }

for workflow in .depot/workflows/*.yml; do
  while IFS= read -r use; do
    [[ "$use" =~ ^[[:space:]]*uses:[[:space:]]+[^@]+@[0-9a-f]{40}([[:space:]]+#[[:space:]]+v[^[:space:]]+)?$ ]] \
      || fail "unpinned or uncommented action in ${workflow}: ${use}"
  done < <(grep -E '^[[:space:]]*uses:' "$workflow" || true)
done

grep -Fq 'No license stanza' Formula/adversary.rb.tmpl || fail 'formula license decision missing'
grep -Fq 'source-code adversaries' Formula/adversary.rb.tmpl || fail 'formula description drift'
grep -Fq '__INSTALLED_BINARY__ version' Formula/adversary.rb.tmpl || fail 'formula smoke test drift'
# shellcheck disable=SC2016 # The function variables are intentional literals.
grep -Fq 'install -m 0644 "${DIST_DIR}/${FORMULA_NAME}"' scripts/publish-homebrew.sh || fail 'tap publication does not use verified formula bytes'
grep -Fq 'staged formula differs from verified bundle' scripts/publish-homebrew.sh || fail 'staged formula digest invariant missing'
grep -Fq 'GNU tar is required' scripts/publish-homebrew.sh || fail 'GNU tar preflight missing'
grep -Fq 'test ! -s /tmp/untracked-files' .depot/workflows/release.yml || fail 'pre-secret nonignored-file check missing'
grep -Fq 'publish-github mode rejects HOMEBREW_TAP_TOKEN' scripts/publish-homebrew.sh || fail 'GitHub publication channel guard missing'
grep -Fq 'publish-homebrew mode rejects GITHUB_TOKEN' scripts/publish-homebrew.sh || fail 'Homebrew publication channel guard missing'
grep -Fq 'adversary completion bash' README.md || fail 'README command surface drift'
# shellcheck disable=SC2016 # Markdown backticks are literal.
grep -Fq 'version `dev`' README.md || fail 'go install version semantics missing'

go run ./scripts/verify-ci-contract.go
if command -v actionlint >/dev/null; then actionlint .depot/workflows/*.yml; fi
if command -v shellcheck >/dev/null; then shellcheck scripts/publish-homebrew.sh scripts/test-release-contract.sh; fi

[[ ! -e dist ]] || fail 'contract test requires absent dist directory'
untracked_before="$(git ls-files --others --exclude-standard)"
mkdir dist; touch dist/ignored-release-fixture
[[ "$(git ls-files --others --exclude-standard)" == "$untracked_before" ]] || fail 'ignored dist fixture was treated as an unexpected untracked file'
rm -f -- dist/ignored-release-fixture; rmdir dist

fixture_sbom="${TMPDIR:-/tmp}/adversary-spdx-replacement.$$.json"
SOURCE_DATE_EPOCH=0 go run ./scripts/generate-sbom.go -version 1.0.0 -dir scripts/testdata/spdx-replace/main -output "$fixture_sbom"
(cd scripts/spdx-validator && go run . "$fixture_sbom")
grep -Eq '"versionInfo": "v1.2.3\+replace\.[0-9a-f]{12}"' "$fixture_sbom" || fail 'local replacement was not resolved in SBOM'
rm -f -- "$fixture_sbom"

tmp=".release-dist/contract-$$"; tmp2=".release-dist/contract-two-$$"
sum1="${TMPDIR:-/tmp}/adversary-release-one.$$.sum"; sum2="${TMPDIR:-/tmp}/adversary-release-two.$$.sum"
fakebin="${TMPDIR:-/tmp}/adversary-release-fake-$$"; publish_log="${TMPDIR:-/tmp}/adversary-release-publish-$$.log"
mkdir -p -m 0700 .release-dist; trap 'rm -rf -- "$tmp" "$tmp2" "$fakebin"; rm -f -- "$sum1" "$sum2" "$publish_log"; rmdir .release-dist 2>/dev/null || true' EXIT
DIST_DIR="$tmp" RELEASE_MODE=build scripts/publish-homebrew.sh 2099.1.2 >/dev/null
DIST_DIR="$tmp2" RELEASE_MODE=build scripts/publish-homebrew.sh 2099.1.2 >/dev/null
(cd "$tmp" && shasum -a 256 ./*.tar.gz ./*.spdx.json ./release-manifest.json) >"$sum1"
(cd "$tmp2" && shasum -a 256 ./*.tar.gz ./*.spdx.json ./release-manifest.json) >"$sum2"
if ! cmp "$sum1" "$sum2"; then
  printf '%s\n' 'release contract: reproducibility checksum diff:' >&2
  diff -u "$sum1" "$sum2" >&2 || true
  for first in "$tmp"/*; do
    second="$tmp2/${first##*/}"
    if [[ ! -f "$second" ]] || ! cmp -s -- "$first" "$second"; then
      printf 'release contract: nondeterministic artifact: %s\n' "${first##*/}" >&2
      case "$first" in
        *.tar.gz)
          printf '%s\n' 'release contract: first archive listing:' >&2
          tar -tvzf "$first" >&2
          printf '%s\n' 'release contract: second archive listing:' >&2
          [[ -f "$second" ]] && tar -tvzf "$second" >&2
          ;;
      esac
    fi
  done
  fail 'release output is not reproducible'
fi

RELEASE_MODE=verify DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
(cd scripts/spdx-validator && go run . "../../$tmp/adversary_2099.1.2.spdx.json")
touch "$tmp/unexpected"; if RELEASE_MODE=verify DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'extra bundle entry accepted'; fi
rm -f "$tmp/unexpected"
cp "$tmp/checksums.txt" "$sum1"
head -n 1 "$sum1" >>"$tmp/checksums.txt"
if RELEASE_MODE=verify DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'duplicate checksum accepted'; fi
cp "$sum1" "$tmp/checksums.txt"
sed '1s#  [^ ]*$#  ../escape#' "$sum1" >"$tmp/checksums.txt"
if RELEASE_MODE=verify DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'traversal checksum accepted'; fi
cp "$sum1" "$tmp/checksums.txt"
mv "$tmp/release-manifest.json" "$sum2"
if RELEASE_MODE=verify DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'missing bundle entry accepted'; fi
mv "$sum2" "$tmp/release-manifest.json"

for unsafe in cmd Formula ../adversary-release-escape .; do
  if DIST_DIR="$unsafe" RELEASE_MODE=build scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail "unsafe DIST_DIR accepted: $unsafe"; fi
done
ln -s "${TMPDIR:-/tmp}" .release-dist/link
if DIST_DIR=.release-dist/link RELEASE_MODE=build scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'symlink DIST_DIR accepted'; fi
rm -f .release-dist/link
if [[ ! -f cmd/root.go || ! -f Formula/adversary.rb.tmpl ]]; then fail 'unsafe deletion damaged source'; fi

mkdir -p "$fakebin"
chmod 0700 "$fakebin"
cat >"$fakebin/gh" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$PUBLISH_TEST_LOG"
if [ "$1 $2" = "release view" ]; then
  [ -f "$PUBLISH_GH_STATE/release" ] || exit 1
  case "$*" in
    *'--json isDraft'*) [ "$(cat "$PUBLISH_GH_STATE/state")" = draft ] && printf 'true\n' || printf 'false\n' ;;
    *'--json isPrerelease'*) cat "$PUBLISH_GH_STATE/prerelease" ;;
    *'--json assets'*)
      count=$(cat "$PUBLISH_GH_STATE/list-count" 2>/dev/null || printf '0')
      count=$((count + 1)); printf '%s\n' "$count" >"$PUBLISH_GH_STATE/list-count"
      if [ -f "$PUBLISH_GH_STATE/race-replace" ] && [ "$count" -ge 3 ]; then
        for asset in "$PUBLISH_GH_STATE/remote"/*; do
          [ -f "$asset" ] || continue
          printf 'replacement\n' >>"$asset"
          printf 'replacement-%s\n' "$count" >"$PUBLISH_GH_STATE/ids/${asset##*/}"
          break
        done
      fi
      if [ -f "$PUBLISH_GH_STATE/race-state" ] && [ "$count" -ge 3 ]; then printf 'published\n' >"$PUBLISH_GH_STATE/state"; fi
      for asset in "$PUBLISH_GH_STATE/remote"/*; do
        if [ -f "$asset" ]; then
          size=$(wc -c <"$asset" | tr -d ' ')
          printf '%s\t%s\t%s\t\n' "$(cat "$PUBLISH_GH_STATE/ids/${asset##*/}")" "${asset##*/}" "$size"
        fi
      done
      if [ -f "$PUBLISH_GH_STATE/race" ] && [ "$count" -ge 3 ]; then printf 'concurrent-id\tconcurrent-extra\t1\t\n'; fi
      ;;
  esac
  exit 0
fi
if [ "$1 $2" = "release create" ]; then
  mkdir -p "$PUBLISH_GH_STATE/remote" "$PUBLISH_GH_STATE/ids"
  : >"$PUBLISH_GH_STATE/release"; printf 'draft\n' >"$PUBLISH_GH_STATE/state"
  case "$*" in *'--prerelease'*) printf 'true\n';; *) printf 'false\n';; esac >"$PUBLISH_GH_STATE/prerelease"
  exit 0
fi
if [ "$1 $2" = "release upload" ]; then
  shift 2
  for argument in "$@"; do
    if [ -f "$argument" ]; then
      [ ! -e "$PUBLISH_GH_STATE/remote/${argument##*/}" ] || exit 2
      cp "$argument" "$PUBLISH_GH_STATE/remote/${argument##*/}"
      next=$(cat "$PUBLISH_GH_STATE/next-id" 2>/dev/null || printf '1')
      printf 'asset-%s\n' "$next" >"$PUBLISH_GH_STATE/ids/${argument##*/}"
      next=$((next + 1)); printf '%s\n' "$next" >"$PUBLISH_GH_STATE/next-id"
    fi
  done
  exit 0
fi
if [ "$1 $2" = "release download" ]; then
  pattern='' destination=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --pattern) pattern=$2; shift 2 ;;
      --dir) destination=$2; shift 2 ;;
      *) shift ;;
    esac
  done
  cp "$PUBLISH_GH_STATE/remote/$pattern" "$destination/$pattern"
  exit 0
fi
if [ "$1 $2" = "release edit" ]; then printf 'published\n' >"$PUBLISH_GH_STATE/state"; exit 0; fi
exit 0
EOF
chmod 0700 "$fakebin/gh"
export PUBLISH_TEST_LOG="$publish_log"
export PUBLISH_GH_STATE="$fakebin/github-state"
setup_github_state() {
  local scenario="$1" asset first='' next=1
  rm -rf -- "$PUBLISH_GH_STATE"; mkdir -p "$PUBLISH_GH_STATE/remote" "$PUBLISH_GH_STATE/ids"
  case "$scenario" in
    absent|race|race-replace|race-state)
      if [[ "$scenario" == race ]]; then : >"$PUBLISH_GH_STATE/race"; fi
      if [[ "$scenario" == race-replace ]]; then : >"$PUBLISH_GH_STATE/race-replace"; fi
      if [[ "$scenario" == race-state ]]; then : >"$PUBLISH_GH_STATE/race-state"; fi
      return
      ;;
    partial-draft|mismatch-draft|published-partial)
      for asset in "$tmp"/*; do first="$asset"; break; done
      cp "$first" "$PUBLISH_GH_STATE/remote/${first##*/}"
      ;;
    exact-published|unexpected|mismatch|wrong-prerelease)
      for asset in "$tmp"/*; do cp "$asset" "$PUBLISH_GH_STATE/remote/${asset##*/}"; done
      ;;
  esac
  for asset in "$PUBLISH_GH_STATE/remote"/*; do
    [[ -f "$asset" ]] || continue
    printf 'asset-%s\n' "$next" >"$PUBLISH_GH_STATE/ids/${asset##*/}"
    next=$((next + 1))
  done
  printf '%s\n' "$next" >"$PUBLISH_GH_STATE/next-id"
  : >"$PUBLISH_GH_STATE/release"
  case "$scenario" in partial-draft|mismatch-draft) printf 'draft\n';; *) printf 'published\n';; esac >"$PUBLISH_GH_STATE/state"
  printf 'false\n' >"$PUBLISH_GH_STATE/prerelease"
  if [[ "$scenario" == unexpected ]]; then printf 'unexpected\n' >"$PUBLISH_GH_STATE/remote/unexpected.txt"; fi
  if [[ "$scenario" == mismatch || "$scenario" == mismatch-draft ]]; then
    for asset in "$PUBLISH_GH_STATE/remote"/*; do printf 'mismatch\n' >>"$asset"; break; done
  fi
  if [[ "$scenario" == wrong-prerelease ]]; then printf 'true\n' >"$PUBLISH_GH_STATE/prerelease"; fi
}

setup_github_state absent
: >"$publish_log"
PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
if ! grep -Fq 'release view' "$publish_log" || ! grep -Fq 'release create' "$publish_log"; then fail 'GitHub-only publication did not invoke the expected release operations'; fi
grep -Eq 'release create .* --draft( |$)' "$publish_log" || fail 'new GitHub release was not created as a draft'
grep -Fq 'release upload' "$publish_log" || fail 'new draft did not receive verified assets'
tail -n 1 "$publish_log" | grep -Fq 'release edit' || fail 'draft promotion was not the final operation'
if grep -Fq -- '--clobber' "$publish_log"; then fail 'GitHub publication retained destructive clobber behavior'; fi

setup_github_state partial-draft
: >"$publish_log"
PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
grep -Fq 'release download' "$publish_log" || fail 'partial draft did not verify the existing asset bytes'
grep -Fq 'release upload' "$publish_log" || fail 'partial retry did not upload missing assets'
tail -n 1 "$publish_log" | grep -Fq 'release edit' || fail 'resumed draft promotion was not the final operation'
if grep -Fq -- '--clobber' "$publish_log"; then fail 'partial retry attempted to replace an existing asset'; fi

setup_github_state mismatch-draft
: >"$publish_log"
if PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'mismatched existing draft asset was accepted'; fi
if grep -Eq 'release (upload|edit)' "$publish_log"; then fail 'mismatched existing draft was mutated'; fi

setup_github_state exact-published
: >"$publish_log"
PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
grep -Fq 'release download' "$publish_log" || fail 'exact retry did not verify existing asset bytes'
if grep -Eq 'release (create|upload|edit)' "$publish_log"; then fail 'exact published retry was not a no-op'; fi

setup_github_state published-partial
: >"$publish_log"
if PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'partial published GitHub release was accepted'; fi
if grep -Eq 'release (upload|edit)' "$publish_log"; then fail 'partial published release was mutated'; fi

for rejected_state in unexpected mismatch wrong-prerelease; do
  setup_github_state "$rejected_state"; : >"$publish_log"
  if PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail "invalid published GitHub state was accepted: $rejected_state"; fi
  if grep -Eq 'release (upload|edit)' "$publish_log"; then fail "invalid published GitHub state was mutated: $rejected_state"; fi
done

setup_github_state race
: >"$publish_log"
if PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'post-upload GitHub asset mutation was accepted'; fi
if grep -Fq 'release edit' "$publish_log"; then fail 'raced draft was promoted'; fi
for raced_state in race-replace race-state; do
  setup_github_state "$raced_state"; : >"$publish_log"
  if PATH="$fakebin:$PATH" RELEASE_MODE=publish-github GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail "concurrent GitHub mutation was accepted: $raced_state"; fi
  if grep -Fq 'release edit' "$publish_log"; then fail "concurrently changed draft was promoted: $raced_state"; fi
done
if RELEASE_MODE=publish-github GITHUB_TOKEN=test-token GH_TOKEN=override-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'GitHub publication accepted an overriding GH_TOKEN'; fi
if RELEASE_MODE=publish-github GITHUB_TOKEN=test-token HOMEBREW_TAP_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'GitHub publication accepted the tap token'; fi
if RELEASE_MODE=publish-homebrew GITHUB_TOKEN=test-token HOMEBREW_TAP_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'Homebrew publication accepted GitHub authority'; fi
if RELEASE_MODE=verify GITHUB_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'verification accepted a publication credential'; fi
if BUILD_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'legacy release mode was accepted'; fi
set +e
empty_cleanup_output="$(DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 2>&1)"
empty_cleanup_status=$?
set -e
[[ $empty_cleanup_status -eq 1 ]] || fail "empty cleanup changed the original failure status: ${empty_cleanup_status}"
if grep -Fq 'unbound variable' <<<"$empty_cleanup_output"; then fail 'empty cleanup is not set -u safe'; fi
if [[ -x /bin/bash ]] && /bin/bash --version | head -n 1 | grep -Fq 'version 3.2'; then
  set +e
  bash3_cleanup_output="$(DIST_DIR="$tmp" /bin/bash scripts/publish-homebrew.sh 2099.1.2 2>&1)"
  bash3_cleanup_status=$?
  set -e
  [[ $bash3_cleanup_status -eq 1 ]] || fail "Bash 3.2 cleanup changed the original failure status: ${bash3_cleanup_status}"
  if grep -Fq 'unbound variable' <<<"$bash3_cleanup_output"; then fail 'Bash 3.2 empty cleanup is not set -u safe'; fi
fi

real_git="$(command -v git)"
cat >"$fakebin/git" <<'EOF'
#!/bin/sh
case "$1" in
  clone)
    printf 'clone\n' >>"$PUBLISH_TEST_LOG"
    mkdir -p -- "$3/Formula"
    ;;
  -C)
    printf 'tap %s\n' "$*" >>"$PUBLISH_TEST_LOG"
    ;;
  *) exec "$REAL_GIT" "$@" ;;
esac
EOF
chmod 0700 "$fakebin/git"
export REAL_GIT="$real_git"
: >"$publish_log"
PATH="$fakebin:$PATH" RELEASE_MODE=publish-homebrew HOMEBREW_TAP_TOKEN=test-token DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
grep -Fxq 'clone' "$publish_log" || fail 'Homebrew-only publication did not stage the verified formula'
if grep -Fq 'release ' "$publish_log"; then fail 'Homebrew-only publication invoked GitHub release operations'; fi

for archive in "$tmp"/*.tar.gz; do
  listing="$(tar -tzf "$archive")"
  grep -Eq '(^|/)adversary$' <<<"$listing" || fail "binary absent from $archive"
  grep -Eq '(^|/)LICENSE$' <<<"$listing" || fail "LICENSE absent from $archive"
  grep -Eq '(^|/)README.md$' <<<"$listing" || fail "README absent from $archive"
done
