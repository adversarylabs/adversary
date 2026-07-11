#!/usr/bin/env bash
set -euo pipefail

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
grep -Fq 'adversary completion bash' README.md || fail 'README command surface drift'
# shellcheck disable=SC2016 # Markdown backticks are literal.
grep -Fq 'version `dev`' README.md || fail 'go install version semantics missing'

if command -v actionlint >/dev/null; then actionlint .depot/workflows/*.yml; fi
if command -v shellcheck >/dev/null; then shellcheck scripts/publish-homebrew.sh scripts/test-release-contract.sh; fi

[[ ! -e dist ]] || fail 'contract test requires absent dist directory'
mkdir dist; touch dist/ignored-release-fixture
[[ -z "$(git ls-files --others --exclude-standard)" ]] || fail 'ignored dist fixture was treated as an unexpected untracked file'
rm -f -- dist/ignored-release-fixture; rmdir dist

fixture_sbom="${TMPDIR:-/tmp}/adversary-spdx-replacement.$$.json"
SOURCE_DATE_EPOCH=0 go run ./scripts/generate-sbom.go -version 1.0.0 -dir scripts/testdata/spdx-replace/main -output "$fixture_sbom"
(cd scripts/spdx-validator && go run . "$fixture_sbom")
grep -Eq '"versionInfo": "v1.2.3\+replace\.[0-9a-f]{12}"' "$fixture_sbom" || fail 'local replacement was not resolved in SBOM'
rm -f -- "$fixture_sbom"

tmp=".release-dist/contract-$$"; tmp2=".release-dist/contract-two-$$"
sum1="${TMPDIR:-/tmp}/adversary-release-one.$$.sum"; sum2="${TMPDIR:-/tmp}/adversary-release-two.$$.sum"
mkdir -p -m 0700 .release-dist; trap 'rm -rf -- "$tmp" "$tmp2"; rm -f -- "$sum1" "$sum2"; rmdir .release-dist 2>/dev/null || true' EXIT
DIST_DIR="$tmp" BUILD_ONLY=1 scripts/publish-homebrew.sh 2099.1.2 >/dev/null
DIST_DIR="$tmp2" BUILD_ONLY=1 scripts/publish-homebrew.sh 2099.1.2 >/dev/null
(cd "$tmp" && shasum -a 256 ./*.tar.gz ./*.spdx.json ./release-manifest.json) >"$sum1"
(cd "$tmp2" && shasum -a 256 ./*.tar.gz ./*.spdx.json ./release-manifest.json) >"$sum2"
cmp "$sum1" "$sum2" || fail 'release output is not reproducible'

PUBLISH_ONLY=1 VERIFY_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null
(cd scripts/spdx-validator && go run . "../../$tmp/adversary_2099.1.2.spdx.json")
touch "$tmp/unexpected"; if PUBLISH_ONLY=1 VERIFY_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'extra bundle entry accepted'; fi
rm -f "$tmp/unexpected"
cp "$tmp/checksums.txt" "$sum1"
head -n 1 "$sum1" >>"$tmp/checksums.txt"
if PUBLISH_ONLY=1 VERIFY_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'duplicate checksum accepted'; fi
cp "$sum1" "$tmp/checksums.txt"
sed '1s#  [^ ]*$#  ../escape#' "$sum1" >"$tmp/checksums.txt"
if PUBLISH_ONLY=1 VERIFY_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'traversal checksum accepted'; fi
cp "$sum1" "$tmp/checksums.txt"
mv "$tmp/release-manifest.json" "$sum2"
if PUBLISH_ONLY=1 VERIFY_ONLY=1 DIST_DIR="$tmp" scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'missing bundle entry accepted'; fi
mv "$sum2" "$tmp/release-manifest.json"

for unsafe in cmd Formula ../adversary-release-escape .; do
  if DIST_DIR="$unsafe" BUILD_ONLY=1 scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail "unsafe DIST_DIR accepted: $unsafe"; fi
done
ln -s "${TMPDIR:-/tmp}" .release-dist/link
if DIST_DIR=.release-dist/link BUILD_ONLY=1 scripts/publish-homebrew.sh 2099.1.2 >/dev/null 2>&1; then fail 'symlink DIST_DIR accepted'; fi
rm -f .release-dist/link
test -f cmd/root.go && test -f Formula/adversary.rb.tmpl || fail 'unsafe deletion damaged source'

for archive in "$tmp"/*.tar.gz; do
  listing="$(tar -tzf "$archive")"
  grep -Eq '(^|/)adversary$' <<<"$listing" || fail "binary absent from $archive"
  grep -Eq '(^|/)LICENSE$' <<<"$listing" || fail "LICENSE absent from $archive"
  grep -Eq '(^|/)README.md$' <<<"$listing" || fail "README absent from $archive"
done
