#!/usr/bin/env bash
set -euo pipefail

readonly REPO="adversarylabs/adversary" TAP_REPO="adversarylabs/homebrew-tap" BINARY="adversary"
readonly DIST_DIR="${DIST_DIR:-dist}" FORMULA_TEMPLATE="${FORMULA_TEMPLATE:-Formula/adversary.rb.tmpl}"
readonly STABLE_FORMULA_NAME="adversary.rb" PRERELEASE_FORMULA_NAME="adversary-beta.rb"
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/adversary-go-build}"

TEMP_PATHS=()
cleanup() {
  HOMEBREW_TAP_TOKEN=""
  unset HOMEBREW_TAP_TOKEN GH_TOKEN GIT_ASKPASS
  local path
  for path in "${TEMP_PATHS[@]}"; do rm -rf -- "$path"; done
}
trap cleanup EXIT HUP INT TERM

log() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

detect_tag() {
  if [[ $# -gt 0 && -n "${1:-}" ]]; then printf '%s\n' "$1"
  elif [[ -n "${GITHUB_REF_NAME:-}" ]]; then printf '%s\n' "$GITHUB_REF_NAME"
  elif [[ "${GITHUB_REF:-}" =~ ^refs/tags/(.+)$ ]]; then printf '%s\n' "${BASH_REMATCH[1]}"
  else git describe --tags --exact-match 2>/dev/null || true; fi
}

checksum_for() {
  local checksum
  checksum="$(awk -v artifact="$1" '$2 == artifact { print $1 }' "${DIST_DIR}/checksums.txt")"
  [[ -n "$checksum" ]] || fail "missing checksum for $1"
  printf '%s\n' "$checksum"
}

render_formula() {
  local output="$1" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/adversary-formula.XXXXXX")"; TEMP_PATHS+=("$tmp")
  sed -e "s|__VERSION__|${VERSION}|g" -e "s|__FORMULA_CLASS__|${FORMULA_CLASS}|g" \
    -e "s|__INSTALLED_BINARY__|${INSTALLED_BINARY}|g" \
    -e "s|__DARWIN_AMD64_URL__|${DARWIN_AMD64_URL}|g" -e "s|__DARWIN_AMD64_SHA256__|${DARWIN_AMD64_SHA256}|g" \
    -e "s|__DARWIN_ARM64_URL__|${DARWIN_ARM64_URL}|g" -e "s|__DARWIN_ARM64_SHA256__|${DARWIN_ARM64_SHA256}|g" \
    -e "s|__LINUX_AMD64_URL__|${LINUX_AMD64_URL}|g" -e "s|__LINUX_AMD64_SHA256__|${LINUX_AMD64_SHA256}|g" \
    -e "s|__LINUX_ARM64_URL__|${LINUX_ARM64_URL}|g" -e "s|__LINUX_ARM64_SHA256__|${LINUX_ARM64_SHA256}|g" \
    "$FORMULA_TEMPLATE" >"$tmp"
  mv -- "$tmp" "$output"
}

guard_and_clean_dist() {
  local root parent
  root="$(git rev-parse --show-toplevel)"; [[ "$PWD" == "$root" ]] || fail "release must run from the Git root"
  [[ "$DIST_DIR" == dist || "$DIST_DIR" =~ ^\.release-dist/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "DIST_DIR must be dist or .release-dist/<safe-name>"
  parent="${DIST_DIR%/*}"; [[ "$parent" == "$DIST_DIR" ]] && parent=.
  mkdir -p -- "$parent"
  [[ ! -L "$parent" && ! -L "$DIST_DIR" ]] || fail "DIST_DIR path must not contain symbolic links"
  [[ "$(cd "$parent" && pwd -P)" == "$root" || "$(cd "$parent" && pwd -P)" == "$root/.release-dist" ]] || fail "DIST_DIR escapes the Git root"
  rm -rf -- "$DIST_DIR"
  mkdir -p -- "$DIST_DIR"
}

create_archive() {
  local build_dir="$1" archive="$2" tar_cmd=tar
  command -v gtar >/dev/null 2>&1 && tar_cmd=gtar
  "$tar_cmd" --version 2>/dev/null | grep -Fq 'GNU tar' || fail "GNU tar is required (install gtar on macOS)"
  "$tar_cmd" --sort=name --format=ustar --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH}" --mode='u+rwX,go+rX,go-w' -C "$build_dir" -cf - . \
    | gzip -n -9 >"${DIST_DIR}/${archive}"
}

verify_binary() {
  local file="$1" metadata
  metadata="$(go version -m "$file")"
  grep -Fq 'path' <<<"$metadata" || fail "Go build metadata missing from ${file}"
  LC_ALL=C grep -aFq -- "$VERSION" "$file" || fail "stamped version missing from ${file}"
}

build_release() {
  guard_and_clean_dist
  log "Building deterministic release archives for ${TAG}"
  local target goos goarch build_dir archive
  for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
    goos="${target%/*}"; goarch="${target#*/}"
    build_dir="${DIST_DIR}/${BINARY}_${VERSION}_${goos}_${goarch}"
    archive="${BINARY}_${VERSION}_${goos}_${goarch}.tar.gz"
    mkdir -p "$build_dir/docs"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
      -ldflags="-s -w -X github.com/adversarylabs/adversary/internal/version.Version=${VERSION} -X github.com/adversarylabs/adversary/internal/version.Commit=${COMMIT} -X github.com/adversarylabs/adversary/internal/version.BuildDate=${BUILD_DATE}" \
      -o "${build_dir}/${BINARY}" .
    verify_binary "${build_dir}/${BINARY}"
    install -m 0644 LICENSE README.md "${build_dir}/"
    install -m 0644 docs/release.md docs/trust-model.md "${build_dir}/docs/"
    create_archive "$build_dir" "$archive"
    rm -rf -- "$build_dir"
  done
  if [[ "$(go env GOOS)/$(go env GOARCH)" == linux/amd64 ]]; then
    tar -xOzf "${DIST_DIR}/${LINUX_AMD64_ARCHIVE}" ./adversary >"${DIST_DIR}/.smoke-adversary"
    chmod 0755 "${DIST_DIR}/.smoke-adversary"
    "${DIST_DIR}/.smoke-adversary" version | grep -Fq "$VERSION" || fail "native version smoke test failed"
    rm -f -- "${DIST_DIR}/.smoke-adversary"
  fi
  go run ./scripts/generate-sbom.go -version "$VERSION" -output "${DIST_DIR}/adversary_${VERSION}.spdx.json"
  (cd scripts/spdx-validator && go run . "../../${DIST_DIR}/adversary_${VERSION}.spdx.json")
  (cd "$DIST_DIR" && LC_ALL=C shasum -a 256 "${ARCHIVES[@]}" "adversary_${VERSION}.spdx.json" >checksums.txt)
}

finalize_bundle() {
  render_formula "${DIST_DIR}/${FORMULA_NAME}"
  go run ./scripts/generate-release-manifest.go -dir "$DIST_DIR" -version "$VERSION" -commit "$COMMIT" -formula "$FORMULA_NAME" -output "${DIST_DIR}/release-manifest.json"
  (cd "$DIST_DIR" && LC_ALL=C shasum -a 256 "${ARCHIVES[@]}" "adversary_${VERSION}.spdx.json" "$FORMULA_NAME" release-manifest.json >checksums.txt)
}

verify_bundle() {
  go run ./scripts/verify-release-bundle.go -dir "$DIST_DIR" -version "$VERSION" -commit "$COMMIT" -formula "$FORMULA_NAME"
  (cd "$DIST_DIR" && shasum -a 256 -c checksums.txt >/dev/null)
}

upload_release_assets() {
  local assets=("${DIST_DIR}/${ARCHIVES[0]}" "${DIST_DIR}/${ARCHIVES[1]}" "${DIST_DIR}/${ARCHIVES[2]}" "${DIST_DIR}/${ARCHIVES[3]}" "${DIST_DIR}/adversary_${VERSION}.spdx.json" "${DIST_DIR}/${FORMULA_NAME}" "${DIST_DIR}/release-manifest.json" "${DIST_DIR}/checksums.txt")
  export GH_TOKEN="$GITHUB_TOKEN"
  if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release upload "$TAG" "${assets[@]}" --repo "$REPO" --clobber
  else
    local flags=(); [[ "$IS_PRERELEASE" == 1 ]] && flags+=(--prerelease)
    gh release create "$TAG" "${assets[@]}" --repo "$REPO" --title "$TAG" --generate-notes "${flags[@]}"
  fi
}

publish_formula() {
  local tap_dir askpass
  tap_dir="$(mktemp -d "${TMPDIR:-/tmp}/adversary-tap.XXXXXX")"; askpass="$(mktemp "${TMPDIR:-/tmp}/adversary-askpass.XXXXXX")"; TEMP_PATHS+=("$tap_dir" "$askpass")
  chmod 0700 "$askpass"
  # shellcheck disable=SC2016 # The generated helper expands these at invocation time.
  printf '%s\n' '#!/bin/sh' 'case "$1" in *Username*) printf "%s\n" x-access-token;; *) printf "%s\n" "$HOMEBREW_TAP_TOKEN";; esac' >"$askpass"
  export GIT_ASKPASS="$askpass" GIT_TERMINAL_PROMPT=0
  git clone "https://github.com/${TAP_REPO}.git" "$tap_dir"
  mkdir -p "${tap_dir}/Formula"
  install -m 0644 "${DIST_DIR}/${FORMULA_NAME}" "${tap_dir}/Formula/${FORMULA_NAME}"
  [[ "$(shasum -a 256 "${DIST_DIR}/${FORMULA_NAME}" | awk '{print $1}')" == "$(shasum -a 256 "${tap_dir}/Formula/${FORMULA_NAME}" | awk '{print $1}')" ]] || fail "staged formula differs from verified bundle"
  git -C "$tap_dir" config user.name "${GIT_COMMITTER_NAME:-adversary-release-bot}"
  git -C "$tap_dir" config user.email "${GIT_COMMITTER_EMAIL:-release-bot@adversarylabs.com}"
  git -C "$tap_dir" add "Formula/${FORMULA_NAME}"
  git -C "$tap_dir" diff --cached --quiet || { git -C "$tap_dir" commit -m "Update adversary to ${TAG}"; git -C "$tap_dir" push origin HEAD; }
}

need git; need go; need shasum; need gzip; need tar
[[ -f "$FORMULA_TEMPLATE" && -f LICENSE ]] || fail "release metadata is missing"
TAG="$(detect_tag "${1:-}")"; [[ -n "$TAG" ]] || fail "could not determine release tag"
[[ "$TAG" =~ ^20[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || fail "invalid CalVer tag: ${TAG}"
VERSION="$TAG"; COMMIT="$(git rev-parse HEAD)"; SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
export SOURCE_DATE_EPOCH
BUILD_DATE="$(date -u -r "$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
if [[ "$TAG" == *-* ]]; then IS_PRERELEASE=1; FORMULA_NAME="$PRERELEASE_FORMULA_NAME"; FORMULA_CLASS=AdversaryBeta; INSTALLED_BINARY=adversary-beta
else IS_PRERELEASE=0; FORMULA_NAME="$STABLE_FORMULA_NAME"; FORMULA_CLASS=Adversary; INSTALLED_BINARY="$BINARY"; fi
DARWIN_AMD64_ARCHIVE="${BINARY}_${VERSION}_darwin_amd64.tar.gz"; DARWIN_ARM64_ARCHIVE="${BINARY}_${VERSION}_darwin_arm64.tar.gz"
LINUX_AMD64_ARCHIVE="${BINARY}_${VERSION}_linux_amd64.tar.gz"; LINUX_ARM64_ARCHIVE="${BINARY}_${VERSION}_linux_arm64.tar.gz"
ARCHIVES=("$DARWIN_AMD64_ARCHIVE" "$DARWIN_ARM64_ARCHIVE" "$LINUX_AMD64_ARCHIVE" "$LINUX_ARM64_ARCHIVE")

[[ "${PUBLISH_ONLY:-0}" == 1 ]] || build_release
if [[ "${PUBLISH_ONLY:-0}" == 1 ]]; then verify_bundle; fi
for archive in "${ARCHIVES[@]}"; do checksum_for "$archive" >/dev/null; done
DARWIN_AMD64_SHA256="$(checksum_for "$DARWIN_AMD64_ARCHIVE")"; DARWIN_ARM64_SHA256="$(checksum_for "$DARWIN_ARM64_ARCHIVE")"
LINUX_AMD64_SHA256="$(checksum_for "$LINUX_AMD64_ARCHIVE")"; LINUX_ARM64_SHA256="$(checksum_for "$LINUX_ARM64_ARCHIVE")"
base="https://github.com/${REPO}/releases/download/${TAG}"
DARWIN_AMD64_URL="$base/$DARWIN_AMD64_ARCHIVE"; DARWIN_ARM64_URL="$base/$DARWIN_ARM64_ARCHIVE"
LINUX_AMD64_URL="$base/$LINUX_AMD64_ARCHIVE"; LINUX_ARM64_URL="$base/$LINUX_ARM64_ARCHIVE"
if [[ "${PUBLISH_ONLY:-0}" != 1 ]]; then finalize_bundle; verify_bundle; fi
if [[ "${BUILD_ONLY:-0}" == 1 || "${SKIP_PUBLISH:-0}" == 1 || "${VERIFY_ONLY:-0}" == 1 ]]; then exit 0; fi
[[ -n "${HOMEBREW_TAP_TOKEN:-}" && -n "${GITHUB_TOKEN:-}" ]] || fail "publishing tokens are required"
need gh; upload_release_assets; publish_formula; log "Published ${TAG}"
