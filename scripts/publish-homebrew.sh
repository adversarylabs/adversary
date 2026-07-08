#!/usr/bin/env bash
set -euo pipefail

readonly REPO="adversarylabs/adversary"
readonly TAP_REPO="adversarylabs/homebrew"
readonly BINARY="adversary"
readonly DIST_DIR="${DIST_DIR:-dist}"
readonly FORMULA_TEMPLATE="${FORMULA_TEMPLATE:-Formula/adversary.rb.tmpl}"
readonly STABLE_FORMULA_NAME="adversary.rb"
readonly PRERELEASE_FORMULA_NAME="adversary-beta.rb"

export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/adversary-go-build}"

log() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

detect_tag() {
  if [[ $# -gt 0 && -n "${1:-}" ]]; then
    printf '%s\n' "$1"
    return
  fi

  if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
    printf '%s\n' "$GITHUB_REF_NAME"
    return
  fi

  if [[ "${GITHUB_REF:-}" =~ ^refs/tags/(.+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return
  fi

  git describe --tags --exact-match 2>/dev/null || true
}

checksum_for() {
  local artifact="$1"
  local checksum

  checksum="$(awk -v artifact="$artifact" '$2 == artifact { print $1 }' "${DIST_DIR}/checksums.txt")"
  [[ -n "$checksum" ]] || fail "missing checksum for ${artifact}"
  printf '%s\n' "$checksum"
}

render_formula() {
  local output="$1"
  local tmp
  tmp="$(mktemp)"

  sed \
    -e "s|__VERSION__|${VERSION}|g" \
    -e "s|__FORMULA_CLASS__|${FORMULA_CLASS}|g" \
    -e "s|__INSTALLED_BINARY__|${INSTALLED_BINARY}|g" \
    -e "s|__DARWIN_AMD64_URL__|${DARWIN_AMD64_URL}|g" \
    -e "s|__DARWIN_AMD64_SHA256__|${DARWIN_AMD64_SHA256}|g" \
    -e "s|__DARWIN_ARM64_URL__|${DARWIN_ARM64_URL}|g" \
    -e "s|__DARWIN_ARM64_SHA256__|${DARWIN_ARM64_SHA256}|g" \
    -e "s|__LINUX_AMD64_URL__|${LINUX_AMD64_URL}|g" \
    -e "s|__LINUX_AMD64_SHA256__|${LINUX_AMD64_SHA256}|g" \
    -e "s|__LINUX_ARM64_URL__|${LINUX_ARM64_URL}|g" \
    -e "s|__LINUX_ARM64_SHA256__|${LINUX_ARM64_SHA256}|g" \
    "$FORMULA_TEMPLATE" >"$tmp"

  mv "$tmp" "$output"
}

upload_release_assets() {
  local assets=(
    "${DIST_DIR}/${DARWIN_AMD64_ARCHIVE}"
    "${DIST_DIR}/${DARWIN_ARM64_ARCHIVE}"
    "${DIST_DIR}/${LINUX_AMD64_ARCHIVE}"
    "${DIST_DIR}/${LINUX_ARM64_ARCHIVE}"
    "${DIST_DIR}/checksums.txt"
  )

  export GH_TOKEN="${HOMEBREW_TAP_TOKEN}"

  if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
    log "Uploading artifacts to existing GitHub Release ${TAG}"
    gh release upload "$TAG" "${assets[@]}" --repo "$REPO" --clobber
  else
    log "Creating GitHub Release ${TAG} and uploading artifacts"
    gh release create "$TAG" "${assets[@]}" \
      --repo "$REPO" \
      --title "$TAG" \
      --notes "Release ${TAG}"
  fi
}

publish_formula() {
  local tap_dir
  tap_dir="$(mktemp -d)"

  log "Cloning Homebrew tap ${TAP_REPO}"
  git clone "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${TAP_REPO}.git" "$tap_dir"

  mkdir -p "${tap_dir}/Formula"
  render_formula "${tap_dir}/Formula/${FORMULA_NAME}"

  git -C "$tap_dir" config user.name "${GIT_COMMITTER_NAME:-adversary-release-bot}"
  git -C "$tap_dir" config user.email "${GIT_COMMITTER_EMAIL:-release-bot@adversarylabs.com}"

  if git -C "$tap_dir" diff --quiet -- "Formula/${FORMULA_NAME}"; then
    log "Formula is already current"
    return
  fi

  git -C "$tap_dir" add "Formula/${FORMULA_NAME}"
  git -C "$tap_dir" commit -m "Update adversary to ${TAG}"
  log "Pushing Homebrew formula update"
  git -C "$tap_dir" push origin HEAD
}

need git
need go
need shasum
need tar

[[ -f "$FORMULA_TEMPLATE" ]] || fail "formula template not found: ${FORMULA_TEMPLATE}"

TAG="$(detect_tag "${1:-}")"
[[ -n "$TAG" ]] || fail "could not determine release tag"
if [[ ! "$TAG" =~ ^20[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  fail "tag must be CalVer-like (2026.7.8 or 2026.7.8-beta.1), got ${TAG}"
fi

VERSION="$TAG"
if [[ "$TAG" == *-* ]]; then
  FORMULA_NAME="$PRERELEASE_FORMULA_NAME"
  FORMULA_CLASS="AdversaryBeta"
  INSTALLED_BINARY="adversary-beta"
else
  FORMULA_NAME="$STABLE_FORMULA_NAME"
  FORMULA_CLASS="Adversary"
  INSTALLED_BINARY="$BINARY"
fi
readonly TAG VERSION FORMULA_NAME FORMULA_CLASS INSTALLED_BINARY

DARWIN_AMD64_ARCHIVE="${BINARY}_${VERSION}_darwin_amd64.tar.gz"
DARWIN_ARM64_ARCHIVE="${BINARY}_${VERSION}_darwin_arm64.tar.gz"
LINUX_AMD64_ARCHIVE="${BINARY}_${VERSION}_linux_amd64.tar.gz"
LINUX_ARM64_ARCHIVE="${BINARY}_${VERSION}_linux_arm64.tar.gz"
readonly DARWIN_AMD64_ARCHIVE DARWIN_ARM64_ARCHIVE LINUX_AMD64_ARCHIVE LINUX_ARM64_ARCHIVE

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

log "Building release archives for ${TAG}"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
  goos="${target%/*}"
  goarch="${target#*/}"
  build_dir="${DIST_DIR}/${BINARY}_${VERSION}_${goos}_${goarch}"
  archive="${BINARY}_${VERSION}_${goos}_${goarch}.tar.gz"

  mkdir -p "$build_dir"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -trimpath \
    -ldflags="-s -w" \
    -o "${build_dir}/${BINARY}" \
    .
  tar -C "$build_dir" -czf "${DIST_DIR}/${archive}" "$BINARY"
done

log "Generating SHA256 checksums"
(
  cd "$DIST_DIR"
  shasum -a 256 "$DARWIN_AMD64_ARCHIVE" "$DARWIN_ARM64_ARCHIVE" "$LINUX_AMD64_ARCHIVE" "$LINUX_ARM64_ARCHIVE" >checksums.txt
)

log "Verifying expected checksums"
DARWIN_AMD64_SHA256="$(checksum_for "$DARWIN_AMD64_ARCHIVE")"
DARWIN_ARM64_SHA256="$(checksum_for "$DARWIN_ARM64_ARCHIVE")"
LINUX_AMD64_SHA256="$(checksum_for "$LINUX_AMD64_ARCHIVE")"
LINUX_ARM64_SHA256="$(checksum_for "$LINUX_ARM64_ARCHIVE")"
readonly DARWIN_AMD64_SHA256 DARWIN_ARM64_SHA256 LINUX_AMD64_SHA256 LINUX_ARM64_SHA256

DARWIN_AMD64_URL="https://github.com/${REPO}/releases/download/${TAG}/${DARWIN_AMD64_ARCHIVE}"
DARWIN_ARM64_URL="https://github.com/${REPO}/releases/download/${TAG}/${DARWIN_ARM64_ARCHIVE}"
LINUX_AMD64_URL="https://github.com/${REPO}/releases/download/${TAG}/${LINUX_AMD64_ARCHIVE}"
LINUX_ARM64_URL="https://github.com/${REPO}/releases/download/${TAG}/${LINUX_ARM64_ARCHIVE}"
readonly DARWIN_AMD64_URL DARWIN_ARM64_URL LINUX_AMD64_URL LINUX_ARM64_URL

if [[ "${SKIP_PUBLISH:-}" == "1" ]]; then
  log "Rendering formula to ${DIST_DIR}/${FORMULA_NAME}"
  render_formula "${DIST_DIR}/${FORMULA_NAME}"
  log "Skipping GitHub Release and Homebrew tap publishing"
  exit 0
fi

[[ -n "${HOMEBREW_TAP_TOKEN:-}" ]] || fail "HOMEBREW_TAP_TOKEN is required"
need gh

upload_release_assets
publish_formula

log "Published ${TAG}"
