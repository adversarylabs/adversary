#!/usr/bin/env bash
set -euo pipefail

readonly ACTIONLINT_VERSION="1.7.7"
readonly SHELLCHECK_VERSION="0.10.0"
readonly GOVULNCHECK_VERSION="1.6.0"
readonly COVERAGE_FLOOR="70.0"

fail() { printf 'ci verify: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

root="$(git rev-parse --show-toplevel)"
[[ "$PWD" == "$root" ]] || fail "run from the Git repository root"

# Codex sandboxes and some local macOS setups expose an unusable default Go
# cache. CI runners use their native cache; Unix local runs fall back to /tmp
# only when the configured cache cannot be written.
if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* ]]; then
  configured_cache="${GOCACHE:-$(go env GOCACHE)}"
  cache_probe="${configured_cache}/.adversary-write-probe-$$"
  if ! { mkdir -p -- "$configured_cache" 2>/dev/null && ( : >"$cache_probe" ) 2>/dev/null; }; then
    export GOCACHE="/tmp/adversary-ci-go-cache-${UID:-0}"
    mkdir -p -- "$GOCACHE"
  else
    rm -f -- "$cache_probe"
  fi

  configured_mod_cache="${GOMODCACHE:-$(go env GOMODCACHE)}"
  mod_cache_probe="${configured_mod_cache}/.adversary-write-probe-$$"
  if ! { mkdir -p -- "$configured_mod_cache" 2>/dev/null && ( : >"$mod_cache_probe" ) 2>/dev/null; }; then
    export GOPATH="/tmp/adversary-ci-go-path-${UID:-0}"
    export GOMODCACHE="/tmp/adversary-ci-go-mod-${UID:-0}"
    mkdir -p -- "$GOPATH" "$GOMODCACHE"
  else
    rm -f -- "$mod_cache_probe"
  fi
fi

make_temp_dir() {
  local dir
  if dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/adversary-ci.XXXXXX" 2>/dev/null)"; then
    printf '%s\n' "$dir"
    return
  fi
  mktemp -d /tmp/adversary-ci.XXXXXX
}

tracked_format() {
  local unformatted
  unformatted="$(git ls-files '*.go' | while IFS= read -r file; do gofmt -l "$file"; done)"
  [[ -z "$unformatted" ]] || { printf '%s\n' "$unformatted" >&2; fail "tracked Go files are not formatted"; }
}

native_tests() {
  log "Go tests"
  go test ./...
  log "vendored TypeScript SDK protocol tests"
  node --test templates/typescript/vendor/adversary-sdk/test/protocol.test.js
}

quality() {
  log "tracked gofmt check"
  tracked_format
  log "module verification"
  go mod verify
  log "Go vet"
  go vet ./...
  log "CI and release workflow contract"
  go run ./scripts/verify-ci-contract.go
}

race_tests() {
  log "Go race tests"
  go test -race ./...
}

coverage() {
  local tmp profile total
  tmp="$(make_temp_dir)"
  trap 'rm -rf -- "$tmp"' RETURN
  profile="$tmp/coverage.out"
  log "Go coverage (floor ${COVERAGE_FLOOR}%)"
  go test -coverprofile="$profile" ./...
  total="$(go tool cover -func="$profile" | awk '/^total:/ { gsub(/%/, "", $3); print $3 }')"
  [[ -n "$total" ]] || fail "could not calculate total coverage"
  awk -v actual="$total" -v floor="$COVERAGE_FLOOR" 'BEGIN { exit !(actual + 0 >= floor + 0) }' \
    || fail "coverage ${total}% is below the ${COVERAGE_FLOOR}% floor"
  printf 'total statement coverage: %s%% (floor %s%%)\n' "$total" "$COVERAGE_FLOOR"
  rm -rf -- "$tmp"
  trap - RETURN
}

cross_build() {
  local target="${TARGET:-}" goos goarch tmp suffix=""
  case "$target" in
    linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64) ;;
    *) fail "TARGET must be one of linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64" ;;
  esac
  goos="${target%/*}"
  goarch="${target#*/}"
  [[ "$goos" == windows ]] && suffix=".exe"
  tmp="$(make_temp_dir)"
  trap 'rm -rf -- "$tmp"' RETURN
  log "cross-build ${target}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -o "$tmp/adversary${suffix}" .
  test -s "$tmp/adversary${suffix}" || fail "cross-build produced no binary for ${target}"
  rm -rf -- "$tmp"
  trap - RETURN
}

template_tests() {
  local tmp binary project
  need npm
  tmp="$(make_temp_dir)"
  trap 'rm -rf -- "$tmp"' RETURN
  binary="$tmp/adversary"
  project="$tmp/generated-adversary"
  log "generate TypeScript template with the actual CLI"
  go build -trimpath -o "$binary" .
  HOME="$tmp/home" "$binary" init "$project"
  log "generated TypeScript npm ci, build, tests, and complete audit"
  (
    cd "$project"
    export HOME="$tmp/home"
    export npm_config_cache="$tmp/npm-cache"
    npm ci
    npm run build
    npm test
    npm audit --audit-level=low
  )
  rm -rf -- "$tmp"
  trap - RETURN
}

cli_smoke() {
  local tmp binary project json
  tmp="$(make_temp_dir)"
  trap 'rm -rf -- "$tmp"' RETURN
  binary="$tmp/adversary"
  project="$tmp/smoke-adversary"
  json="$tmp/pack-check.json"
  log "build and execute CLI version/init/pack preflight smoke"
  go build -trimpath -ldflags='-X github.com/adversarylabs/adversary/internal/version.Version=ci-smoke' -o "$binary" .
  "$binary" version | grep -Fq 'ci-smoke' || fail "version smoke failed"
  HOME="$tmp/home" "$binary" init "$project" >/dev/null
  HOME="$tmp/home" "$binary" pack --check --format json "$project" >"$json"
  grep -Fq '"command":"pack-check"' "$json" || fail "pack --check smoke did not emit its versioned JSON envelope"
  [[ ! -e "$tmp/home/.adversary/artifacts" ]] || fail "pack --check mutated the artifact repository"
  rm -rf -- "$tmp"
  trap - RETURN
}

tool_archive() {
  local tool="$1" os arch version url sha archive_dir archive shell_arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os/$arch" in
    Linux/x86_64) os=linux; arch=amd64 ;;
    Linux/aarch64|Linux/arm64) os=linux; arch=arm64 ;;
    Darwin/x86_64) os=darwin; arch=amd64 ;;
    Darwin/arm64) os=darwin; arch=arm64 ;;
    *) fail "unsupported tooling platform: $(uname -s)/$(uname -m)" ;;
  esac
  archive_dir="$2"
  case "$tool/$os/$arch" in
    actionlint/linux/amd64) sha=023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757 ;;
    actionlint/linux/arm64) sha=401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0 ;;
    actionlint/darwin/amd64) sha=28e5de5a05fc558474f638323d736d822fff183d2d492f0aecb2b73cc44584f5 ;;
    actionlint/darwin/arm64) sha=2693315b9093aeacb4ebd91a993fea54fc215057bf0da2659056b4bc033873db ;;
    shellcheck/linux/amd64) sha=6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87 ;;
    shellcheck/linux/arm64) sha=324a7e89de8fa2aed0d0c28f3dab59cf84c6d74264022c00c22af665ed1a09bb ;;
    shellcheck/darwin/amd64) sha=ef27684f23279d112d8ad84e0823642e43f838993bbb8c0963db9b58a90464c2 ;;
    shellcheck/darwin/arm64) sha=bbd2f14826328eee7679da7221f2bc3afb011f6a928b848c80c321f6046ddf81 ;;
    *) fail "no checksum for ${tool} on ${os}/${arch}" ;;
  esac
  if [[ "$tool" == actionlint ]]; then
    version="$ACTIONLINT_VERSION"
    archive="actionlint_${version}_${os}_${arch}.tar.gz"
    url="https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}"
  else
    version="$SHELLCHECK_VERSION"
    shell_arch="$arch"
    [[ "$arch" == amd64 ]] && shell_arch=x86_64
    [[ "$os/$arch" == darwin/arm64 ]] && shell_arch=aarch64
    [[ "$os/$arch" == linux/arm64 ]] && shell_arch=aarch64
    archive="shellcheck-v${version}.${os}.${shell_arch}.tar.xz"
    url="https://github.com/koalaman/shellcheck/releases/download/v${version}/${archive}"
  fi
  need curl
  curl --fail --location --silent --show-error --retry 3 --output "$archive_dir/$archive" "$url"
  printf '%s  %s\n' "$sha" "$archive_dir/$archive" | shasum -a 256 -c - >/dev/null
  printf '%s\n' "$archive_dir/$archive"
}

security_tooling() {
  local tmp archive actionlint_bin shellcheck_bin tool_mod_cache cache_probe
  tmp="$(make_temp_dir)"
  trap 'rm -rf -- "$tmp"' RETURN
  log "install checksum-pinned actionlint ${ACTIONLINT_VERSION} and ShellCheck ${SHELLCHECK_VERSION}"
  archive="$(tool_archive actionlint "$tmp")"
  tar -xzf "$archive" -C "$tmp"
  actionlint_bin="$tmp/actionlint"
  archive="$(tool_archive shellcheck "$tmp")"
  tar -xJf "$archive" -C "$tmp"
  shellcheck_bin="$tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck"
  if [[ ! -x "$actionlint_bin" || ! -x "$shellcheck_bin" ]]; then fail "tool extraction failed"; fi
  PATH="$tmp:$tmp/shellcheck-v${SHELLCHECK_VERSION}:$PATH" "$actionlint_bin" .depot/workflows/*.yml
  "$shellcheck_bin" scripts/*.sh
  log "govulncheck ${GOVULNCHECK_VERSION}"
  tool_mod_cache="${GOMODCACHE:-$(go env GOMODCACHE)}"
  cache_probe="${tool_mod_cache}/.adversary-write-probe-$$"
  if ! { mkdir -p -- "$tool_mod_cache" 2>/dev/null && ( : >"$cache_probe" ) 2>/dev/null; }; then
    tool_mod_cache="/tmp/adversary-ci-go-mod-${UID:-0}"
    mkdir -p -- "$tool_mod_cache"
  else
    rm -f -- "$cache_probe"
  fi
  XDG_CACHE_HOME="$tmp/cache" GOPATH="$tmp/gopath" GOMODCACHE="$tool_mod_cache" \
    go run "golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK_VERSION}" ./...
  rm -rf -- "$tmp"
  trap - RETURN
}

release_contract() {
  log "release contract"
  scripts/test-release-contract.sh
}

run_all() {
  local target
  quality
  native_tests
  race_tests
  coverage
  for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    TARGET="$target" cross_build
  done
  template_tests
  cli_smoke
  security_tooling
  release_contract
}

case "${1:-all}" in
  all) run_all ;;
  native) native_tests ;;
  quality) quality ;;
  race) race_tests ;;
  coverage) coverage ;;
  cross) cross_build ;;
  template) template_tests ;;
  smoke) cli_smoke ;;
  tooling) security_tooling ;;
  release) release_contract ;;
  *) fail "unknown verification stage: ${1:-}" ;;
esac
