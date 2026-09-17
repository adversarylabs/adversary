#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'generated version action test: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 2 ]] || fail "usage: $0 <adversary-binary> <actions-v1-checkout>"
binary="$1"
actions_root="$2"
metadata_script="$actions_root/version/scripts/metadata.mjs"
runtime_script="$actions_root/version/scripts/runtime.mjs"
[[ -x "$binary" ]] || fail "adversary binary is not executable: $binary"
[[ -f "$metadata_script" ]] || fail "metadata script does not exist: $metadata_script"
[[ -f "$runtime_script" ]] || fail "runtime script does not exist: $runtime_script"
[[ "$(node --version)" == v22.* ]] || fail "Node 22 is required; found $(node --version)"

tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/adversary-version-fixture.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
catalog="$tmp/catalog"
project_relative="adversaries/reliability-and-concurrency"
project="$catalog/$project_relative"

HOME="$tmp/home" "$binary" catalog init "$catalog" >/dev/null

grep -Fq $'  command:\n    - dist/index.js' "$project/adversary.yaml" \
  || fail "generated runtime command is not a block-style list"
if grep -Fq 'command: [' "$project/adversary.yaml"; then
  fail "generated runtime command uses unsupported inline YAML"
fi
grep -Fq 'readFileSync(new URL("../package.json", import.meta.url), "utf8")' "$project/src/index.ts" \
  || fail "generated source does not read its package version"
grep -Fq 'version: packageVersion' "$project/src/index.ts" \
  || fail "generated source does not pass the package version"
if grep -Fq 'version: "0.0.1"' "$project/src/index.ts"; then
  fail "generated source hard-codes its runtime version"
fi

git -C "$catalog" init --initial-branch=main >/dev/null
git -C "$catalog" config user.name version-fixture
git -C "$catalog" config user.email version-fixture@example.com
git -C "$catalog" add .
git -C "$catalog" commit -m generated >/dev/null

(
  cd "$project"
  HOME="$tmp/home" npm_config_cache="$tmp/npm-cache" npm ci
  HOME="$tmp/home" npm_config_cache="$tmp/npm-cache" npm test
)
git -C "$catalog" diff --exit-code \
  || fail "a clean Node 22 build changed generated tracked files"

metadata_output="$tmp/metadata-output.txt"
runtime_output="$tmp/runtime-output.json"
(
  cd "$catalog"
  node "$metadata_script" apply "$project_relative" 0.0.2 auto >"$metadata_output"
  HOME="$tmp/home" npm_config_cache="$tmp/npm-cache" \
    node "$runtime_script" apply "$project_relative" 0.0.2 "$runtime_output"
  node "$metadata_script" verify "$project_relative" 0.0.2 auto >/dev/null
  node "$runtime_script" verify "$project_relative" 0.0.2
)

expected_metadata=$'private/reliability-and-concurrency\nadversaries/reliability-and-concurrency/adversary.yaml\nadversaries/reliability-and-concurrency/package.json\nadversaries/reliability-and-concurrency/package-lock.json'
[[ "$(<"$metadata_output")" == "$expected_metadata" ]] \
  || fail "metadata script reported unexpected paths: $(<"$metadata_output")"

changed="$(git -C "$catalog" diff --name-only)"
expected_changed=$'adversaries/reliability-and-concurrency/adversary.yaml\nadversaries/reliability-and-concurrency/package-lock.json\nadversaries/reliability-and-concurrency/package.json'
[[ "$changed" == "$expected_changed" ]] \
  || fail "patch bump changed unexpected tracked files: $changed"

node -e '
  const output = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  if (!Array.isArray(output.files) || output.files.length !== 0) process.exit(1);
' "$runtime_output" || fail "runtime build reported unexpected source or dist changes"

[[ -f "$project/dist/index.js" ]] || fail "project-relative dist/index.js was not built"
[[ ! -e "$project/reliability-and-concurrency" ]] \
  || fail "versioning created a duplicated adversary project path"
grep -Fq 'version: packageVersion' "$project/src/index.ts" \
  || fail "version action rewrote package-derived source"

printf 'generated catalog version-action integration passed\n'
