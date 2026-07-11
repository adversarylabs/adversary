# Platform and runtime support (CLI-018)

This document is the repository decision record for CLI-018.

## Supported contract

The CLI builds and is tested on Linux, macOS, and Windows. Artifact manifests,
not the presence of `package.json` or `dist/`, select the runtime. The supported
named host runtimes are `node` and `process`; image runtimes may be stored but
the local `run` command does not execute containers.

Node is user-managed. The CLI does not download, install, or update Node and no
longer advertises a managed-runtime store. It resolves an absolute
`ADVERSARY_NODE_PATH`, a `node` on the immutable startup `PATH`, then
conventional nvm, Volta, and asdf locations. Every candidate is a regular
executable, must answer `--version` under the captured startup environment, and
must satisfy the manifest's semantic-version requirement. Bare `22` means
`>=22.0.0, <23.0.0`; normal semver constraints are also accepted. Empty and
relative startup `PATH` entries are rejected rather than interpreted relative
to a mutable working directory.

Runtime discovery is a cooperative same-user trust boundary, not a stable-file
identity guarantee. Explicit `ADVERSARY_NODE_PATH` and conventional nvm, Volta,
and asdf candidates are rejected when the executable or any pathname component
is a symlink. A candidate discovered through captured `PATH` may itself be a
symlink (as in Nix profiles), but the CLI resolves it first, requires an
absolute canonical target, validates that target as a regular executable, and
uses the canonical target for both `--version` and execution. It never executes
the original alias, so replacing that alias after resolution cannot redirect
the child. A user who can replace the canonical target's path components
between validation, probing, and execution can still win a pathname TOCTOU
race; `ADVERSARY_NODE_PATH`, `PATH`, and conventional runtime directories must
therefore be controlled by the invoking user and not be writable by
less-trusted principals.

`ADVERSARY_DATA_DIR` overrides only persistent artifact data. Configuration,
cache, and temporary files use the operating system's config, cache, and temp
locations. Defaults are:

| Platform | Data | Config/cache/temp |
| --- | --- | --- |
| Linux | `$XDG_DATA_HOME/adversary` or `~/.local/share/adversary` | Go OS/XDG directories and `os.TempDir()` |
| macOS | `~/Library/Application Support/Adversary` | macOS OS directories and `os.TempDir()` |
| Windows | `%LOCALAPPDATA%\Adversary` | Windows OS directories and `os.TempDir()` |

Host shell discovery uses `sh` on Unix and `cmd.exe` on Windows. Unix process
cancellation supervises the process group. Bare process commands, the host
shell, Git, and the browser launcher use the same captured-`PATH` canonical
target policy and every spawned process receives the captured environment.
Explicit executable paths retain the stricter no-symlink policy. Windows
currently kills the direct child only;
adversaries must not detach descendants. Network, filesystem, and environment
sandbox policies remain explicit unsupported errors for host execution rather
than silently weakened promises.

Executable mode bits from artifacts remain preserved by the repository
materializer. On Windows, executable overrides use `PATHEXT` semantics because
POSIX execute bits do not exist.

## Rollback

When the new OS config file does not exist, credentials remain readable from
legacy `~/.adversary/config.json`; the next credential write uses the new
location and leaves the source intact. Reverting the CLI-018 PR restores the former directory and
prefix-version behavior. Before rollback, copy newer credentials from the OS
config directory to the legacy location if required. Persistent artifact data
is not migrated or deleted by this change; an explicit `ADVERSARY_DATA_DIR` can
point either version at the same repository.
