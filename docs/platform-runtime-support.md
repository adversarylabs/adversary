# Platform and runtime support (CLI-018)

This document is the repository decision record for CLI-018.

## Supported contract

The CLI builds and is tested on Linux, macOS, and Windows. Artifact manifests,
not the presence of `package.json` or `dist/`, select the runtime. The supported
named host runtimes are `node` and `process`; image runtimes may be stored but
the local `run` command does not execute containers.

Node is user-managed. The CLI does not download, install, or update Node and no
longer advertises a managed-runtime store. It resolves `ADVERSARY_NODE_PATH`, a
`node` on `PATH`, then conventional nvm, Volta, and asdf locations. Every
candidate is a regular executable, must answer `--version`, and must satisfy the
manifest's semantic-version requirement. Bare `22` means `>=22.0.0, <23.0.0`;
normal semver constraints are also accepted.

Runtime discovery is a cooperative same-user trust boundary, not a stable-file
identity guarantee. The CLI rejects candidates when the executable or any
pathname component is a symlink, then validates the regular file, executable
semantics, and `--version` response. It later starts that same pathname. A user
who can replace path components between validation, probing, and execution can
still win a pathname TOCTOU race; `ADVERSARY_NODE_PATH`, `PATH`, and conventional
runtime directories must therefore be controlled by the invoking user and not
be writable by less-trusted principals.

`ADVERSARY_DATA_DIR` overrides only persistent artifact data. Configuration,
cache, and temporary files use the operating system's config, cache, and temp
locations. Defaults are:

| Platform | Data | Config/cache/temp |
| --- | --- | --- |
| Linux | `$XDG_DATA_HOME/adversary` or `~/.local/share/adversary` | Go OS/XDG directories and `os.TempDir()` |
| macOS | `~/Library/Application Support/Adversary` | macOS OS directories and `os.TempDir()` |
| Windows | `%LOCALAPPDATA%\Adversary` | Windows OS directories and `os.TempDir()` |

Host shell discovery uses `sh` on Unix and `cmd.exe` on Windows. Unix process
cancellation supervises the process group. Windows currently kills the direct
child only; adversaries must not detach descendants. Network, filesystem, and
environment sandbox policies remain explicit unsupported errors for host
execution rather than silently weakened promises.

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
