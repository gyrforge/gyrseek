# Behavior Reference

Details worth knowing once you're past the basics.

**Execution & caching**

- `gyrseek` forwards your command in the current working directory.
- Repeated package-version probes within the same CLI execution are cached in-memory and reused.
- Docker mode batches probe matrices (multiple packages × versions) into a single container run when possible.

**Version handling**

- Version selection is semantic-version aware: npm uses semver, Python (pip/uv/poetry) uses PEP 440. Unparseable version strings sort below any parseable version, so malformed entries are never chosen as `latest`.
- After a clean scan of an unpinned (`latest`) **explicit install target**, the forwarded command is rewritten to pin the exact version that was examined, so the host installs the same version `gyrseek` scanned. Lockfile-driven flows (`uv sync`, `poetry install`, etc.) already carry pinned versions and are forwarded verbatim.
- If baseline versions are unavailable, output may show `baseline-1=n/a` and `baseline-2=n/a`.

## Scanning a whole lockfile

A lockfile scan probes **every registry package the lockfile pins**, not just your direct dependencies, and each one is
compared against `baseline_count` earlier versions. The work therefore scales with the resolved tree, which is usually
far larger than the dependency list you wrote. Measured on a project declaring three dependencies (`express`, `axios`,
`lodash`):

| | |
|---|---|
| Direct dependencies declared | 3 |
| Packages in `package-lock.json` | 84 |
| Probes at `baseline_count: 2` | 252 |
| Probe containers (32 probes each) | 8 |

Published surveys put a typical npm project in the hundreds of resolved packages, with large trees past 700, so a real
application is commonly 1,500–2,400 probes across 50–75 containers. Containers run one after another, not in parallel.

**Expect the first scan of a lockfile to stop early.** Registry metadata is fetched per package before any container
starts, and a package with fewer than `baseline_count` published versions fails the run closed with
`insufficient_baselines`. Small, stable transitive dependencies routinely have only one or two releases: in the 84-package
tree above, **8 of the 81 packages reached** hit this — `dunder-proto`, `es-define-property`, `get-proto`,
`math-intrinsics`, `side-channel-list`, `side-channel-map`, `unpipe` and `utils-merge`. That is by design rather than a
defect: too little history means there is nothing to compare against, which is the same position as a brand-new package,
and gyrseek will not vouch for one. Vet each and add it to `new_package_exemptions` with the version you vetted. Because
the failure happens in the metadata phase, each iteration is fast but you will discover them one at a time.

**Use a prebuilt scanner image for lockfile scans.** On the default path every container runs `apt-get update` and
`apt-get install strace` before its probes. That is tolerable once and wasteful fifty times over; see
[Prebuilt Scanner Images](SANDBOX.md#prebuilt-scanner-images).

**The trace tmpfs is not a scale constraint.** Each probe's files are streamed out and deleted before the next probe
runs, so peak use is one probe's worth whether you scan one package or five hundred.

**Per-command scanning scope**

- `uv sync` scans all packages found in `uv.lock` before forwarding.
- `uv sync`, `uv lock` (bare), and `uv lock --upgrade` exclude local project entries (editable/path/workspace blocks) from comparison.
- `uv pip sync` scans all parseable packages from its source files (requirements-style files and `pylock.toml`).
- `uv lock` (bare) and `uv lock --upgrade` scan all packages in `uv.lock`; both fail closed if `uv.lock` is missing or empty. `uv lock -P/--upgrade-package` scans the explicitly targeted packages. When `-P` is followed by a flag (e.g. `-P --dry-run`), the flag is not consumed as a package name and the next real `-P pkg` argument is not silently skipped.
- `pip install` / `pip3 install` scan all parseable entries, including `-r/--requirements` files.
- `poetry install`, `poetry update`, and `poetry lock` scan all packages in `poetry.lock`, excluding local directory/path/editable source blocks. `poetry lock` fails closed if `poetry.lock` is missing or empty.
- **npm and pnpm scan the versions that are installed.** With packages named (`npm install lodash@4.17.21`, `pnpm add react`) each may be an exact version, a bare name, `@latest` or a range (scanned at the latest version, as described above); a dist-tag (`@next`) or an alias is refused with exit 1. With nothing named, `npm install`, `npm i`, `npm ci`, `pnpm install` and `pnpm i` scan every registry package in the lockfile (`npm-shrinkwrap.json` or `package-lock.json`, `pnpm-lock.yaml`), because that is what is installed. `package.json` is not used: its dependencies are ranges. With no lockfile they fail closed; create one without installing anything via `npm install --package-lock-only` or `pnpm install --lockfile-only`, which `gyrseek` forwards without a scan. `npm update` / `pnpm update` with no packages choose new versions when they run, so they fail closed too: run them with `--package-lock-only` / `--lockfile-only`, then install from the new lockfile. Non-registry specs (`file:`, `workspace:`, `git+`, URL, `link:`) are excluded.
- **An install is refused when a setting redirects it to another registry.** Because the sandbox probes the public package, `--index-url`/`--extra-index-url`/`--find-links` (also inside `-r` requirements files), `--registry`, `PIP_*`/`UV_*`/`npm_config_*` variables, `pip.conf`, `uv.toml`/`[tool.uv]`, `[[tool.poetry.source]]` and `.npmrc` that name a host other than the public registry or one in `trusted_index_hosts` exit 1 before anything is scanned, naming the setting and the host (never credentials). Local paths and `file:` URLs are your own files and are left alone, and commands that are not scanned (`uv venv`) are not checked. Not detected yet: see open finding #450.
- **A lockfile install is refused when its hashes are not the public registry's.** Before the scan, every package a lockfile pins (npm, pnpm, `uv.lock`, `poetry.lock`, `pylock.toml`) is compared with the hashes the public registry publishes for that version: a locked hash the registry does not publish, an entry with no hash, a registry that cannot be reached, or a Python lock that pins only the source distribution while wheels exist (the install would build it, the scan did not) exits 1, so a mirror cannot serve other files for a locked version. Requirements files are compared the same way through their `--hash` options (a line without one is refused only when `trusted_index_hosts` is set). Packages in `internal_package_exemptions` are skipped. Not covered: packages named on the command line through a mirror (#481) and the wheels of other platforms (#482).
- **npm, pnpm and `uv sync` lockfile installs install exactly what was scanned.** A no-argument `npm install`/`npm i` is forwarded as `npm ci` (which refuses a lockfile that disagrees with `package.json`; if both `npm-shrinkwrap.json` and `package-lock.json` exist, every entry of both is scanned, because npm 11 prefers the shrinkwrap and npm 12 ignores it, so with npm 12 rename or delete the old shrinkwrap) and `pnpm install`/`pnpm i` gets `--frozen-lockfile`; flags that turn the lockfile off (`--no-package-lock`, `--no-frozen-lockfile`, `--lockfile=false`, …) exit 1 before anything is scanned. `uv sync` is forwarded as `uv sync --locked` (uv fails instead of re-locking; `--upgrade`/`--upgrade-package` exit 1, `--frozen` is kept); `poetry install` refuses a stale lockfile on its own and is forwarded as typed. For every manager, lockfile entries that do not come from `registry.npmjs.org` (npm/pnpm) or PyPI (`uv.lock`, `poetry.lock`): another host or index, git, ssh, a tarball URL, exit 1 and are named (credentials and query strings in a URL are never printed), unless the package is in `internal_package_exemptions`; `file:` and relative paths are your own code and are left out. Every file gyrseek reads to decide what to scan (requirements files, lockfiles) is checked again before forwarding, and if one changed during the scan the command exits 1 and must be run again.
- `uv venv` and other unrecognized `uv` subcommands are forwarded verbatim (unscanned passthrough).

**Fail-closed guarantees**

- **Unrecognized manager:** any first argument other than `pip`, `pip3`, `uv`, `poetry`, `npm`, or `pnpm` is rejected with a non-zero exit and a clear error message listing the supported managers. Previously, unrecognized managers were silently forwarded unscanned.
- For supported install/sync paths, package-detection failures are fail-closed (non-zero exit) instead of passthrough.
- If the host command itself cannot be launched after a clean scan, `gyrseek` also fails closed.
- A package whose **import step** (loading the installed package) runs longer than `import_timeout_seconds` (default 300) is blocked as `import_failed`. See the import-time scan above for how a failed load is judged.
- A probe that runs longer than `probe_timeout_seconds` (default 300) is stopped and **that package is blocked**; the rest of the batch is still scanned. Slow but legitimate source builds (for example numpy or pandas in an image with a compiler) can hit it: the message names the package and the setting, and the fix is to raise `probe_timeout_seconds` in `gyrseek.yaml`.
- Inside a `-r` requirements file every line must be pinned (`name==1.2.3`): `gyrseek` cannot pin lines in a file, so a bare name there would be resolved again at install time. `npm install --package-lock-only false` is an ordinary install and is scanned; a real `--package-lock-only` / `--lockfile-only` command is forwarded with `--ignore-scripts` because npm still runs the project's `prepare` script in that mode.
- **Version ranges on the command line are scanned at the latest version.** `uv add 'pytest>=9'`, `pip install 'requests~=2.31'`, `poetry add requests@^2` and `npm install lodash@^4` scan the latest version of the package, check that it satisfies the range you wrote, and install that exact version (the range is replaced by the version that was scanned, and `gyrseek` prints a line saying so). If the latest version is outside your range (`npm install lodash@^3` when 4.x is out), `gyrseek` exits 1: it only scans the latest version, so it cannot vouch for what the range would install. Write the exact version, or widen the range. Direct references (`name @ https://…`) and dist-tags (`@next`) exit 1. For a whole project use `uv sync`, `uv lock` or `poetry install`, which are scanned from the lockfile.
- `pip`, `uv pip install`, `uv add` and `poetry add` scan **every** package named on the command line, including those in `-r` requirements files. `-r` includes inside a requirements file are followed. `-r pyproject.toml` (or any other non-requirements file) and an unreadable `-r` file, at any depth, fail closed: use `uv sync`/`uv lock`, or a requirements file with pinned versions.
- If a package's **install fails inside the sandbox** (the candidate or any baseline version), `gyrseek` blocks it with `install_failed`. The message names the failed versions and exit codes and prints the package manager's own error. This is not a `gyrseek` error: fix the install (a dependency that does not resolve, a build that fails) and run `gyrseek` again. The sandbox is a locked-down Linux container, so a package that must be built from source can fail there even though it installs on your machine; point `GYRSEEK_PY_SCANNER_IMAGE` or `GYRSEEK_NPM_SCANNER_IMAGE` at an image that matches your project.
- A sandbox probe that produces an **empty/whitespace trace** (e.g. `strace` could not attach) is a hard error: every package in that batch is blocked. Blank traces are never interpreted as clean.
- **Post-install artifact findings** — binary executables, suspicious `.pth` files, unexpected runtimes, and large files — are diffed across versions. A finding newly present in the current version (absent from all baselines) fails closed (see [Post-Install Artifact Detection](DETECTION.md#post-install-artifact-behavior-detection)).
- When a forwarded command exits non-zero, `gyrseek` **exits with the same code** rather than masking the failure as success.
