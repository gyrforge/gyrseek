# Configuration


`gyrseek` reads a YAML policy file to allowlist known-good endpoints and tune its release gates.

## CLI Arguments

Gyrseek supports the following global CLI arguments. `--version` must be the first argument and `--config`/`-c` must come before the package manager command (e.g., `gyrseek --config=./my.yaml npm install`). `--no-sandbox`, `--no-import-scan` and `--danger-disable-seccomp` are accepted anywhere and are never forwarded to the package manager.

| Argument | Description |
|---|---|
| `--version`, `-V` | Prints the current Gyrseek version and exits. |
| `--config`, `-c` | Path to the YAML policy file. Overrides the default `gyrseek.yaml` and `GYRSEEK_CONFIG` environment variable. Example: `--config=./policy.yaml`. |
| `--no-sandbox` | Runs probes directly on the host with **no isolation** (detection only; Linux/WSL2, needs `strace`, and no post-install artifact scan or import-time scan). See [Sandbox Modes](SANDBOX.md#sandbox-modes). |
| `--no-import-scan` | Skips the import-time scan: installed packages are not loaded in the sandbox (equivalent to `import_scan: false`). |
| `--danger-disable-seccomp` | Disables the embedded default-allow seccomp profile during the sandbox phase. This drastically reduces the sandbox's security guarantees and should only be used for debugging. |


**Config path:** defaults to `gyrseek.yaml` in the working directory. Override it with `--config` / `-c` or the `GYRSEEK_CONFIG` environment variable:

```bash
./target/release/gyrseek --config ./security-policy.yaml npm install
./target/release/gyrseek -c ./security-policy.yaml npm install
GYRSEEK_CONFIG=./security-policy.yaml ./target/release/gyrseek npm install
```

## Config keys

| Key                           | Default       | Purpose                                                                                                                                                                                                                                                        |
| ----------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_allowlist`                | empty         | IPs to ignore before anomaly blocking. Supports **global** entries (`- "1.2.3.4"`) and **per-package** entries (`- pkg: ["5.6.7.8"]`) in the same list. Effective set = global ∪ per-package; per-package entries never reduce global protection. Canonicalized (equivalent IPv6 forms match); invalid entries are skipped with a warning. |
| `domain_allowlist`            | empty         | Domains to ignore. Same semantics and syntax: effective set = global ∪ per-package (see `ip_allowlist`). Lowercased, trailing `.` stripped. Subdomains match parents (`cdn.example.com` matches `example.com`). Only **forward-confirmed** PTR hostnames (FCrDNS) are matched, so a spoofed reverse-DNS record cannot bypass the allowlist. |
| `artifact_allowlist`          | empty         | Artifact findings to allow **per package** (map of package name to list of allowed artifacts; exact `type\|path\|details` or prefix `type\|path`). New artifacts not in baselines and not allowlisted fail closed. Example: `binary\|/work/bin/tool`.               |
| `git_clone_allowlist`         | empty         | Git clone targets to allow **per package** when new install-time clone behavior appears (the repository is matched case-insensitively, option values such as paths are case-sensitive). A URL entry covers a plain or `--recursive` clone only; a clone that also uses `--config`/`-c`, `--upload-pack`, `--template` or `--reference` has those options in its signature (`url\|non-recursive\|config:k=v`) and needs that full signature listed.                                                                                                                                                    |
| `sensitive_file_access_allowlist` | empty         | Sensitive file reads to ignore **per package** (map of package name to list of allowed paths). A leading `*` matches a read whose path equals, or ends in `/`, the text after the `*`. E.g. `*.env` matches a read of `.env` or `/work/.env`, not `foo.env`. |
| `baseline_overrides`          | none          | Pin baseline versions **per package** via `baseline-1` / `baseline-2`. Missing keys fall back to registry-derived baselines.                                                                                                                                       |
| `baseline_count`              | `2`           | How many historical baselines to compare against.                                                                                                                                                                                                              |
| `min_baseline_age_hours`      | `72`          | **Per-package** minimum age (hours) before a version is eligible as a baseline. Packages not listed use the default. Values below 24h are clamped to the 24h security floor (with a warning).                                       |
| `new_package_exemptions`      | none          | Map of package names to their specifically vetted version (e.g. `requests: "1.0.0"`). Exempts the pinned version when fewer than 2 eligible baselines exist. Helps prevent exemption-list rot since newer versions naturally ignore the pinned exemption. |
| `internal_package_exemptions` | none          | Skip specific packages **entirely** — no registry history fetch, no sandbox install, no diff. For first-party / internal packages served from a private index (e.g. Nexus) that `gyrseek`'s public-registry lookups can't resolve, so scanning only yields noise. The package is forwarded unscanned at its requested version.            |
| `trusted_index_hosts`         | none          | Hosts, besides the public registry (`pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`), that a package-manager index or registry setting may point at: `--index-url`, `--extra-index-url`, `--find-links`, `--registry`, `PIP_INDEX_URL`, `UV_INDEX_URL`, `npm_config_registry`, a requirements file's `--index-url`, `pip.conf`, `uv.toml` / `[tool.uv]`, `[[tool.poetry.source]]` or `.npmrc`. `gyrseek` scans the public package of the same name and version, so an install redirected to any other host exits 1 (dependency confusion) unless the host is listed here. List only a mirror of the public registry that you trust (Nexus, Artifactory); for a locked install the lockfile hashes must still be the public registry's, so the mirror cannot serve other files (a package named on the command line is not hash-checked, open finding #481); a package that exists only on a private index also needs `internal_package_exemptions`. Entries are bare host names, matched exactly (no wildcards, no suffixes; a short intranet name such as `nexus` is fine). A scoped registry (`@corp:registry=…` in `.npmrc`) counts for the whole command, not only for packages of that scope, and `pip --isolated` does not switch the check off. |
| `minimum_release_age_package` | off           | Minimum release age in **days**. When set, runs before burst/anomaly checks and fails closed if the current release is younger.                                                                                                                                |
| `release_burst_threshold`     | off           | Fails closed if a package published at least this many versions within the burst window.                                                                                                                                                                       |
| `python_version`              | auto          | Python minor version for the Python sandbox (`"3.11"`; supported: 3.10–3.14). Wins over project files. An unsupported value is a config error. |
| `node_version`                | auto          | Node major version for the npm/pnpm sandbox (`"22"`; supported: 20, 22, 24, 26). Wins over project files. An unsupported value is a config error. |
| `probe_timeout_seconds`       | `300`         | Wall-clock limit (seconds) for each install probe. A probe that exceeds it blocks that package (fail closed); the rest of the batch is still scanned. `0` falls back to `300`. Raise it for slow native builds. |
| `import_scan`                 | `true`        | Load each installed package in the sandbox after its install and compare what that does (see the import-time scan above). `false` turns it off, like `--no-import-scan`. |
| `import_timeout_seconds`      | `300`         | Wall-clock limit (seconds) for loading one package. A load that exceeds it blocks the package as `import_failed`. `0` falls back to `300`. |
| `import_*_allowlist`          | empty         | `import_ip_allowlist`, `import_domain_allowlist`, `import_git_clone_allowlist`, `import_process_exec_allowlist`, `import_artifact_allowlist`, `import_sensitive_file_access_allowlist`: the same formats and validation as the install-time keys, applied only to behaviour at import time. |
| `trace_limit`                 | `1024m`       | Size of the root-only tmpfs that holds one install probe's trace (the largest trace accepted for a probe); a probe that fills it is blocked on its own. A size such as `512m`, `2g` or `65536k`. The `GYRSEEK_TRACE_LIMIT` environment variable overrides it. The tmpfs counts against the container memory limit (`GYRSEEK_MEM_LIMIT`, default `2g`), so keep the two in proportion. |
| `release_burst_window_hours`  | `24`          | Lookback window (hours) for the burst checker.                                                                                                                                                                                                                 |
| `process_exec_allowlist`      | empty         | Process-execution signatures (`bun\|run\|build`) or bare executables (`bun`) that are allowed **per package** even when newly introduced. All executables are monitored by default; only signatures in this list escape the fail-closed diff. Sandbox harness commands are always excluded. |

## Example config

```yaml
ip_allowlist:
  - 151.101.0.223        # global — applies to all packages
  - 151.101.64.223
  - my-private-pkg:      # per-package — only applies to my-private-pkg
    - 10.0.0.1
domain_allowlist:
  - pypi.org             # global
  - files.pythonhosted.org
  - boto3:               # per-package — only applies to boto3
    - s3.amazonaws.com
git_clone_allowlist:
  evil-pkg:
    - https://github.com/acme/repo.git

process_exec_allowlist:
  buildy:
    - bun|run|build
    - deno

artifact_allowlist:
  aws-sdk:
    - binary|/work/bin/aws-helper
    - suspicious_pth|/work/site-packages/aws.pth

sensitive_file_access_allowlist:
  my-database-tool:
    - "*.env"
  my-aws-tool:
    - "*.aws/credentials"
baseline_overrides:
  requests:
    baseline-1: "2.30.0"
    baseline-2: "2.29.0"
  lodash:
    baseline-1: "4.17.20"
baseline_count: 2
min_baseline_age_hours:
  requests: 72
  lodash: 96
new_package_exemptions:
  newly-published-package: "1.0.0"
internal_package_exemptions:
  - internal-pkg-logger          # first-party package served from a private Nexus index
trusted_index_hosts:
  - nexus.corp.example           # a mirror of the public registry that this machine's pip.conf / .npmrc points at
minimum_release_age_package: 3
release_burst_threshold: 3
release_burst_window_hours: 24
probe_timeout_seconds: 300
import_timeout_seconds: 300   # optional; import_scan: false (or --no-import-scan) skips loading packages
import_process_exec_allowlist:
  some-package: ["ldconfig|-p"]   # allowed when the package is loaded, not when it is installed
trace_limit: 1024m             # optional; GYRSEEK_TRACE_LIMIT overrides
python_version: "3.12"        # optional; otherwise .python-version / pyproject.toml, then 3.13
node_version: "22"            # optional; otherwise .nvmrc / .node-version / engines.node, then 26
```

## Config loading behavior

- If `gyrseek.yaml` is **missing**, `gyrseek` runs with an empty allowlist.
- If a **custom** config path is provided and can't be read, `gyrseek` **fails closed**.
