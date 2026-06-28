# Won't Fix Findings (Detailed)

*This document contains the detailed rationale for findings marked Won't Fix. For the brief overview, see [WONT_FIX_FINDINGS.md](./WONT_FIX_FINDINGS.md).*

# Won't Fix Findings

This document tracks findings that were raised by static analysis, AI reviews, or manual inspection, but have been explicitly marked as "Won't Fix" along with extensive rationale.

## Summary

| #   | File                       | Tag / Type       | What                                                                                     | Status       |
|-----|----------------------------|------------------|------------------------------------------------------------------------------------------|--------------|
| 190  | `lib.rs`                   | `shrink`         | 31-line manual arg-loop for `--config`/`-c`.                                             | 🚫 Won't Fix |
| 191  | `lib.rs`                   | `yagni`          | `NoopRunner` struct with full trait impl for test bypass.                                | 🚫 Won't Fix |
| 192  | `lib.rs`                   | `shrink`         | `ScanTimer` struct with `Instant`, `Drop`, two print branches.                           | 🚫 Won't Fix |
| 193  | `lib.rs`                   | `yagni`          | `scan_targets` is a 1-line delegate to `scan_many_with_cache`.                           | 🚫 Won't Fix |
| 194 | `parsing.rs`               | `shrink`         | `parse_poetry_lock_packages_from_content` has 7-param closure.                           | 🚫 Won't Fix |
| 195 | `sandbox.rs`               | `shrink`         | `scanner_user_setup_steps` returns `vec!["..."]`, called once.                           | 🚫 Won't Fix |
| 196 | `sandbox.rs`               | `shrink`         | `image_setup_steps` 4× `steps.push(...)` with `format!`.                                 | 🚫 Won't Fix |
| 197 | `scanning.rs`              | `false-positive` | Host-mode `uv pip install` leaks into exec signatures.                                   | 🚫 Won't Fix |
| 198 | `.github/workflows/ci.yml` | `false-positive` | `actions/checkout@v7` does not exist.                                                    | 🚫 Won't Fix |
| 199 | `scanning.rs`              | `false-positive` | `/.azure/` test exists but no `/.gnupg/` test.                                           | 🚫 Won't Fix |
| 200 | `README.md`                | `false-positive` | Exfiltration "caught at the network boundary" docs claim overstates completeness.        | 🚫 Won't Fix |
| 201 | `AGENTS.md`                | `false-positive` | Graphify skill referenced but skill file does not exist.                 | 🚫 Won't Fix |
| 202 | `docs/common_prompts.md` | `false-positive` | Raw CI prompt committed into documentation directory. | 🚫 Won't Fix |
| 203 | `sandbox.rs`               | `false-positive` | `process_vm_readv` is permitted in the seccomp profile.                                  | 🚫 Won't Fix |
| 204 | `scanning.rs`              | `false-positive` | Race condition in insufficient_baselines check ordering.                                 | 🚫 Won't Fix |
| 205| `.github/workflows/`       | `false-positive` | Prompt Injection / Runner Compromise exfiltrating deployment secrets.                    | 🚫 Won't Fix |
| 206| `.github/workflows/`       | `false-positive` | Autonomous Agent execution via `--dangerously-skip-permissions`.                         | 🚫 Won't Fix |
| 81 | `.github/scripts/sanitize_review.py` | `low` | Python truncation decodes by byte count and ignores UTF-8 errors. | 🚫 Won't Fix |
| 118 | `.github/workflows/ci.yml` | `low` | Doctest CI tests PR-head sanitizer, not default-branch production script. | 🚫 Won't Fix |
| 123 | `.github/workflows/post_review.yml` | `invalid` | Adding `actions/checkout` without `ref` would hand `GH_TOKEN` to attacker. | 🚫 Won't Fix |
| 124 | `.github/scripts/sanitize_review.py` | `low` | Code-block URL defanging is missing AST backtick-context awareness. | 🚫 Won't Fix |
| 125 | `.github/scripts/post_comment.sh` | `invalid` | `cmark --safe` flag deprecated in cmark ≥0.31. | 🚫 Won't Fix |
| 129 | `.github/scripts/post_comment.sh` | `accepted-risk` | No automated tests for `post_comment.sh`. | 🚫 Won't Fix |
| 207| `.github/workflows/ci.yml` | `accepted-risk`  | `timeout-minutes: 10` with no partial-output trap.                                       | 🚫 Won't Fix |
| 208| `.github/workflows/ci.yml` | `accepted-risk`  | `max-parallel: 3` vector for CI inference budget exhaustion.                             | 🚫 Won't Fix |
| 209| `AGENTS.md`                | `false-positive` | `AGENTS.md` CI description omits operational details (model name, SHA hash).             | 🚫 Won't Fix |
| 210| `.github/workflows/ci.yml` | `false-positive` | Redundant OpenCode installation script in dependent consolidation job.                   | 🚫 Won't Fix |
| 211| `.github/workflows/ci.yml` | `accepted-risk`  | LLM self-censoring via tool access (`--dangerously-skip-permissions`).                   | 🚫 Won't Fix |
| 212| `.github/workflows/ci.yml` | `accepted-risk`  | Findings documents (`OPEN_FINDINGS`, `WONT_FIX`) are not protected from PR tampering.    | 🚫 Won't Fix |
| 213| `.github/workflows/ci.yml` | `accepted-risk`  | `graphify update` parsing vulnerability leading to CI runner RCE.                        | 🚫 Won't Fix |
| 214| `.github/workflows/ci.yml` | `false-positive` | CI job fails if `gyrseek_review.md` or other artifact files are missing.                 | 🚫 Won't Fix |
| 215| `.github/workflows/ci.yml` | `false-positive` | Permissions fragmentation for `checks: write` across jobs.                               | 🚫 Won't Fix |
| 138 | `.github/scripts/sanitize_review.py` | `accepted-risk` | `PARENS_REGEX` depth-1 limit causes cosmetic artifacts on deeply-nested URLs. | 🚫 Won't Fix |
| 151 | `.github/scripts/sanitize_review.py` | `invalid` | `www.` defang is case-sensitive — GFM cmark-gfm is also case-sensitive; `WWW.` does not auto-link. | 🚫 Won't Fix |
| 152 | `.github/scripts/sanitize_review.py` | `accepted-risk` | Autolink `[^>]+` truncates at first literal `>` in URL — RFC-invalid URLs; `cmark --safe` second layer covers it. | 🚫 Won't Fix |
| 161 | `.github/scripts/sanitize_review.py` | `invalid`       | `@mention` defang regex fails on second `@` in malformed string like `@evil@user`. | 🚫 Won't Fix |
| 216| `.github/workflows/`       | `accepted-risk`  | Third-party actions use moving tags instead of being SHA-pinned.                         | 🚫 Won't Fix |
| 217| `.github/workflows/ci.yml` | `false-positive` | Truncated consolidation prompt is undetected due to lack of file size verification.      | 🚫 Won't Fix |
| 218| `.github/workflows/ci.yml` | `false-positive` | "Enhanced Only" template has no section for purely-new findings.                         | 🚫 Won't Fix |
| 219| `.github/workflows/ci.yml` | `false-positive` | No integrity verification (SHA-256) of multi-agent review outputs.                       | 🚫 Won't Fix |
| 220| `.github/workflows/ci.yml` | `accepted-risk`  | Per-reviewer skill injection removed, relying on autonomous discovery.                   | 🚫 Won't Fix |
| 221| `.github/workflows/ci.yml` | `false-positive` | Duplicated "checkout trusted policies" bash loop violates DRY.                           | 🚫 Won't Fix |
| 222| `.github/workflows/ci.yml` | `false-positive` | `consolidate-reviews` lacks explicit `success()` gate.                                   | 🚫 Won't Fix |
| 223| `.github/workflows/ci.yml` | `false-positive` | No SHA hash pin on `graphify` dependency. Duplicate of 179.                             | 🚫 Won't Fix |
| 224| `.github/workflows/ci.yml` | `false-positive` | `git fetch` race conditions across concurrent matrix pods.                               | 🚫 Won't Fix |
| 225| `.github/workflows/ci.yml` | `false-positive` | `rm -rf graphify-out` flagged as unnecessary noise.                                      | 🚫 Won't Fix |
| 226| `.github/workflows/ci.yml` | `false-positive` | `graphify-out/` architecture context flagged as generated but never consumed.            | 🚫 Won't Fix |
| 227| `.github/workflows/ci.yml` | `false-positive` | Latent coupling warning between cache key and temp script path.                          | 🚫 Won't Fix |
| 179 | `.github/workflows/post_review.yml` + `.github/scripts/post_comment.sh` | `accepted-risk` | `workflow_run.pull_requests[0].number` does not exist; commit-based PR resolution returns first ambiguous match. | 🚫 Won't Fix |


*For detailed reasoning, see [WONT_FIX_FINDINGS_DETAILED.md](./WONT_FIX_FINDINGS_DETAILED.md).*


---

## Detailed Rationale

# Won't Fix Findings - Detailed

---

### Finding 190 — `shrink` | `lib.rs:64-95` | 🚫 Won't Fix

**Summary:** 31-line manual arg-loop for `--config`/`-c`.

**Suggested Fix:** Compact `while let Some(arg)` with `strip_prefix` + `ok_or_else` → 20 lines.

**Reason for Not Fixing:** The manual loop is highly readable. Refactoring to an iterator chain reduces line count but increases cognitive overhead (unnecessary churn). The current structure allows for straightforward addition of new flags without disrupting nested map chains.

---

### Finding 191 — `yagni` | `lib.rs:572-583` | 🚫 Won't Fix

**Summary:** `NoopRunner` struct with full trait impl for test bypass.

**Suggested Fix:** Rust requires a concrete type for trait impl; closure can't substitute.

**Reason for Not Fixing:** As stated, Rust requires a concrete type for trait implementation. Replacing it with a closure is not natively supported without boxing overhead. The `NoopRunner` struct is a clean, dependency-free way to mock out the sandbox in tests.

---

### Finding 192 — `shrink` | `lib.rs:701-717` | 🚫 Won't Fix

**Summary:** `ScanTimer` struct with `Instant`, `Drop`, two print branches.

**Suggested Fix:** Inlined approach introduced maintenance footgun. RAII Drop is the correct, lazy choice for scoped cleanup.

**Reason for Not Fixing:** The RAII Drop pattern ensures the timer is always printed on scope exit, preventing missed prints on early returns. Inlining it introduces a maintenance footgun.

---

### Finding 193 — `yagni` | `lib.rs:802-810` | 🚫 Won't Fix

**Summary:** `scan_targets` is a 1-line delegate to `scan_many_with_cache`.

**Suggested Fix:** Inlined at 5 call sites.

**Reason for Not Fixing:** Inlining a 1-line delegate at 5 call sites causes duplication and breaks the single source of truth for the scan delegation path. Keeping the delegate provides a central point if future logic (like logging or metrics) needs to be added before caching.

---

### Finding 194 — `shrink` | `parsing.rs:79-239` | 🚫 Won't Fix

**Summary:** `parse_poetry_lock_packages_from_content` has 7-param closure.

**Suggested Fix:** `Pkg` struct with `finalize()` method eliminates 7-param closure; `fn` replaces closure.

**Reason for Not Fixing:** Moving from a closure to a full `Pkg` struct with state management adds unnecessary boilerplate. The closure keeps the parsing logic localized and prevents structural bloat for what is ultimately a single sequential parsing pass.

---

### Finding 195 — `shrink` | `sandbox.rs:462-477` | 🚫 Won't Fix

**Summary:** `scanner_user_setup_steps` returns `vec!["..."]`, called once.

**Suggested Fix:** Inlined at both call sites.

**Reason for Not Fixing:** Keeping setup steps in a dedicated function improves readability and modularity, preventing the parent caller from becoming bloated. It visually segments the "what to run" from the "how to run it".

---

### Finding 196 — `shrink` | `sandbox.rs:517-538` | 🚫 Won't Fix

**Summary:** `image_setup_steps` 4× `steps.push(...)` with `format!`.

**Suggested Fix:** `match manager` replaces if/else if; inlined at both call sites.

**Reason for Not Fixing:** Similar to 195, keeping the step creation encapsulated makes the main runner pipeline much easier to read. `match` statements vs `if/else` here is a stylistic choice that isn't worth the code churn.

---

### Finding 197 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** Host-mode `uv pip install` leaks into exec signatures.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. `sandbox.rs:254-259` shows that `--target` and `target_path` are correctly included in the host runner args. Furthermore, `is_harness_command` accurately matches via `--target`. The reported leak cannot happen under the current code execution flow.

---

### Finding 198 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `actions/checkout@v7` does not exist.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. `actions/checkout` has indeed published `v7` on GitHub. The static analysis or reviewer's local cache was likely outdated, leading to the assumption that `v4` was the maximum major tag.

---

### Finding 199 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** `/.azure/` test exists but no `/.gnupg/` test.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. Both `.azure` and `.gnupg` are tested. Specifically, `scanning.rs:2193-2195` clearly covers the `.gnupg` test case. The reviewer missed these lines.

---

### Finding 200 — `false-positive` | `README.md` | 🚫 Won't Fix

**Summary:** Exfiltration "caught at the network boundary" docs claim overstates completeness.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive based on semantic interpretation. This is a threat modeling caveat rather than a direct code defect. The docs correctly state the theoretical coverage, but bypasses are acknowledged architectural risks. We will not change the docs because they accurately reflect the feature intent, not an infallible guarantee. Additionally, the Threat Model review clarifies that DNS tunneling exfiltration is invisible not just because DNS queries go to a sandbox-local resolver, but because `extract_dns_map` parses DNS *responses*, not queries. An attacker encoding secrets in DNS query names to a domain they control exfiltrates data without ever calling `connect()` to a new IP. Finally, there is an endpoint baseline poisoning angle: an attacker could seed their C2 domain in the baseline via benign telemetry in v1.0.0. Both are fundamental behavioral-diffing limitations that are explicitly accepted as out-of-scope.



### Finding 201 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** Graphify skill referenced but skill file does not exist.

**Suggested Fix:** Either install the missing skill file or remove the reference from `AGENTS.md`.

**Reason for Not Fixing:** This is a false positive. Graphify is not an agent skill, but a Python package tool that is invoked directly via the CLI (`graphify update .`). The reference in `AGENTS.md` is correct in instructing the agent to invoke the tool, but the static analysis misunderstood it as a missing `.agents/skills` folder entry.


### Finding 202 — `false-positive` | `docs/common_prompts.md` | 🚫 Won't Fix

**Summary:** Raw CI prompt committed into documentation directory.

**Suggested Fix:** Remove the file or move it to a dedicated internal/`.github` directory with proper context headers.

**Reason for Not Fixing:** The file is intentionally kept in the documentation directory for the developer's own reference during CI pipeline adjustments. It is not considered a defect.

### Finding 203 — `false-positive` (Not blocking `process_vm_readv`) | `sandbox.rs` | 🚫 Won't Fix

**Summary:** `process_vm_readv` is permitted in the seccomp profile, allowing a process to read memory from its siblings.

**Suggested Fix:** Block `process_vm_readv` in the default-allow seccomp profile.

**Reason for Not Fixing:** This is a won't fix because `strace` intrinsically requires `process_vm_readv` to function. `strace` relies on this syscall to read strings and data structures (like arguments to `execve` or file paths in `open`) from the target process's memory space. Blocking it would render `strace` unable to capture the rich behavioral telemetry that Gyrseek relies on for its anomaly detection. 

Furthermore, a malicious process can only use `process_vm_readv` for *read-only* access to sibling memory. To actively corrupt logs or interfere with sibling execution, an attacker would need `process_vm_writev`. Because we have explicitly blocked `process_vm_writev`, the memory corruption vector is neutralized. The read-only access does not pose a threat to the integrity of the trace logs, making `process_vm_readv` safe to leave permitted.

---

### Finding 204 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** Race condition in insufficient_baselines check ordering.

**Suggested Fix:** Move the baseline-count check after the self-reference override check.

**Reason for Not Fixing:** This is a false positive. While the count check (`baselines.len() < policy.baseline_count` at line 1753) occurs textually before the override logic block (line 1772), `select_effective_baselines` (called prior to this flow) already explicitly filters out `v_curr` from the baselines. Thus, the count at line 1753 correctly reflects the effective baselines, excluding any self-referencing overrides. Unit tests (e.g., `override_equal_to_current_is_excluded_from_baselines`) already confirm this behavior.

*Note:* This "Won't Fix" dismissal is scoped strictly to the sequential text ordering concern. The separate issue regarding the async cache race (`scan_with_cache` concurrent cache population) is tracked as a distinct legitimate vulnerability in `OPEN_FINDINGS.md` (Finding 84).

---

### Finding 205 — `false-positive` (Accepted Architectural Risk) | `.github/workflows/` | 🚫 Won't Fix

**Summary:** AI Reviewer prompt injection or runner compromise could lead to secret exfiltration or supply chain attacks.

**Suggested Fix:** Implement strict, hyper-isolated runner environments or avoid AI execution on PRs.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk based on the specific threat model of this repository. We have implemented Job Separation (untrusted AI runs with `contents: read` and passes an artifact to a trusted publisher), which protects the `GITHUB_TOKEN` from being used maliciously by the AI.

However, we explicitly accept the residual risks of runner compromise (e.g., if a malicious code change escapes the AI sandbox) for the following reasons:
1. **No Deployment Secrets:** This is a CLI tool that is not published to `crates.io` or any other external registry via CI. There are technically no long-lived deployment secrets in this repository.
2. **Ephemeral Tokens Only:** The only secret in the environment is the dynamically generated `GITHUB_TOKEN`, which is short-lived and dies immediately after the runner finishes.
3. **Curated Contributors:** We only accept contributions from developers we know and explicitly trust, significantly reducing the likelihood of a targeted, malicious PR.
4. **Managed Infrastructure:** All workflows run on GitHub-hosted runners. A significant portion of the runner-isolation risk is transferred to GitHub's infrastructure.

Because the blast radius is strictly limited to the repository itself during the short window of the CI run, and the risk of a malicious contributor is exceptionally low, further architectural complexity for runner isolation is deemed unnecessary.

---

### Finding 206 — `false-positive` (Accepted Architectural Risk) | `.github/workflows/` | 🚫 Won't Fix

**Summary:** Using `--dangerously-skip-permissions` allows the AI code reviewer to autonomously execute tools (file reads, web searches) without human oversight, creating a vector for prompt injection to weaponize the agent's capabilities.

**Suggested Fix:** Require human approval (interactive mode) for all agent tool executions, or strictly sandbox network and file access.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk required to run an agentic review system headlessly in CI. Without `--dangerously-skip-permissions`, the agent cannot use its tools and would crash or hang when attempting to read the repository context.

We accept the risk of prompt injection weaponizing the autonomous agent because the blast radius is fundamentally constrained by the CI Job Separation architecture:
1. **Read-Only Sandbox:** The agent executes within `ci.yml`, which is strictly locked to `contents: read`. Even if the agent is tricked into using its tools maliciously, it cannot push commits, merge PRs, or modify repository configurations.
2. **Ephemeral Environment:** The runner is destroyed immediately after execution.
3. **No Private Data Exfiltration:** As an open-source project, the source code is public. Even if an attacker tricks the autonomous agent into reading source files and `POST`ing them to an external server via web tools, no confidential intellectual property is lost.
4. **Prompt-Level Directives:** We have explicitly instructed the agent in its system prompt that it is "strictly forbidden from downloading files or executing commands," providing a first layer of defense against generic autonomous abuse.

---

### Finding 207 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `timeout-minutes: 10` with no partial-output trap (ci.yml:134,232). Timeout produces zero output; no trap/signal handler to dump partial results.

**Reason for Not Fixing:** The AI review output is inherently structured markdown; a partial or truncated LLM output stream is generally corrupted and impossible to parse reliably by downstream consolidation logic. Failing cleanly with zero output is preferred over injecting malformed context.

---

### Finding 208 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `max-parallel: 3` on 5-reviewer matrix (ci.yml:62). Up to 30 concurrent minutes of AI inference per run; CI budget exhaustion vector via repeated PRs.

**Reason for Not Fixing:** The matrix strategy is intentionally designed to trade inference budget for parallel speed. Throttling this via concurrency limits or serializing the reviewers would degrade developer experience and increase PR latency. Cost/budget controls should be enforced at the API key limit level, not via workflow throttling.

---

### Finding 209 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** AGENTS.md CI description omits operational details (AGENTS.md:53-54). High-level summary drops model name, install verification SHA, artifact flow. Developers cannot trace CI behavior from AGENTS.md alone.

**Reason for Not Fixing:** `AGENTS.md` is an architectural memory file, not a line-by-line technical specification. Hardcoding volatile operational details (like the OpenCode version SHA or the exact model name) into the documentation creates unnecessary maintenance churn. The single source of truth for execution mechanics is `ci.yml`.

---

### Finding 210 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** Redundant OpenCode installation (ci.yml:207-219). Full `curl | sha256sum | bash` chain re-runs in `post-review-comments` job despite same cache key as `code-review` job.

**Reason for Not Fixing:** The static analysis tool incorrectly flags this block because it fails to account for GitHub Actions caching logic. The installation script is wrapped in an `if: steps.cache-opencode.outputs.cache-hit != 'true'` conditional. Because the consolidation job strictly depends on (`needs:`) the review job, the cache is guaranteed to be populated. The installation script is skipped at runtime, making this a true false positive.

---

### Finding 211 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** LLM self-censoring via tool access (ci.yml). With `--dangerously-skip-permissions`, the agent has file-write capabilities. Under prompt injection from malicious PR code, the agent could be instructed to read its own in-progress output file or review ledger, and modify or delete findings before they are written back. This is distinct from exfiltration (206); this is purely self-censoring of security reviews.

**Suggested Fix:** Restrict the agent's tool access to read-only tools, or remove `--dangerously-skip-permissions` and rely purely on stateless LLM execution.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk. The agent requires tool access to explore the codebase effectively, and it requires write access to generate and consolidate the final markdown artifacts (e.g., `consolidated_gyrseek_review.md`).
We accept this risk because the CI pipeline is a supplementary defense layer. Human review is still required for PRs. If an attacker successfully injects a prompt to censor findings, the output will simply be clean, which degrades gracefully to the baseline level of security (standard human review). Neutering the agent's tool access would cripple its ability to conduct deep, context-aware architectural reviews, which provides more value than the theoretical risk posed by self-censoring.

---

### Finding 212 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `docs/OPEN_FINDINGS.md` and `docs/WONT_FIX_FINDINGS.md` are not protected from tampering during CI. The workflow checks out the PR versions of these files rather than strictly enforcing the base branch versions. 

**Suggested Fix:** Add `docs/OPEN_FINDINGS.md` and `docs/WONT_FIX_FINDINGS.md` to the base-branch checkout loop in `ci.yml`.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk designed to prevent "Context Contradiction" bugs. If we force these files back to their base branch state, the AI reviewer receives contradictory signals when reviewing a PR that legitimately fixes a vulnerability (the diff shows the bug moved to `FIXED_FINDINGS.md`, but the file on disk still says it's `OPEN`). 

We accept the risk of an attacker tampering with `OPEN_FINDINGS.md` to hide a backdoor because the AI reviewer is explicitly given the PR diff. If an attacker maliciously deletes a security policy from the documentation, the AI reviewer (and human reviewers) will see that deletion directly in the code diff and can flag it. The only files that strictly require base-branch enforcement are the immutable system instructions (`AGENTS.md` and `.agents/skills/`).

---

### Finding 213 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `graphify update` executes source-parsing code from the PR branch without container isolation or cryptographic dependency pinning. A crafted source file exploiting a `graphify` parsing bug, or a compromised PyPI release/sub-dependency, could achieve Remote Code Execution (RCE) on the CI runner, allowing an attacker to forge the AI's review output.

**Suggested Fix:** Isolate `graphify` execution to a locked-down Docker container, or pin the dependency via exact commit hash/SHA256 checksums rather than just PyPI version.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk. Exploiting a niche parser vulnerability just to forge an AI review is a highly complex attack vector with very low impact. As an open-source project, the repository is public and the CI workflow executes with strictly read-only permissions (`contents: read`) under our Job Separation architecture. There are no deployment secrets, write-tokens, or private data in the runner environment to exfiltrate. The absolute worst-case scenario is that the attacker successfully forges a "clean" review for their malicious PR, which degrades the security posture to exactly that of a standard human review without AI assistance. Because the impact is negligible, the operational complexity of containerizing or cryptographically pinning the `graphify` execution is not justified.

---

### Finding 214 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The `upload-artifact` step in `ci.yml` uses `if-no-files-found: error`, causing the entire `code-review` job to fail if the AI reviewer does not produce an output file. 

**Suggested Fix:** Change the setting back to `if-no-files-found: ignore` to prevent CI flakiness when the LLM API times out.

**Reason for Not Fixing:** This is an intentional security design. Setting it to `ignore` creates a dangerous "silent failure" where an AI crash or API timeout results in a green CI build with a blank review, tricking developers into thinking the code was successfully audited and found to be safe. We intentionally enforce `if-no-files-found: error` so that if the AI review pipeline fails to generate an output, it fails loudly and blocks the PR. **Do not revert this to `ignore`.**

---

### Finding 215 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** Permissions fragmentation for `checks: write`. The `checks: write` permission is not granted at the top-level of the workflow; it is only granted explicitly to the `cargo-audit` job. This prevents other jobs (like `rust-checks` or `code-review`) from posting inline check annotations.

**Suggested Fix:** Move `checks: write` to the top-level `permissions` block so all jobs inherit the ability to write check annotations.

**Reason for Not Fixing:** This is an intentional implementation of the Principle of Least Privilege and a major security feature, not a bug. If `checks: write` were applied globally, the `code-review` job (which executes untrusted PR code and AI models) would inherit it. An attacker achieving RCE during the review job could use that permission to forge fake "All Checks Passed!" annotations to deceive human reviewers. By intentionally fragmenting permissions and keeping the top-level default to strictly `read-only`, the pipeline successfully limits the blast radius of any potential compromise.

---

### Finding 216 — `accepted-risk` | `.github/workflows/` | 🚫 Won't Fix

**Summary:** Third-party actions use mutable moving tags (e.g., `@v4`) instead of being cryptographically SHA-pinned.

**Suggested Fix:** Pin all third-party actions to specific commit SHAs to prevent supply chain compromise.

**Reason for Not Fixing:** This is an explicitly accepted risk in favor of Developer Experience (DX). Pinning to SHAs makes workflow files significantly harder to read and requires heavy automation (like Dependabot or Renovate) just to keep actions up to date. Furthermore, the actual impact of a compromised third-party action in this repository is very low. The primary CI jobs run with strictly `contents: read` permissions and no secrets. If an attacker gains RCE via a compromised action in `ci.yml`, the absolute worst-case scenario is that they bypass the AI code review (a risk we have already accepted in Finding 213). The operational overhead of managing SHAs heavily outweighs the theoretical risk to the read-only CI pipeline.

---

### Finding 217 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The `prompt.txt` heredoc has no file size or checksum verification before execution, theoretically allowing a silently truncated prompt to drop critical security constraints.

**Suggested Fix:** Add a `test -s prompt.txt && wc -c prompt.txt` guard before running the AI to mathematically verify the prompt was written entirely.

**Reason for Not Fixing:** This is a false positive because it ignores how `bash` handles write failures in GitHub Actions environments. GitHub Actions `run` steps execute with `set -e` by default. If the `cat` command fails to write the full heredoc due to a `disk-full` (ENOSPC) or `OOM` error, the standard POSIX utility returns a non-zero exit code. `set -e` instantly catches this failure and aborts the entire job before the `opencode` execution line can ever be reached. Adding byte-counting logic is brittle (breaking if a single typo in the prompt is fixed) and mathematically unnecessary due to the fail-closed nature of `set -e`.

---

### Finding 218 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The consolidation job's markdown template only has explicit sections for "Enhanced Open Findings" and "Enhanced Won't Fix Findings," supposedly leaving the AI with nowhere to record purely new vulnerabilities.

**Suggested Fix:** Add a specific "New Open Findings" section to the consolidation output template.

**Reason for Not Fixing:** This is a fundamental misunderstanding of the template structure. The top sections of the template (`## High`, `## Medium`, and `## Low`) are specifically designed to capture net-new findings. The "Enhanced" sections at the bottom exist explicitly to filter out duplicates of known issues, keeping the PR clean. If a completely new vulnerability is found, the AI correctly places it directly under the appropriate severity header at the top of the report. The template is logically complete as written.

---

### Finding 219 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The consolidation job downloads review artifacts without cryptographic checksum verification (e.g., SHA-256 sidecars), allegedly allowing cross-run injection or compromised-agent spoofing.

**Suggested Fix:** Generate a SHA-256 sidecar file for each artifact at upload time, and verify the hash before consuming the artifact in the consolidation job.

**Reason for Not Fixing:** This finding recommends "Cryptographic Theater." First, cross-run artifact injection is natively impossible because `actions/download-artifact@v4` strictly isolates storage to the current `github.run_id`. Second, while a compromised agent *could* theoretically spoof an artifact (an accepted risk documented in 179), requiring a SHA-256 sidecar provides zero actual security. If an attacker has RCE to forge the artifact, they can simply forge the accompanying SHA-256 sidecar as well. The downstream consolidation job would successfully verify the forged checksum against the forged artifact, providing a dangerous false sense of security.

---

### Finding 220 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The static Python prompt builder (`build_prompt.py`), which forcefully injected specific `.agents/skills/` file contents directly into the prompt string for each reviewer, was removed. The new bash `cat` heredoc in `ci.yml` relies on the AI to autonomously discover and read the relevant skill files, potentially regressing review depth if the AI fails to fetch them.

**Suggested Fix:** Restore the static skill-file injection logic into the `ci.yml` bash script to mathematically force the skill text into the AI's context window.

**Reason for Not Fixing:** The removal of `build_prompt.py` was an intentional architectural shift to reduce complexity and mitigate local prompt injection vulnerabilities. We explicitly choose to rely on the agent's autonomous tool-use capabilities (`view_file`) to fetch its own context rather than forcing a complex, static pre-processing step. While this introduces a risk of the AI "forgetting" or failing to fetch the skills, the trade-off for a vastly simpler, more secure CI orchestration script is accepted. *(Note: The stale `<skill>` XML references in the prompt files themselves were fixed to explicitly command the AI to use its tools).*

---

### Finding 221 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The bash loop responsible for explicitly checking out trusted `AGENTS.md` and `.agents/skills/` policies from the base branch is duplicated in both the `code-review` and `consolidate-reviews` jobs.

**Suggested Fix:** Extract the duplicated bash logic into a reusable GitHub Action or a centralized shell script (e.g., `.github/scripts/checkout-trusted-policies.sh`) to adhere to DRY (Don't Repeat Yourself) principles.

**Reason for Not Fixing:** (UPDATED) The original reasoning for this finding falsely assumed that `ci.yml` is natively guaranteed to load from the trusted base branch on `pull_request` events. This is **incorrect**; GitHub Actions loads `ci.yml` from the PR's merge commit. Therefore, an attacker can modify inline YAML just as easily as external shell scripts to bypass policy checkouts. However, the repository remains completely secure because `ci.yml` runs with strictly `contents: read` permissions. The actual trusted boundary is `post_review.yml`, which triggers on `workflow_run` (strictly loaded from the base branch) and holds the `GH_TOKEN`. Because of this separation, extracting the orchestration logic into `.github/scripts/generate_review.sh` does not introduce any new vulnerabilities compared to inline YAML. We accept this finding because DRY extraction into `.github/scripts/` is safe and improves maintainability.

---

### Finding 222 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The `consolidate-reviews` job lacks an explicit `if: needs.code-review.result == 'success'` gate, allegedly allowing it to execute and produce a silent "No reviewer outputs" success even if the upstream `code-review` job fails.

**Suggested Fix:** Explicitly add `if: needs.code-review.result == 'success'` to the `consolidate-reviews` job.

**Reason for Not Fixing:** This finding hallucinates non-existent behavior and is factually incorrect regarding the GitHub Actions engine. By default, the `needs:` array implies a strict dependency on success. If the upstream `code-review` job fails or is skipped for any reason, the downstream `consolidate-reviews` job is automatically and instantly skipped by the Actions engine. The only way it would execute on failure is if an explicit `always()` or `failure()` condition were present, which it is not. The suggested fix is entirely redundant.

---

### Finding 223 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** No SHA hash pin on `graphify` dependency.

**Reason for Not Fixing:** This finding is a duplicate of **213**. The scanner isolated the supply-chain poisoning aspect of 179 into its own separate finding, despite 179 already explicitly identifying and accepting the exact same risk ("without cryptographic dependency pinning", "compromised PyPI release") and mitigation strategy.

---

### Finding 224 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The static analysis scanner claims that because multiple code-review matrix pods run `git fetch origin "$BASE_REF"` concurrently, they will cause a race condition and corrupt the Git ref database.

**Reason for Not Fixing:** This is fundamentally incorrect due to a hallucination regarding GitHub Actions architecture. GitHub Actions matrix jobs do not run in containers sharing a single filesystem; they spawn entirely isolated Virtual Machines (`ubuntu-latest`). Because each matrix pod has its own dedicated hard drive and its own local `.git/` database, it is physically impossible for them to collide or corrupt each other's git objects. No fix is required for the race condition (though the `|| true` masking the fetch failure was resolved separately in Finding 97).

---

### Finding 225 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner flagged the `rm -rf graphify-out` pre-generation step as unnecessary noise, incorrectly assuming the directory is entirely git-ignored and therefore impossible to be pre-compromised in a PR checkout.

**Reason for Not Fixing:** The `.gitignore` explicitly whitelists certain outputs (`!graphify-out/GRAPH_REPORT.md`, `!graphify-out/graph.json`). Because these files are tracked, an attacker can submit a PR containing a pre-compromised `GRAPH_REPORT.md` laden with prompt-injection instructions. If the `rm -rf` step is removed, the `graphify update` tool might append to or fail to cleanly overwrite the attacker's file, resulting in the AI consuming the malicious instructions. The `rm -rf` step is a critical defense-in-depth measure to guarantee a clean workspace.

---

### Finding 226 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner flagged the `graphify update .` step as dead output, claiming that because `graphify-out/` or `GRAPH_REPORT.md` are not explicitly listed in the workflow's prompt file references, the AI never consumes the generated architecture context.

**Reason for Not Fixing:** This is a false positive caused by the scanner failing to trace transitive prompt instructions. Both the `code-review` and `consolidate-reviews` jobs explicitly instruct the AI to read `AGENTS.md`. `AGENTS.md` contains an extensive, dedicated section outlining the precise rules and commands for the AI to interact with the `graphify-out/` directory and `GRAPH_REPORT.md`. Because the AI parses `AGENTS.md`, it is fully aware of and capable of consuming the generated architectural context. Explicitly duplicating the graphify references in the workflow YAML prompts is unnecessary boilerplate.

---

### Finding 227 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner noticed that the OpenCode installation script path was changed from `/tmp` to `${{ runner.temp }}` (in Finding 89), but the cache key for the OpenCode binary was not changed, resulting in a latent coupling warning.

**Reason for Not Fixing:** This is completely benign. The cache action targets the final installed binary directory (`~/.opencode`), not the temporary download script location (`${{ runner.temp }}`). Therefore, the cache key (`opencode-${{ env.OPENCODE_VERSION }}-...`) is functionally independent of where the installation script is staged. There are no stale cache misses or collisions possible under the current architecture, rendering the scanner's hypothetical warning unactionable.

---

### Finding 228 — `false-positive` | `docs/FIXED_FINDINGS.md` | 🚫 Won't Fix

**Summary:** The scanner flagged the fix description for Finding 92 as "architecturally incorrect" because it describes sanitizing `graphify-out` artifacts via Python XML-tag replacements before appending to `prompt.txt`. This references a stale architecture, as graphify output is no longer injected into `prompt.txt`.

**Reason for Not Fixing:** `FIXED_FINDINGS.md` is an immutable, point-in-time audit ledger. It correctly describes exactly what the fix was *at the time Finding 92 was resolved*. Rewriting historical audit logs to reflect future architectural changes defeats the purpose of an audit trail.

---

### Finding 229 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner warned that `fetch-err.log` (created during the `git fetch --unshallow` step) is never cleaned up via `rm -f`, meaning a stale log could produce false warnings on subsequent operations.

**Reason for Not Fixing:** This is an overly pedantic warning that ignores the execution model. The `fetch-err.log` file is written once, read exactly once on the immediately following line, and never referenced again within the step. Furthermore, GitHub Actions runners execute in ephemeral environments that are destroyed after the job completes, making "stale log interference" impossible.

---

### Finding 230 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner complained that there is no dedicated CI or script-level test to validate that the multi-step heredoc prompts (`prompt.txt`) are well-formed (i.e., verifying bash variable expansion of `$REVIEWER_NAME`, missing `$`, etc.).

**Reason for Not Fixing:** This violates the "Ponytail" principle (YAGNI). Writing an entire parallel testing apparatus just to `grep` a bash script to ensure string interpolation didn't fail is textbook over-engineering. We rely on standard bash `cat << 'EOF'` semantics. If a variable fails to expand, the generated PR review comment will immediately exhibit obvious formatting errors, serving as its own integration test.

### Finding 81 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix

**Summary:** Python truncation decodes by byte count and ignores UTF-8 errors.

**Root cause:** The script truncates based on 60,000 raw bytes, which may split a multi-byte character. It then uses `errors='ignore'` on decode, dropping the remainder mid-sequence.

**Failure scenario:** This produces garbled text at the truncation boundary, dropping a single multibyte character if the boundary perfectly bisects it.

**Reasoning:** Because this only drops a single character at the extreme edge of a massive wall of text that is already intentionally and visibly truncated (with a `*(Review truncated...)*` warning appended immediately after), the impact is effectively zero. A strict character-based truncation approach would require loading the entire file into memory as a string first, which violates lazy engineering principles for such an insignificant edge case.

### Finding 118 — Low | `.github/workflows/ci.yml` | 🛑 Wont Fix

**Summary:** Doctest CI tests PR-head sanitizer, not default-branch production script.

**Root cause:** The `ci.yml` workflow checks out the PR branch and runs `doctest` against the PR's version of `.github/scripts/sanitize_review.py`. An attacker could remove both the security logic and the tests in the same PR, resulting in a passing CI check.

**Failure scenario:** An attacker successfully merges a weakened sanitizer because the CI pipeline provided a false sense of security by testing the attacker's weakened tests.

**Reasoning:** This is a fundamental property of how PR-based CI/CD systems operate (tests live with the code). Because `post_review.yml` strictly checks out the base `main` branch when executing the actual production comment posting, the attacker cannot weaponize this against their own PR. Bypassing the CI check only serves to deceive a human reviewer into merging the PR, which means standard human code review is the correct and expected mitigation here. Cross-checking out `main` just to test PRs introduces unnecessary complexity for an edge case covered by review.

### Finding 123 — High | `.github/workflows/post_review.yml` | 🛑 Wont Fix / Invalid

**Summary:** Adding `actions/checkout` without an explicit `ref` would hand `GH_TOKEN` to attacker-controlled scripts.

**Root cause:** The Threat Modeler claimed that a naive `actions/checkout` inside a `workflow_run` event would check out the untrusted PR branch by default, allowing an attacker to run their own `post_comment.sh` with elevated permissions.

**Failure scenario:** An attacker modifies `.github/scripts/post_comment.sh` in their PR to exfiltrate the `GH_TOKEN`.

**Reasoning:** This finding is factually invalid and represents a hallucination regarding GitHub Actions architecture. When a `workflow_run` event is triggered by a `pull_request`, GitHub Actions natively sets `github.sha` to the commit on the *base branch* (e.g. `main`), precisely to enforce a secure execution boundary. A plain `actions/checkout` safely checks out the trusted default branch, not the PR head. No fix is required.

### Finding 124 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix

**Summary:** Code-block URL defanging is missing AST backtick-context awareness.

**Root cause:** The global regular expressions used to strip explicit links and defang bare URLs do not respect markdown AST block boundaries (such as ` ``` ` or inline backticks).

**Failure scenario:** Legitimate code examples in PR reviews that contain URL strings or markdown link syntax will have their links stripped or defanged, potentially altering the intended visual output of the code block.

**Reasoning:** Attempting to parse markdown AST structures using Regex is notoriously fragile and frequently introduces ReDoS vulnerabilities. Implementing a proper AST parser would require pulling in a heavy third-party dependency like `markdown-it-py`. In accordance with "fail-closed" security and lazy engineering principles, slightly garbling a legitimate code snippet is an acceptable cosmetic tradeoff to guarantee absolute zero-dependency protection against prompt-injected phishing links.

### Finding 125 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Invalid

**Summary:** `cmark --safe` flag deprecated in cmark ≥0.31.

**Root cause:** A developer reported that the `--safe` flag was deprecated in recent `cmark` versions and might produce stderr warnings or fail in the future.

**Failure scenario:** The script fails to run due to an unrecognized flag, breaking the comment pipeline, or stderr warnings pollute the logs.

**Reasoning:** This is a hallucinated/invalid finding. Manual verification of `cmark 0.31.2` (the standard version in modern Ubuntu runners) confirms that the `--safe` flag is fully supported, actively documented in `--help`, and produces no deprecation warnings in stderr. The `--safe` flag remains the correct and secure mechanism for stripping raw HTML. No action required.

### Finding 129 — Low | `.github/scripts/post_comment.sh` | 🛑 Wont Fix / Accepted Risk

**Summary:** No automated tests for `post_comment.sh`.

**Root cause:** QA notes that `post_comment.sh` contains non-trivial orchestration logic (PR number resolution, traps, failure paths) but lacks a dedicated mock test script like `test_check_diff.sh`.

**Failure scenario:** A syntax error or logic bug in `post_comment.sh` causes the final PR comment step to fail in production, breaking the review pipeline.

**Reasoning:** Writing a dedicated test suite for `post_comment.sh` would require extensive over-engineering to mock the `gh` API, file system state, and `cmark` binaries. The script is inherently fail-closed (using `set -euo pipefail` and explicit file-size checks). A failure here simply results in a red X on the CI pipeline without posting a comment, which is immediately visible and safe. Following the "lazy engineering" philosophy, testing pipeline glue code via live pipeline execution is the shortest and most pragmatic path.

### Finding 179 — `accepted-risk` | `.github/scripts/post_comment.sh` + `.github/workflows/post_review.yml` | 🛑 Wont Fix

**Summary:** `github.event.workflow_run.pull_requests[0].number` does not exist reliably on `workflow_run` events. The commit-based PR number resolution fetches the first ambiguous match.

**Root cause:** `post_comment.sh:13-20` queries `/repos/$REPO/commits/$SHA/pulls` and unconditionally takes `.[0].number`. A commit present on multiple PRs (cherry-pick, merge-queue) returns the wrong PR.

**Failure scenario:** A cherry-picked commit across multiple PRs or a merge-queue squash causes the review comment to be posted to the wrong PR with no warning to operators.

**Reasoning:** `github.event.workflow_run.pull_requests[0].number` is an unreliable field on the `workflow_run` event—it is often sparsely populated or missing entirely by GitHub. Passing it from `post_review.yml` would not resolve the issue because the field is not consistently populated by the GitHub Actions event payload. The commit-based API resolution (`/repos/$REPO/commits/$SHA/pulls`), despite its first-match ambiguity for cherry-picks and merge-queue squashes, is the most reliable mechanism available. Wrong-PR comments are cosmetic (the full review is always accessible from the Actions tab), and this edge case is inherently bounded by GitHub's API contract. Building a disambiguation layer to handle this rare condition is not justified by the severity.

### Finding 138 — Low | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix / Accepted Risk

**Summary:** `PARENS_REGEX` depth-1 limit causes cosmetic artifacts on deeply-nested URLs.

**Root cause:** `PARENS_REGEX = r"(?:[^)(]+|\([^)(]*\))*"` only handles one level of nested parentheses in link URLs. A URL like `https://evil.com/path(a(b))` fails to fully match the inline link regex; the outer link is stripped but leftover markdown syntax may be visible.

**Failure scenario:** Deeply-nested URL in a markdown link produces leftover `)(` artifacts in the rendered comment text.

**Reasoning:** The URL is still defanged and the link is stripped (safe outcome). Adding recursive parenthesis matching via a recursive regex or loop would significantly increase complexity and introduce a real ReDoS attack surface, which is strictly worse than the current cosmetic artifact. Documented as a known limitation.

---
### Finding 151 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix

**Summary:** `www.` defang is case-sensitive.

**Root cause:** The defang regex `www\.` only matches lowercase `www.`.

**Failure scenario:** An attacker injects `WWW.evil.com` hoping to bypass the regex and produce a clickable link.

**Reasoning:** GFM's `cmark-gfm` autolinker is natively case-sensitive for the `www.` prefix. `WWW.evil.com` does not automatically render as a clickable link on GitHub. Therefore, no attack vector exists to bypass. Adding case-insensitivity would be defense against a non-issue.

---
### Finding 152 — Accepted Risk | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix

**Summary:** Autolink regex `[^>]+` truncates at first literal `>` in URL.

**Root cause:** The step 4 autolink regex `r"<[a-zA-Z][a-zA-Z0-9+.-]*://[^>]+>"` stops matching at the first literal `>` inside the URL itself.

**Failure scenario:** An attacker injects `<https://evil.com/?q=>payload>` hoping to leave `payload>` partially unstripped.

**Reasoning:** URLs containing literal `>` are technically invalid under RFC 3986 (they must be percent-encoded as `%3E`). However, even if an attacker tricks the parser, the second layer of defense (`cmark --safe`) will safely strip or defang the remaining HTML/markdown artifacts. The current regex is simple and robust against valid URLs; complicating it for invalid edge cases isn't warranted given the safety net.

---
### Finding 161 — Invalid | `.github/scripts/sanitize_review.py` | 🛑 Wont Fix

**Summary:** `@mention` defang regex fails on second `@` in malformed string like `@evil@user`.

**Root cause:** After step 1 strips link syntax from `[@evil@user](url)`, the string `@evil@user` enters step 6. `@evil` matches the regex `(?<!\w)@(\w[\w/-]*)` (preceded by start-of-string), but `@user` does not match because it is preceded by `l` (a word character).

**Failure scenario:** An attacker attempts to inject a malformed string like `[@evil@user](url)` hoping the LLM will output a clickable mention to `@user`.

**Reasoning:** On GitHub, `@user` embedded in the middle of a continuous text block without a trailing space or newline does not render as a mention and will not trigger a notification. Since this does not bypass the notification spam protection, this is a purely cosmetic artifact with no security implications.
