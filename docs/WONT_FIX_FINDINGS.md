# Won't Fix Findings

This document tracks findings that were raised by static analysis, AI reviews, or manual inspection, but have been explicitly marked as "Won't Fix" along with extensive rationale.

## Summary

| #   | File                       | Tag / Type       | What                                                                                     | Status       |
|-----|----------------------------|------------------|------------------------------------------------------------------------------------------|--------------|
| C1  | `lib.rs`                   | `shrink`         | 31-line manual arg-loop for `--config`/`-c`.                                             | 🚫 Won't Fix |
| C3  | `lib.rs`                   | `yagni`          | `NoopRunner` struct with full trait impl for test bypass.                                | 🚫 Won't Fix |
| C4  | `lib.rs`                   | `shrink`         | `ScanTimer` struct with `Instant`, `Drop`, two print branches.                           | 🚫 Won't Fix |
| C5  | `lib.rs`                   | `yagni`          | `scan_targets` is a 1-line delegate to `scan_many_with_cache`.                           | 🚫 Won't Fix |
| C11 | `parsing.rs`               | `shrink`         | `parse_poetry_lock_packages_from_content` has 7-param closure.                           | 🚫 Won't Fix |
| C12 | `sandbox.rs`               | `shrink`         | `scanner_user_setup_steps` returns `vec!["..."]`, called once.                           | 🚫 Won't Fix |
| C13 | `sandbox.rs`               | `shrink`         | `image_setup_steps` 4× `steps.push(...)` with `format!`.                                 | 🚫 Won't Fix |
| FP1 | `scanning.rs`              | `false-positive` | Host-mode `uv pip install` leaks into exec signatures.                                   | 🚫 Won't Fix |
| FP2 | `.github/workflows/ci.yml` | `false-positive` | `actions/checkout@v7` does not exist.                                                    | 🚫 Won't Fix |
| FP3 | `scanning.rs`              | `false-positive` | `/.azure/` test exists but no `/.gnupg/` test.                                           | 🚫 Won't Fix |
| FP4 | `README.md`                | `false-positive` | Exfiltration "caught at the network boundary" docs claim overstates completeness.        | 🚫 Won't Fix |
| FP6 | `AGENTS.md`                | `false-positive` | Graphify skill referenced but skill file does not exist.                 | 🚫 Won't Fix |
| FP7 | `docs/common_prompts.md` | `false-positive` | Raw CI prompt committed into documentation directory. | 🚫 Won't Fix |
| FP8 | `sandbox.rs`               | `false-positive` | `process_vm_readv` is permitted in the seccomp profile.                                  | 🚫 Won't Fix |
| FP9 | `scanning.rs`              | `false-positive` | Race condition in insufficient_baselines check ordering.                                 | 🚫 Won't Fix |
| FP10| `.github/workflows/`       | `false-positive` | Prompt Injection / Runner Compromise exfiltrating deployment secrets.                    | 🚫 Won't Fix |
| FP11| `.github/workflows/`       | `false-positive` | Autonomous Agent execution via `--dangerously-skip-permissions`.                         | 🚫 Won't Fix |
| FP12| `.github/workflows/ci.yml` | `accepted-risk`  | `timeout-minutes: 10` with no partial-output trap.                                       | 🚫 Won't Fix |
| FP13| `.github/workflows/ci.yml` | `accepted-risk`  | `max-parallel: 3` vector for CI inference budget exhaustion.                             | 🚫 Won't Fix |
| FP14| `AGENTS.md`                | `false-positive` | `AGENTS.md` CI description omits operational details (model name, SHA hash).             | 🚫 Won't Fix |
| FP15| `.github/workflows/ci.yml` | `false-positive` | Redundant OpenCode installation script in dependent consolidation job.                   | 🚫 Won't Fix |
| FP16| `.github/workflows/ci.yml` | `accepted-risk`  | LLM self-censoring via tool access (`--dangerously-skip-permissions`).                   | 🚫 Won't Fix |
| FP17| `.github/workflows/ci.yml` | `accepted-risk`  | Findings documents (`OPEN_FINDINGS`, `WONT_FIX`) are not protected from PR tampering.    | 🚫 Won't Fix |
| FP18| `.github/workflows/ci.yml` | `accepted-risk`  | `graphify update` parsing vulnerability leading to CI runner RCE.                        | 🚫 Won't Fix |
| FP19| `.github/workflows/ci.yml` | `false-positive` | CI job fails if `gyrseek_review.md` or other artifact files are missing.                 | 🚫 Won't Fix |
| FP20| `.github/workflows/ci.yml` | `false-positive` | Permissions fragmentation for `checks: write` across jobs.                               | 🚫 Won't Fix |
| FP21| `.github/workflows/`       | `accepted-risk`  | Third-party actions use moving tags instead of being SHA-pinned.                         | 🚫 Won't Fix |

---

### Finding C1 — `shrink` | `lib.rs:64-95` | 🚫 Won't Fix

**Summary:** 31-line manual arg-loop for `--config`/`-c`.

**Suggested Fix:** Compact `while let Some(arg)` with `strip_prefix` + `ok_or_else` → 20 lines.

**Reason for Not Fixing:** The manual loop is highly readable. Refactoring to an iterator chain reduces line count but increases cognitive overhead (unnecessary churn). The current structure allows for straightforward addition of new flags without disrupting nested map chains.

---

### Finding C3 — `yagni` | `lib.rs:572-583` | 🚫 Won't Fix

**Summary:** `NoopRunner` struct with full trait impl for test bypass.

**Suggested Fix:** Rust requires a concrete type for trait impl; closure can't substitute.

**Reason for Not Fixing:** As stated, Rust requires a concrete type for trait implementation. Replacing it with a closure is not natively supported without boxing overhead. The `NoopRunner` struct is a clean, dependency-free way to mock out the sandbox in tests.

---

### Finding C4 — `shrink` | `lib.rs:701-717` | 🚫 Won't Fix

**Summary:** `ScanTimer` struct with `Instant`, `Drop`, two print branches.

**Suggested Fix:** Inlined approach introduced maintenance footgun. RAII Drop is the correct, lazy choice for scoped cleanup.

**Reason for Not Fixing:** The RAII Drop pattern ensures the timer is always printed on scope exit, preventing missed prints on early returns. Inlining it introduces a maintenance footgun.

---

### Finding C5 — `yagni` | `lib.rs:802-810` | 🚫 Won't Fix

**Summary:** `scan_targets` is a 1-line delegate to `scan_many_with_cache`.

**Suggested Fix:** Inlined at 5 call sites.

**Reason for Not Fixing:** Inlining a 1-line delegate at 5 call sites causes duplication and breaks the single source of truth for the scan delegation path. Keeping the delegate provides a central point if future logic (like logging or metrics) needs to be added before caching.

---

### Finding C11 — `shrink` | `parsing.rs:79-239` | 🚫 Won't Fix

**Summary:** `parse_poetry_lock_packages_from_content` has 7-param closure.

**Suggested Fix:** `Pkg` struct with `finalize()` method eliminates 7-param closure; `fn` replaces closure.

**Reason for Not Fixing:** Moving from a closure to a full `Pkg` struct with state management adds unnecessary boilerplate. The closure keeps the parsing logic localized and prevents structural bloat for what is ultimately a single sequential parsing pass.

---

### Finding C12 — `shrink` | `sandbox.rs:462-477` | 🚫 Won't Fix

**Summary:** `scanner_user_setup_steps` returns `vec!["..."]`, called once.

**Suggested Fix:** Inlined at both call sites.

**Reason for Not Fixing:** Keeping setup steps in a dedicated function improves readability and modularity, preventing the parent caller from becoming bloated. It visually segments the "what to run" from the "how to run it".

---

### Finding C13 — `shrink` | `sandbox.rs:517-538` | 🚫 Won't Fix

**Summary:** `image_setup_steps` 4× `steps.push(...)` with `format!`.

**Suggested Fix:** `match manager` replaces if/else if; inlined at both call sites.

**Reason for Not Fixing:** Similar to C12, keeping the step creation encapsulated makes the main runner pipeline much easier to read. `match` statements vs `if/else` here is a stylistic choice that isn't worth the code churn.

---

### Finding FP1 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** Host-mode `uv pip install` leaks into exec signatures.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. `sandbox.rs:254-259` shows that `--target` and `target_path` are correctly included in the host runner args. Furthermore, `is_harness_command` accurately matches via `--target`. The reported leak cannot happen under the current code execution flow.

---

### Finding FP2 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `actions/checkout@v7` does not exist.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. `actions/checkout` has indeed published `v7` on GitHub. The static analysis or reviewer's local cache was likely outdated, leading to the assumption that `v4` was the maximum major tag.

---

### Finding FP3 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** `/.azure/` test exists but no `/.gnupg/` test.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive. Both `.azure` and `.gnupg` are tested. Specifically, `scanning.rs:2193-2195` clearly covers the `.gnupg` test case. The reviewer missed these lines.

---

### Finding FP4 — `false-positive` | `README.md` | 🚫 Won't Fix

**Summary:** Exfiltration "caught at the network boundary" docs claim overstates completeness.

**Suggested Fix:** None.

**Reason for Not Fixing:** This is a false positive based on semantic interpretation. This is a threat modeling caveat rather than a direct code defect. The docs correctly state the theoretical coverage, but bypasses are acknowledged architectural risks. We will not change the docs because they accurately reflect the feature intent, not an infallible guarantee. Additionally, the Threat Model review clarifies that DNS tunneling exfiltration is invisible not just because DNS queries go to a sandbox-local resolver, but because `extract_dns_map` parses DNS *responses*, not queries. An attacker encoding secrets in DNS query names to a domain they control exfiltrates data without ever calling `connect()` to a new IP. Finally, there is an endpoint baseline poisoning angle: an attacker could seed their C2 domain in the baseline via benign telemetry in v1.0.0. Both are fundamental behavioral-diffing limitations that are explicitly accepted as out-of-scope.



### Finding FP6 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** Graphify skill referenced but skill file does not exist.

**Suggested Fix:** Either install the missing skill file or remove the reference from `AGENTS.md`.

**Reason for Not Fixing:** This is a false positive. Graphify is not an agent skill, but a Python package tool that is invoked directly via the CLI (`graphify update .`). The reference in `AGENTS.md` is correct in instructing the agent to invoke the tool, but the static analysis misunderstood it as a missing `.agents/skills` folder entry.


### Finding FP7 — `false-positive` | `docs/common_prompts.md` | 🚫 Won't Fix

**Summary:** Raw CI prompt committed into documentation directory.

**Suggested Fix:** Remove the file or move it to a dedicated internal/`.github` directory with proper context headers.

**Reason for Not Fixing:** The file is intentionally kept in the documentation directory for the developer's own reference during CI pipeline adjustments. It is not considered a defect.

### Finding FP8 — `false-positive` (Not blocking `process_vm_readv`) | `sandbox.rs` | 🚫 Won't Fix

**Summary:** `process_vm_readv` is permitted in the seccomp profile, allowing a process to read memory from its siblings.

**Suggested Fix:** Block `process_vm_readv` in the default-allow seccomp profile.

**Reason for Not Fixing:** This is a won't fix because `strace` intrinsically requires `process_vm_readv` to function. `strace` relies on this syscall to read strings and data structures (like arguments to `execve` or file paths in `open`) from the target process's memory space. Blocking it would render `strace` unable to capture the rich behavioral telemetry that Gyrseek relies on for its anomaly detection. 

Furthermore, a malicious process can only use `process_vm_readv` for *read-only* access to sibling memory. To actively corrupt logs or interfere with sibling execution, an attacker would need `process_vm_writev`. Because we have explicitly blocked `process_vm_writev`, the memory corruption vector is neutralized. The read-only access does not pose a threat to the integrity of the trace logs, making `process_vm_readv` safe to leave permitted.

---

### Finding FP9 — `false-positive` | `scanning.rs` | 🚫 Won't Fix

**Summary:** Race condition in insufficient_baselines check ordering.

**Suggested Fix:** Move the baseline-count check after the self-reference override check.

**Reason for Not Fixing:** This is a false positive. While the count check (`baselines.len() < policy.baseline_count` at line 1753) occurs textually before the override logic block (line 1772), `select_effective_baselines` (called prior to this flow) already explicitly filters out `v_curr` from the baselines. Thus, the count at line 1753 correctly reflects the effective baselines, excluding any self-referencing overrides. Unit tests (e.g., `override_equal_to_current_is_excluded_from_baselines`) already confirm this behavior.

*Note:* This "Won't Fix" dismissal is scoped strictly to the sequential text ordering concern. The separate issue regarding the async cache race (`scan_with_cache` concurrent cache population) is tracked as a distinct legitimate vulnerability in `OPEN_FINDINGS.md` (Finding 84).

---

### Finding FP10 — `false-positive` (Accepted Architectural Risk) | `.github/workflows/` | 🚫 Won't Fix

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

### Finding FP11 — `false-positive` (Accepted Architectural Risk) | `.github/workflows/` | 🚫 Won't Fix

**Summary:** Using `--dangerously-skip-permissions` allows the AI code reviewer to autonomously execute tools (file reads, web searches) without human oversight, creating a vector for prompt injection to weaponize the agent's capabilities.

**Suggested Fix:** Require human approval (interactive mode) for all agent tool executions, or strictly sandbox network and file access.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk required to run an agentic review system headlessly in CI. Without `--dangerously-skip-permissions`, the agent cannot use its tools and would crash or hang when attempting to read the repository context.

We accept the risk of prompt injection weaponizing the autonomous agent because the blast radius is fundamentally constrained by the CI Job Separation architecture:
1. **Read-Only Sandbox:** The agent executes within `ci.yml`, which is strictly locked to `contents: read`. Even if the agent is tricked into using its tools maliciously, it cannot push commits, merge PRs, or modify repository configurations.
2. **Ephemeral Environment:** The runner is destroyed immediately after execution.
3. **No Private Data Exfiltration:** As an open-source project, the source code is public. Even if an attacker tricks the autonomous agent into reading source files and `POST`ing them to an external server via web tools, no confidential intellectual property is lost.
4. **Prompt-Level Directives:** We have explicitly instructed the agent in its system prompt that it is "strictly forbidden from downloading files or executing commands," providing a first layer of defense against generic autonomous abuse.

---

### Finding FP12 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `timeout-minutes: 10` with no partial-output trap (ci.yml:134,232). Timeout produces zero output; no trap/signal handler to dump partial results.

**Reason for Not Fixing:** The AI review output is inherently structured markdown; a partial or truncated LLM output stream is generally corrupted and impossible to parse reliably by downstream consolidation logic. Failing cleanly with zero output is preferred over injecting malformed context.

---

### Finding FP13 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `max-parallel: 3` on 5-reviewer matrix (ci.yml:62). Up to 30 concurrent minutes of AI inference per run; CI budget exhaustion vector via repeated PRs.

**Reason for Not Fixing:** The matrix strategy is intentionally designed to trade inference budget for parallel speed. Throttling this via concurrency limits or serializing the reviewers would degrade developer experience and increase PR latency. Cost/budget controls should be enforced at the API key limit level, not via workflow throttling.

---

### Finding FP14 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** AGENTS.md CI description omits operational details (AGENTS.md:53-54). High-level summary drops model name, install verification SHA, artifact flow. Developers cannot trace CI behavior from AGENTS.md alone.

**Reason for Not Fixing:** `AGENTS.md` is an architectural memory file, not a line-by-line technical specification. Hardcoding volatile operational details (like the OpenCode version SHA or the exact model name) into the documentation creates unnecessary maintenance churn. The single source of truth for execution mechanics is `ci.yml`.

---

### Finding FP15 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** Redundant OpenCode installation (ci.yml:207-219). Full `curl | sha256sum | bash` chain re-runs in `post-review-comments` job despite same cache key as `code-review` job.

**Reason for Not Fixing:** The static analysis tool incorrectly flags this block because it fails to account for GitHub Actions caching logic. The installation script is wrapped in an `if: steps.cache-opencode.outputs.cache-hit != 'true'` conditional. Because the consolidation job strictly depends on (`needs:`) the review job, the cache is guaranteed to be populated. The installation script is skipped at runtime, making this a true false positive.

---

### Finding FP16 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** LLM self-censoring via tool access (ci.yml). With `--dangerously-skip-permissions`, the agent has file-write capabilities. Under prompt injection from malicious PR code, the agent could be instructed to read its own in-progress output file or review ledger, and modify or delete findings before they are written back. This is distinct from exfiltration (FP11); this is purely self-censoring of security reviews.

**Suggested Fix:** Restrict the agent's tool access to read-only tools, or remove `--dangerously-skip-permissions` and rely purely on stateless LLM execution.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk. The agent requires tool access to explore the codebase effectively, and it requires write access to generate and consolidate the final markdown artifacts (e.g., `consolidated_gyrseek_review.md`).
We accept this risk because the CI pipeline is a supplementary defense layer. Human review is still required for PRs. If an attacker successfully injects a prompt to censor findings, the output will simply be clean, which degrades gracefully to the baseline level of security (standard human review). Neutering the agent's tool access would cripple its ability to conduct deep, context-aware architectural reviews, which provides more value than the theoretical risk posed by self-censoring.

---

### Finding FP17 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `docs/OPEN_FINDINGS.md` and `docs/WONT_FIX_FINDINGS.md` are not protected from tampering during CI. The workflow checks out the PR versions of these files rather than strictly enforcing the base branch versions. 

**Suggested Fix:** Add `docs/OPEN_FINDINGS.md` and `docs/WONT_FIX_FINDINGS.md` to the base-branch checkout loop in `ci.yml`.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk designed to prevent "Context Contradiction" bugs. If we force these files back to their base branch state, the AI reviewer receives contradictory signals when reviewing a PR that legitimately fixes a vulnerability (the diff shows the bug moved to `FIXED_FINDINGS.md`, but the file on disk still says it's `OPEN`). 

We accept the risk of an attacker tampering with `OPEN_FINDINGS.md` to hide a backdoor because the AI reviewer is explicitly given the PR diff. If an attacker maliciously deletes a security policy from the documentation, the AI reviewer (and human reviewers) will see that deletion directly in the code diff and can flag it. The only files that strictly require base-branch enforcement are the immutable system instructions (`AGENTS.md` and `.agents/skills/`).

---

### Finding FP18 — `accepted-risk` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** `graphify update` executes source-parsing code from the PR branch without container isolation or cryptographic dependency pinning. A crafted source file exploiting a `graphify` parsing bug, or a compromised PyPI release/sub-dependency, could achieve Remote Code Execution (RCE) on the CI runner, allowing an attacker to forge the AI's review output.

**Suggested Fix:** Isolate `graphify` execution to a locked-down Docker container, or pin the dependency via exact commit hash/SHA256 checksums rather than just PyPI version.

**Reason for Not Fixing:** This is an explicitly accepted architectural risk. Exploiting a niche parser vulnerability just to forge an AI review is a highly complex attack vector with very low impact. As an open-source project, the repository is public and the CI workflow executes with strictly read-only permissions (`contents: read`) under our Job Separation architecture. There are no deployment secrets, write-tokens, or private data in the runner environment to exfiltrate. The absolute worst-case scenario is that the attacker successfully forges a "clean" review for their malicious PR, which degrades the security posture to exactly that of a standard human review without AI assistance. Because the impact is negligible, the operational complexity of containerizing or cryptographically pinning the `graphify` execution is not justified.

---

### Finding FP19 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The `upload-artifact` step in `ci.yml` uses `if-no-files-found: error`, causing the entire `code-review` job to fail if the AI reviewer does not produce an output file. 

**Suggested Fix:** Change the setting back to `if-no-files-found: ignore` to prevent CI flakiness when the LLM API times out.

**Reason for Not Fixing:** This is an intentional security design. Setting it to `ignore` creates a dangerous "silent failure" where an AI crash or API timeout results in a green CI build with a blank review, tricking developers into thinking the code was successfully audited and found to be safe. We intentionally enforce `if-no-files-found: error` so that if the AI review pipeline fails to generate an output, it fails loudly and blocks the PR. **Do not revert this to `ignore`.**

---

### Finding FP20 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** Permissions fragmentation for `checks: write`. The `checks: write` permission is not granted at the top-level of the workflow; it is only granted explicitly to the `cargo-audit` job. This prevents other jobs (like `rust-checks` or `code-review`) from posting inline check annotations.

**Suggested Fix:** Move `checks: write` to the top-level `permissions` block so all jobs inherit the ability to write check annotations.

**Reason for Not Fixing:** This is an intentional implementation of the Principle of Least Privilege and a major security feature, not a bug. If `checks: write` were applied globally, the `code-review` job (which executes untrusted PR code and AI models) would inherit it. An attacker achieving RCE during the review job could use that permission to forge fake "All Checks Passed!" annotations to deceive human reviewers. By intentionally fragmenting permissions and keeping the top-level default to strictly `read-only`, the pipeline successfully limits the blast radius of any potential compromise.

---

### Finding FP21 — `accepted-risk` | `.github/workflows/` | 🚫 Won't Fix

**Summary:** Third-party actions use mutable moving tags (e.g., `@v4`) instead of being cryptographically SHA-pinned.

**Suggested Fix:** Pin all third-party actions to specific commit SHAs to prevent supply chain compromise.

**Reason for Not Fixing:** This is an explicitly accepted risk in favor of Developer Experience (DX). Pinning to SHAs makes workflow files significantly harder to read and requires heavy automation (like Dependabot or Renovate) just to keep actions up to date. Furthermore, the actual impact of a compromised third-party action in this repository is very low. The primary CI jobs run with strictly `contents: read` permissions and no secrets. If an attacker gains RCE via a compromised action in `ci.yml`, the absolute worst-case scenario is that they bypass the AI code review (a risk we have already accepted in Finding FP18). The operational overhead of managing SHAs heavily outweighs the theoretical risk to the read-only CI pipeline.
