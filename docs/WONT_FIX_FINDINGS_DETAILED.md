# Won't Fix Findings (Detailed)

*This document contains the detailed rationale for findings marked Won't Fix. For the brief overview, see [WONT_FIX_FINDINGS.md](./WONT_FIX_FINDINGS.md).*

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

### Finding 233 — `false-positive` | `docs/FIXED_FINDINGS.md` | 🚫 Won't Fix

**Summary:** The scanner flagged the fix description for Finding 92 as "architecturally incorrect" because it describes sanitizing `graphify-out` artifacts via Python XML-tag replacements before appending to `prompt.txt`. This references a stale architecture, as graphify output is no longer injected into `prompt.txt`.

**Reason for Not Fixing:** `FIXED_FINDINGS.md` is an immutable, point-in-time audit ledger. It correctly describes exactly what the fix was *at the time Finding 92 was resolved*. Rewriting historical audit logs to reflect future architectural changes defeats the purpose of an audit trail.

---

### Finding 234 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

**Summary:** The scanner warned that `fetch-err.log` (created during the `git fetch --unshallow` step) is never cleaned up via `rm -f`, meaning a stale log could produce false warnings on subsequent operations.

**Reason for Not Fixing:** This is an overly pedantic warning that ignores the execution model. The `fetch-err.log` file is written once, read exactly once on the immediately following line, and never referenced again within the step. Furthermore, GitHub Actions runners execute in ephemeral environments that are destroyed after the job completes, making "stale log interference" impossible.

---

### Finding 235 — `false-positive` | `.github/workflows/ci.yml` | 🚫 Won't Fix

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

---

### Finding 236 — `accepted-risk` | `scanning.rs` | 🚫 Won't Fix

**Summary:** An attacker who controls a package can introduce a malicious behavior (e.g., establishing a C2 connection or reading a sensitive file) very slowly to evade detection. They could introduce the behavior in a seemingly benign way, wait several months and multiple version releases for that behavior to become part of the accepted baselines, and then weaponize it in a future update. Because the behavior is already present in the accepted baselines, the subsequent update won't be flagged as an anomaly.

**Suggested Fix:** Implement long-term behavioral drift analysis, or flag behaviors based on their absolute threat level rather than purely relative differences against baselines.

**Reason for Not Fixing:** This is a fundamental limitation of any differential/baseline-based anomaly detection system. Gyrseek's core philosophy is to detect *changes* in behavior between versions, operating under the assumption that long-standing behaviors are implicitly trusted by the ecosystem. Detecting a slow-rolling attack requires absolute semantic understanding of the code's intent (e.g., knowing *why* a connection is being made), which is outside the scope of a behavioral diffing tool. We mitigate this somewhat through static artifact scanning (e.g., flagging unexpected executables or `.pth` files unconditionally), but purely behavioral poisoning over long timeframes will remain an accepted architectural risk.

---

### Finding 240 — `false-positive` | `docs/ARCHITECTURE.md` | 🚫 Won't Fix

**Summary:** Claim that ARCHITECTURE.md line 94 documents `deserialize_new_package_exemptions` as accepting the deprecated list format with a deprecation warning for backward compatibility.

**Reason for Not Fixing:** This is a fabricated claim. ARCHITECTURE.md line 94 describes `src/parsing.rs` (command, lockfile, and requirements parsing) and contains no mention of `deserialize_new_package_exemptions`, deprecated formats, or deprecation warnings. A full-text search of ARCHITECTURE.md for those terms returns zero results. The finding attributes text to the file that simply does not exist there.

---

### Finding 241 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** Claim that AGENTS.md line 117 states `min_baseline_age_hours` default as "2 hours", contradicting `DEFAULT_MIN_BASELINE_AGE_HOURS = 72` in `src/scanning.rs`.

**Reason for Not Fixing:** This is a fabricated claim with a wrong line number. AGENTS.md line 117 discusses forwarded-command exit-code propagation (FIXED_FINDINGS.md #8) and contains no mention of hours or baseline age. The actual `min_baseline_age_hours` entry is at line 128, which correctly reads "default effective age gate **72 hours**" — fully consistent with `DEFAULT_MIN_BASELINE_AGE_HOURS = 72` in `src/scanning.rs:154`. There is no discrepancy.

---

### Finding 242 — `false-positive` | `docs/FIXED_FINDINGS_DETAILED.md` | 🚫 Won't Fix

**Summary:** Claim that FIXED_FINDINGS_DETAILED.md Finding 239 omits the empty-list exception to the hard config-parse error for `new_package_exemptions`.

**Reason for Not Fixing:** This is a fabricated claim. Finding 239 ends with an explicit parenthetical: *"(Note: an empty list `[]` is explicitly handled as an exception and silently maps to no exemptions without error)"* — which precisely matches `src/lib.rs:48` (`List(v) if v.is_empty() => Ok(HashMap::new())`). The exception is fully documented.

---

### Finding 246 — `false-positive` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that `check_override_ages_rejects_version_younger_than_24_hours` and `check_override_ages_accepts_version_24_hours_or_older` use `Utc::now()` instead of deterministic frozen timestamps, while other tests in the same module use frozen timestamps.

**Reason for Not Fixing:** This is a fabricated claim. Both tests construct `now` with `chrono::DateTime::parse_from_rfc3339("2024-01-02T12:00:00Z").unwrap().with_timezone(&Utc)` — a hardcoded, deterministic timestamp — and pass it explicitly to `check_override_ages`. `Utc::now()` appears nowhere in either test.

---

### Finding 247 — `false-positive` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** Claim that the `deserialize_new_package_exemptions` error message uses `[pkg]` bracket syntax that does not match the actual YAML list format, confusing users trying to migrate.

**Reason for Not Fixing:** This is a fabricated claim. The error message at `src/lib.rs:50` reads: `"The 'new_package_exemptions' list format (e.g. '- pkg') is no longer supported."` It uses `- pkg`, which is the correct YAML sequence entry syntax. The `[pkg]` bracket form claimed by the reviewer does not appear anywhere in the message.

---

### Finding 248 — `false-positive` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that the TCP DNS parser only captures `read()` syscalls and ignores `recvmsg()`, allowing native-compiled resolvers (Go, Rust, Node.js N-API) that use `recvmsg()` to bypass DNS interceptor enrichment.

**Reason for Not Fixing:** This is a fabricated claim. The TCP read regex at `src/scanning.rs:525` explicitly uses the alternation `(?:read|recvmsg)\((\d+),...`, matching both `read()` and `recvmsg()` syscalls. `recvmsg` is already captured.

---

### Finding 279 — `yagni` | `sandbox.rs:990-996` | 🚫 Won't Fix

**Summary:** Claim that `SandboxEnvVarGuard::remove` redundantly calls `remove_var` in the constructor (line 993) and then again in Drop (line 1002), making the constructor call wasteful.

**Reason for Not Fixing:** The double-remove is intentional defensive behavior. The constructor call ensures the var is absent before the test body runs; the Drop call ensures it is absent after. If the test body sets the variable for some reason, the Drop still cleans it up. Both calls are idempotent (`remove_var` on an unset var is a no-op). This is correct RAII hygiene, not waste.

---

### Finding 293 — `false-positive` | `src/lib.rs:36-41` | 🚫 Won't Fix

**Summary:** Claim that `#[allow(dead_code)]` on `InvalidMap` and `List` variants in `NewPkgExemptions` is unnecessary because both variants are referenced in match arms.

**Reason for Not Fixing:** This is a false positive. With `#[serde(untagged)]`, serde derives the `Deserialize` impl through macro-generated code that constructs each variant based on structural matching of the input data. The Rust compiler's dead-code analysis operates at the source level and cannot see that these variants are instantiated via the macro-generated deserializer path. Without `#[allow(dead_code)]`, rustc emits spurious "variant is never constructed" warnings for `InvalidMap` and `List` even though they are fully reachable at runtime. The annotation is the standard correct solution for this pattern.

---

### Finding 290 — `false-positive` | `docs/FIXED_FINDINGS_DETAILED.md` | 🚫 Won't Fix

**Summary:** Claim that FIXED_FINDINGS_DETAILED.md Finding 229 references a `MapVisitor` implementation that was never committed, and that the actual code uses a simpler `#[serde(untagged)]` enum.

**Reason for Not Fixing:** This is a fabricated claim. A full-text search of FIXED_FINDINGS_DETAILED.md returns zero hits for "MapVisitor". The documentation for Finding 229 correctly and consistently describes the `#[serde(untagged)]` enum approach (`Map`, `List`, `Null`, `InvalidMap` variants) matching the actual code at `src/lib.rs:28-54`. No stale `MapVisitor` reference exists in the file.

---

### Finding 280 — `yagni` | `scanning.rs:693,764,808` | 🚫 Won't Fix

**Summary:** Claim that removing `.max(0)` guards from `Duration::hours(min_baseline_age_hours)` removes a defense-in-depth layer against future refactoring bugs that bypass the config parser clamp.

**Reason for Not Fixing:** The config parser at `src/lib.rs:257-262` is the correct single enforcement point for the ≥24h floor. A redundant guard scattered across three call sites that can never trigger given the enforced invariant is defensive bloat — it obscures the actual invariant rather than protecting it. Speculative defense for hypothetical future refactoring bypasses is YAGNI.

---

### Finding 273 — `false-positive` | `docs/FIXED_FINDINGS.md` | 🚫 Won't Fix

**Summary:** Claim that findings 254–255 omit the `src/` prefix used consistently by all adjacent entries 228–253.

**Reason for Not Fixing:** This is false. Entries 244–251 in the same table also lack the `src/` prefix (e.g. `scanning.rs:510`, `scanning.rs:503-506`, `lib.rs`, `sandbox.rs`). The prefix usage is already inconsistent throughout the table; 254–255 do not introduce a new inconsistency.

---

### Finding 274 — `false-positive` | `scanning.rs:1893-1908` | 🚫 Won't Fix

**Summary:** Claim that operators cannot distinguish age-rejection from registry-outage as the cause of baseline override removal, because both paths emit only a generic warning.

**Reason for Not Fixing:** The two code paths already emit distinct messages. Age-rejection (`filter_override_version`) says *"is only X hours old, which is below the hardcoded security floor"*; registry-outage (`published_at.is_empty()`) says *"Registry fetch failed (empty publish times) for '...'; discarding baseline overrides securely."* An operator reading either warning can identify the cause unambiguously.

---

### Finding 267 — `yagni` | `scanning.rs:640` | 🚫 Won't Fix

**Summary:** Claim that `active_test_env_vars()` lacks a dedicated unit test verifying each of its four env-var names is correctly detected, and that future renames or additions could drift without testing.

**Reason for Not Fixing:** `active_test_env_vars()` is a trivial filter over a static string array — there is no logic to test beyond `std::env::var` existence. Adding a dedicated test that sets and reads the four variable names would test the standard library, not gyrseek. The functions that consume its output (`fetch_history_with_baselines`) are tested by the surrounding integration harness. This is YAGNI.

---

### Finding 268 — `false-positive` | `docs/OPEN_FINDINGS.md` | 🚫 Won't Fix

**Summary:** Claim that OPEN_FINDINGS.md #177 (duplicate summary tables) must be annotated with partial-progress because the FIXED_FINDINGS_DETAILED.md summary table was removed in this PR, but #177 was not updated.

**Reason for Not Fixing:** This is a process preference, not a defect. Open findings are not required to carry incremental progress annotations; they remain open until the issue is fully resolved. Partial-progress notations add maintenance churn without providing actionable value.

---

### Finding 259 — `false-positive` | `AGENTS.md` / `scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that concatenated TCP DNS responses are silently dropped, allowing an attacker-controlled resolver to inject a second poisoned response that is never parsed.

**Reason for Not Fixing:** This is a known documented limitation, not a surprise finding. AGENTS.md explicitly states: *"lacks full TCP reassembly (fragmented DNS responses are dropped)."* The absence of multi-response TCP parsing is an accepted architectural scope limitation already recorded in the docs.

---

### Finding 260 — `false-positive` | `scanning.rs:1994-1999` | 🚫 Won't Fix

**Summary:** Claim that a self-referencing baseline override only warns but does not block, allowing an attacker with YAML write-access to set `baseline-1: "current"` and disable anomaly detection.

**Reason for Not Fixing:** This is working as designed. The self-ref override is excluded from the effective baseline set; if that exclusion causes the baseline count to drop below threshold, `insufficient_baselines` triggers and fails closed. YAML config is an explicitly trusted boundary — an attacker with config-write access can already bypass detection in more direct ways (Finding 237). No additional blocking is warranted.

---

### Finding 261 — `false-positive` | `src/lib.rs` / `AGENTS.md` | 🚫 Won't Fix

**Summary:** Claim that `min_baseline_age_hours` default was changed from 2h to 72h with no backward-compat migration warning, causing packages with infrequent releases to silently fail `insufficient_baselines`.

**Reason for Not Fixing:** The "2h default" is fabricated. `DEFAULT_MIN_BASELINE_AGE_HOURS` has always been `72` in `src/scanning.rs:154`. There was no change from 2h to 72h and therefore no migration gap. The separate usability concern about the error message not mentioning age-gate filtering is tracked as a real finding in OPEN_FINDINGS.md #258.

---

### Finding 249 — `false-positive` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that `Utc::now()` is captured once at `scan_packages_versions` function entry and becomes stale for later packages in 100+ package bulk scans.

**Reason for Not Fixing:** This is a fabricated claim. `let now = Utc::now()` at line 1879 is inside the `for (pkg_name, tgt_version) in pkg_targets` loop (lines 1851–1889), not at function entry. Every individual package gets a fresh timestamp on each loop iteration.

---

### Finding 250 — `false-positive` | `docs/FIXED_FINDINGS_DETAILED.md` | 🚫 Won't Fix

**Summary:** Claim that Finding 245 appears twice in FIXED_FINDINGS_DETAILED.md — briefly at line 1190 and in detail at line 1442 — with different detail levels.

**Reason for Not Fixing:** This is a fabricated claim. `grep -c "Finding 245"` returns exactly `1` occurrence in FIXED_FINDINGS_DETAILED.md. There is no duplicate.

---

### Finding 251 — `false-positive` | `docs/OPEN_FINDINGS.md` | 🚫 Won't Fix

**Summary:** Claim that Finding 70 was removed from OPEN_FINDINGS.md but never migrated to FIXED_FINDINGS.md, leaving its fix documentation orphaned.

**Reason for Not Fixing:** This is a fabricated claim. Finding 70 does not appear in OPEN_FINDINGS.md, FIXED_FINDINGS.md, or WONT_FIX_FINDINGS.md. There is no entry to be orphaned; the ID simply was never used or was never in the tracked range of these files.

---

### Finding 252 — `false-positive` | `docs/FIXED_FINDINGS.md` | 🚫 Won't Fix

**Summary:** Claim that the Finding 241 summary table entry is 530+ words, violating the single-line convention.

**Reason for Not Fixing:** This is a fabricated claim. The Finding 241 table row is 222 characters total — a normal single-line pipe-delimited entry. 530 words in a single table cell is physically impossible given the measured length.

---

### Finding 253 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** Claim that AGENTS.md lines routinely exceed 2000 characters, creating merge conflict hotspots.

**Reason for Not Fixing:** This is a fabricated claim. `awk`-based measurement finds zero lines in AGENTS.md exceeding 2000 characters.

---

### Finding 243 — `false-positive` | `README.md` | 🚫 Won't Fix

**Summary:** Claim that the `min_baseline_age_hours` configuration table row in README.md omits the 24h hard floor clamp enforced in code.

**Reason for Not Fixing:** This is a fabricated claim. README.md line 434 explicitly reads: *"Values below 24h are silently clamped to the 24h security floor."* The clamp is fully documented in the table row. Nothing is missing.

---

### Finding 244 — `false-positive` | `AGENTS.md` | 🚫 Won't Fix

**Summary:** Claim that AGENTS.md overstates the TCP DNS parser by saying it "tolerates short TCP reads" without disclosing the exact threshold (< 3 bytes) or the lack of reassembly for fragmented responses.

**Reason for Not Fixing:** This is a fabricated claim. AGENTS.md line 110 states: *"skips short TCP reads (< 3 bytes) without crashing, but lacks full TCP reassembly (fragmented DNS responses are dropped)."* Both the exact byte threshold and the reassembly limitation are explicitly documented in the same sentence. The description is accurate and complete.

---

### Finding 237 — `accepted-risk` | `scanning.rs` | 🚫 Won't Fix

**Summary:** An attacker who observes that an old version had a particular network endpoint can set `baseline_overrides` to point at that old version and add the endpoint's IP to the allowlist. Even if the current version connects to a new C2 endpoint, the diff against the overridden baseline produces zero diffs, framing a known-good old version as the comparison point to bypass detection.

**Suggested Fix:** Validate that override versions were published recently, or compute a behavioral signature union/intersection across fetched and override baselines to flag behaviors not present in recent versions.

**Reason for Not Fixing:** This will remain a limitation of gyrseek for the foreseeable future. Baseline overrides are explicitly designed as a heavy-handed configuration escape hatch for users to force a specific baseline when natural resolution fails or is inappropriate. Implementing recency validation or intersection logic would significantly complicate the override mechanism and undermine its purpose as an unconditional user-directed override. It is accepted that malicious or compromised configuration changes within the repository (`gyrseek.yaml`) can bypass anomaly detection, as configuration is assumed to be trusted.

---

### Finding 297 — `false-positive` | `scanning.rs:156-190` | 🚫 Won't Fix

**Summary:** Claim that an unparseable IP string in a strace trace would be silently ignored and treated as non-local, allowing a malformed endpoint to bypass detection.

**Reason for Not Fixing:** This is a false positive. `normalize_ip_string` returns the original string unchanged when parsing fails (line 173: `Ok(ip) => ..., Err(_) => addr.to_string()`), and `is_sandbox_local_ip` returns `false` when the input cannot be parsed as an IP (line 188: `let Ok(ip) = addr.parse::<IpAddr>() else { return false; }`). The combined effect is that an unparseable string is **not** filtered out — it passes through to the diff as-is and would be flagged as a new/unknown endpoint. This is the correct fail-closed behaviour. The only "issue" is potential noise if something generates malformed IP strings in the trace, but that is an upstream parsing problem outside the scope of this filter.

---

### Finding 300 — `yagni` | `scanning.rs:1671-1719` | 🚫 Won't Fix

**Summary:** Claim that `select_effective_baselines` returning `(Vec<String>, bool)` couples selection logic to diagnostic output — the bool is only consumed by a warning message and re-derived independently by the override-survival check.

**Reason for Not Fixing:** The `self_ref` boolean flags a specific semantic condition: "at least one override version equals the current version being scanned." This is distinct from whether any non-null override entries survive (checked by `matches!(filtered_overrides, ...)`). The two checks answer different questions. The bool is a meaningful return value, not a leaking diagnostic concern. The interface is minimal and appropriate.

---

### Finding 301 — `yagni` | `scanning.rs:1839-2373` | 🚫 Won't Fix

**Summary:** Claim that `scan_packages_versions` is too large (~534 lines) with too many responsibilities, and that the `#[cfg(any(debug_assertions, test))]` branching creates CI-invisible behavioral asymmetry between test and production modes.

**Reason for Not Fixing:** Function size is a style/maintainability concern not tied to correctness or security. Refactoring would require user-visible API changes with no functional benefit at this time. The `#[cfg]` test/production asymmetry is a real concern, but it is already separately tracked as OPEN #264 with its own detailed rationale and fix direction — tracking it again here is a duplicate.

---

### Finding 306 — `false-positive` | `src/scanning.rs:279,323` | 🚫 Won't Fix

**Summary:** Claim that `ip_allowlist.get(package_name)` and `domain_allowlist.get(package_name)` at the per-package lookup sites in `filter_allowlisted_new_connections` and `filter_domain_allowlisted_new_connections_with` do not trim `package_name`, so a future caller passing an untrimmed name would silently miss its per-package entries.

**Reason for Not Fixing:** All current callers derive `package_name` from `plan.package` which is populated from parsed CLI arguments or lockfile entries. Neither path introduces leading or trailing whitespace. The claim describes a hypothetical future regression in caller code, not a current bug. Adding a `.trim()` at the lookup site would be defensive bloat for a scenario that does not exist. If a future caller with untrimmed names is added, the fix belongs at the new call site.

---

---

### Finding 308 — `false-positive` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** Claim that per-package domain/IP normalization lacks dedicated edge-case tests for trailing-dot stripping, mixed-case lowering, and IPv6 canonicalization in the per-package code paths.

**Reason for Not Fixing:** The per-package normalization paths execute the same functions as the global paths — `normalize_domain` (which calls `.trim().trim_end_matches('.').to_ascii_lowercase()`) and `scanning::normalize_ip_string`. A regression in normalization logic would break both global and per-package paths simultaneously and would be caught by the existing global-path tests. Adding duplicated test coverage for identical code paths is yagni.

---

### Finding 309 — `yagni` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** Claim that mistyped per-package allowlist keys (e.g. `"requets"` instead of `"requests"`) silently produce dead entries with no diagnostic, and that scan-time validation against the known package list should be added.

**Reason for Not Fixing:** The full package list is not available at config-parse time, making config-load validation impossible. Scan-time cross-referencing would add complexity (passing the resolved package list back to a config-validation layer) for a usability concern with no security consequence — a missed per-package allowlist entry is fail-closed (the package is still scanned, the entry just has no effect). This is the same accepted limitation as mistyped keys in `baseline_overrides` and `min_baseline_age_hours_by_package`.

---

### Finding 311 — `false-positive` | `src/scanning.rs:2351-2370` | 🚫 Won't Fix

**Summary:** Claim that `filter_domain_allowlisted_new_connections_with` runs before `find_new_connections_domain_aware`, so the per-package domain allowlist removes IPs before the domain-aware diff sees them, amplifying the existing OPEN #281 domain-planting attack surface.

**Reason for Not Fixing:** The premise is factually wrong. The call order in `scan_packages_versions` (lines 2351→2359→2364) is: (1) `find_new_connections_domain_aware` computes the diff from raw current and baseline IP sets, (2) `filter_allowlisted_new_connections` applies the ip allowlist to the diff output, (3) `filter_domain_allowlisted_new_connections_with` applies the domain allowlist to the remainder. Neither allowlist filter receives or modifies the raw `ips_curr`/`baseline_ips` sets that the diff reads. The domain allowlist cannot amplify OPEN #281.

### Finding 320 — `false-positive` | `src/scanning.rs:247-252` | 🚫 Won't Fix

**Summary:** Claim that the DNS interceptor in `find_new_connections_domain_aware` has an `IpAddr` type mismatch: connection IPs are normalized to `IpAddr::V4` via `normalize_ip_string`, but DNS-map IPs could be stored as `IpAddr::V6(::ffff:1.2.3.4)`, causing `dns_ips.contains(&parsed)` to always return false for those entries.

**Reason for Not Fixing:** The scenario requires a DNS server to serve an IPv4-mapped address as an AAAA record. This does not happen in practice: IPv4 addresses are served as A records (DNS type 1), which `parse_dns_response` always stores as `IpAddr::V4`. An AAAA record (type 28) contains a 16-byte IPv6 address — a real IPv4-mapped `::ffff:x.x.x.x` in AAAA position would be a synthetic/crafted DNS response outside the real threat model. Both real A records and real AAAA records are stored correctly typed, and a connection IP resolved from an A record always matches its DNS-map counterpart. No production path produces the type mismatch.

---

### Finding 321 — `false-positive` | `src/lib.rs:236` | 🚫 Won't Fix

**Summary:** Claim that per-package allowlist keys are `.trim()`-only (no `.to_ascii_lowercase()`), causing silent dead entries when npm preserves mixed-case package names like `MyPackage` while the allowlist key is `mypackage`.

**Reason for Not Fixing:** npm enforces all-lowercase package names at the registry level. A package named `MyPackage` cannot be published to the npm registry, and `npm install MyPackage` returns a 404. No real npm package has a mixed-case name that could diverge from a lowercase allowlist key.

PyPI is case-insensitive but does NOT normalize package names before they reach `plan.package` — if an operator runs `pip install Requests`, `plan.package` will be `Requests`, and `allowlist.get("Requests")` will miss a key written as `requests`. This creates a genuinely dead allowlist entry with no diagnostic. However, the consequence is fail-closed (a missed allowlist entry means the package is not allowlisted, which is the safe direction — the package still gets scanned and blocked on anomalies). This is the same class as WONT_FIX #309 (misspelled keys): config is a trusted boundary, and adding scan-time cross-referencing to catch casing mismatches would require knowing the full resolved package list at config-parse time, which is unavailable then. Operators who care about exact casing should write lowercase keys, which is the universal convention for Python package names (PEP 508).

**TM-5 (parse_list_map asymmetry):** `parse_list_map` passes `lowercase: bool` to `parse_list` which lowercases *values* only, not package keys. A package key `"Requests"` in YAML stores under `"Requests"` in the map; `scan_packages_versions` looks up by the resolved name (e.g. `"requests"`), producing a miss. This is the same root cause as the PyPI casing issue above — distinct manifestation (values vs. keys path) but identical fail-closed consequence and identical reason for not fixing.

---

### Finding 323 — `false-positive` | `src/scanning.rs:316-322` | 🚫 Won't Fix

**Summary:** Claim that `filter_domain_allowlisted_new_connections_with` builds `effective: HashSet<String>` via `.cloned().collect()`, while the IP equivalent `filter_allowlisted_new_connections` uses `HashSet<&str>` via `.map(|s| s.as_str()).collect()` — an inconsistency and unnecessary allocation.

**Reason for Not Fixing:** Switching the domain filter from `HashSet<String>` to `HashSet<&str>` requires adding a lifetime parameter to the function signature and threading it through `domain_is_allowlisted`, adding complexity for a single O(n) allocation over a typically small (≤10 entry) allowlist that is built once per filter call. FIXED #305 addressed O(n×m) re-normalization work that occurred on every lookup — a per-call cost proportional to both allowlist size and IP count. The `cloned()` here is a one-time O(n) build, which is qualitatively different and not worth the lifetime annotation overhead to eliminate.

---

### Finding 327 — `yagni` | `src/lib.rs:217-330`, `src/scanning.rs:269-334` | 🚫 Won't Fix

**Summary:** Claim that no end-to-end integration test exercises the full `load_policy_config` → `PolicyConfig` → `scan_packages_versions` → filter chain with a mixed global+per-package allowlist.

**Reason for Not Fixing:** The gap exists at the integration boundary, but the risk is low. `load_policy_config` tests assert on every `PolicyConfig` field that the function populates — the output is directly verified. Scan-layer tests construct `PolicyConfig` structs directly with the same field values and assert filter behavior. The connection between the two is direct struct field assignment (`ip_allowlist: ip_allowlist`, etc.) with no transformation logic that could silently regress. A full mock-runner end-to-end test for this path would require MockRunner setup, fake version history, and fake trace output — substantial complexity for a bridge that has no logic to test, only assignment.

**Filter orthogonality note:** A reviewer raised that even if the bridge is correct, a filter function itself could silently ignore per-package entries (e.g., if `get(package_name)` was accidentally replaced with `get("*")`). This is a distinct risk from the bridge. However, each of the four `parse_list_map`-based filter functions has a dedicated per-package isolation test (e.g. `sensitive_reads_allowlist_does_not_leak_across_packages`, FIXED #325) that would catch exactly this regression — the filter tests are independent of the bridge and cover the per-package lookup path directly.

---

### Finding 337 — `false-positive` | `src/scanning.rs:299` | 🚫 Won't Fix

**Summary:** Claim that `ends_with(&format!(".{}", allowed))` in `domain_is_allowlisted` is overly broad — an entry of `"amazonaws.com"` also matches `ec2.us-east-1.amazonaws.com`, `cloudfront.amazonaws.com`, and every other subdomain of the parent zone, when the operator may have intended only to allow that specific domain.

**Reason for Not Fixing:** Subdomain-inclusive matching is **standard DNS allowlist convention**, used by every WAF, proxy, and firewall domain allowlist tool. Writing a parent domain in an allowlist universally means "this domain and its subdomains." The exact-match branch (`normalized == *allowed`) already handles operators who want to scope to a single FQDN — they write `"s3.amazonaws.com"` instead of `"amazonaws.com"`. The suffix match is not a bug but the correct behavior for the common case (e.g., AWS SDK packages legitimately connect to hundreds of `*.amazonaws.com` endpoints; requiring the operator to enumerate every subdomain individually is not viable). The domain allowlist is written by a trusted operator in a trusted config file; an operator who writes `"amazonaws.com"` is making a deliberate scoping decision, not an accidental one. There is no security regression: the allowlist is always an explicit opt-in that widens the pass set; fail-closed behavior applies to everything outside the allowlist.

**Shared-infrastructure amplification note:** An operator writing `"amazonaws.com"` to allow S3 access also admits DynamoDB (`dynamodb.us-east-1.amazonaws.com`), EC2 metadata (`ec2.amazonaws.com`), STS (`sts.amazonaws.com`), and every other AWS service endpoint — a much broader pass set than intended. This is an accepted consequence of parent-domain matching. Operators who want tighter scoping should write the specific service subdomain (e.g. `"s3.amazonaws.com"`) rather than the parent zone. WONT_FIX #347 documents the related FCrDNS erosion risk when a shared-infrastructure domain is allowlisted per-package.

---

### Finding 348 — `yagni` | `src/lib.rs:158` | 🚫 Won't Fix

**Summary:** Claim that `parse_list` lacks a dedicated unit test — coverage is indirect through callers only. (`option_zero_to_none` split to FIXED #376 when a third call site raised the stakes.)

**Reason for Not Fixing:** `parse_list` is a four-line filter+lowercase+collect pipeline. Every caller is independently tested and the function has no branching logic that a caller test could miss. A dedicated test would be an exact duplicate of a subset of the existing caller tests — adding it increases test count without increasing coverage or confidence.

---

### Finding 349 — `false-positive` | `src/lib.rs:257,279-280,300,324` | 🚫 Won't Fix

**Summary:** Claim that the domain allowlist uses `"blank"` while the IP allowlist uses `"invalid"` for similar situations — operators scanning logs for one term miss warnings from the other allowlist.

**Reason for Not Fixing:** The different wording reflects genuinely different validation situations. The IP path emits `"Ignoring invalid ip_allowlist entry (not an IP)"` when `s.parse::<IpAddr>()` returns `Err` — this fires on any non-IP string including non-empty garbage like `"foobar"` or `"1.2.3.4.5"`. The domain path emits `"Ignoring blank domain_allowlist entry"` specifically when `normalize_domain(s)` returns `""` — i.e. the value was whitespace-only or empty after trimming. A non-empty invalid domain string (e.g. `"not_a_domain!"`) would pass through silently because the domain path has no invalid-format check beyond normalization. The messages are accurate for what they detect. Unifying them to `"invalid"` would be misleading for the domain path since it only catches the blank case.

---

### Finding 350 — `false-positive` | `docs/FIXED_FINDINGS_DETAILED.md` | 🚫 Won't Fix

**Summary:** Claim that new detailed entries (332+) include severity in headings as a convention drift — `FIXED #326` and `AGENTS.md` state summary tables (including severity) live only in main files.

**Reason for Not Fixing:** The claim is backwards. New entries (315+) use `### Finding N: description` — no severity in the heading. Old entries (1–24) use `### Finding N — Severity | file | ✅ Fixed` — those include severity. The inconsistency runs in the opposite direction from the claim: older entries are more verbose, newer entries are cleaner. The newer format (no severity) is the correct convention. No action needed.

---

### Finding 342 — `yagni` | `src/lib.rs:247-252,269-274` | 🚫 Won't Fix

**Summary:** Claim that IP addresses are double-parsed at config-load time: `s.parse::<IpAddr>()` validates the string then discards the result; `normalize_ip_string(&s)` parses from scratch internally. The parsed `IpAddr` could be threaded into normalization to avoid the second parse.

**Reason for Not Fixing:** This code path runs once at startup over a small config list (typically <20 entries). The second parse costs nanoseconds. Eliminating it would require changing `normalize_ip_string`'s signature from `(&str) -> String` to accepting an `IpAddr`, rippling the change to all other callers (including the hot-path filter). The complexity cost far exceeds any measurable benefit.

---

### Finding 343 — `yagni` | `src/scanning.rs:286` | 🚫 Won't Fix

**Summary:** Claim that `normalize_ip_string(ip)` in `filter_allowlisted_new_connections` is redundant because connection IPs are already normalized by `extract_connection_ips` at trace-capture time — the call is always a no-op on legitimate inputs.

**Reason for Not Fixing:** The normalization is a cheap defensive guard at the boundary of a security-critical filter. `extract_connection_ips` normalizes today, but a future refactor could add a new call site that bypasses that path. Keeping the normalization in the filter ensures correctness regardless of how the caller constructs `new_connections`. The cost is negligible (parse + format of a small set per scan).

---

### Finding 344 — `yagni` | `src/scanning.rs:299` | 🚫 Won't Fix

**Summary:** Claim that `format!(".{}", allowed)` in `domain_is_allowlisted` allocates a new `String` per allowlist entry per call. The comment on line 298 says "no re-allocation needed" (referring to Fix #324's removal of `normalize_domain` re-allocation), but this `format!` allocation remains.

**Reason for Not Fixing:** The allowlist is typically ≤10 entries; this function is not on a hot path (called once per new IP after a sandbox scan, not in a tight loop). Replacing with a byte-index suffix check would reduce readability for a sub-microsecond saving. The comment on line 298 is accurate in context — it describes the removal of the `normalize_domain(allowed)` per-entry re-normalization allocation from Fix #324, not a claim that zero allocations occur on that line.

---

### Finding 345 — `false-positive` | `src/lib.rs:643-651` | 🚫 Won't Fix

**Summary:** Claim that `is_none_or(|s| s.is_empty())` in `per_package_allowlist_star_key_rejected_for_ip_domain_and_list_map` is less strict than `!contains_key("*")`, potentially masking an insertion-then-removal bug.

**Reason for Not Fixing:** Both `None` (key absent) and `Some(empty_set)` (key present but empty) correctly verify the security property — no IPs are reachable via the `"*"` bucket. The production code path cannot produce `Some(empty_set)` for `"*"` (the `"*"` key is only inserted by the `Global` branch which always inserts a non-empty string, or by the PerPackage branch which is rejected by `validate_allowlist_pkg_key`). There is no real "insertion-then-removal" scenario in the code.

---

### Finding 346 — `yagni` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that `find_new_items` has no dedicated unit test verifying `find_new_items(&a, &a).is_empty()` or superset behavior.

**Reason for Not Fixing:** `find_new_items` is three lines: `current.difference(baseline).cloned().collect()` + `out.sort()`. The set-difference logic is entirely delegated to `HashSet::difference` from the standard library — there is no custom set-difference implementation that could have an off-by-one. The only gyrseek-specific logic is the sort, which the caller tests exercise on all non-empty outputs. The three delegating functions are one-line wrappers; their caller tests exercise identical-sets, new-items, and no-new-items cases, providing complete coverage of everything gyrseek contributes. A dedicated test for `find_new_items` would test stdlib `HashSet::difference`, not gyrseek code.

**Sort stability concern:** A reviewer noted that `HashSet::difference` returns elements in non-deterministic iteration order, so caller tests that only assert membership (rather than exact order) might not catch a regression that removes or breaks the sort. In practice, the three caller wrapper tests (`sensitive_reads`, `git_clone`, `process_exec`) produce multi-element results and assert on `Vec` equality against a sorted expected slice, which locks in sort order. A regression dropping `out.sort()` would fail those tests. The sort contract is covered.

---

### Finding 347 — `accepted-risk` | `src/scanning.rs:295-301`, `docs/ARCHITECTURE.md` | 🚫 Won't Fix

**Summary:** Claim that allowing an operator to add a per-package domain allowlist entry for a domain the package author controls (e.g. `evil-pkg: ["cdn.evil-pkg.net"]`) erodes the FCrDNS trust model. FCrDNS only prevents third-party PTR spoofing; it does not protect against an attacker who owns the allowlisted domain rotating C2 infrastructure behind their own legitimate PTR and forward DNS records.

**Reason for Not Fixing:** This is fundamental to how any allowlist works. When an operator writes `evil-pkg: ["cdn.evil-pkg.net"]`, they are explicitly asserting trust in that domain for that package. The config file is a trusted boundary; the operator is assumed to have vetted the domain before allowlisting it. No allowlist system — DNS-based or otherwise — can protect against an operator deliberately trusting infrastructure the attacker controls. FCrDNS prevents *third-party* DNS spoofing attacks, which is the relevant threat model. Removing or restricting the allowlist feature would not mitigate this scenario; it would only reduce operator control.

**Cloud-storage exfiltration scenario (S3/GCS/Azure Blob):** A concrete instance of this risk: an operator adds `aws-sdk: ["s3.amazonaws.com"]` to allow the AWS SDK to connect to S3. Later, the package is compromised. The malicious version exfiltrates credentials to an attacker-controlled S3 bucket — a connection to `s3.amazonaws.com` that FCrDNS validates cleanly (AWS's own PTR and forward DNS records confirm the binding). gyrseek sees `s3.amazonaws.com` traffic in both baseline and current, the allowlist passes it, and no anomaly fires. The same applies to `storage.googleapis.com`, `blob.core.windows.net`, and similar cloud-storage endpoints. This is an accepted risk: the allowlist is an operator opt-in that explicitly widens the pass set, and the operator is responsible for understanding that allowlisting a shared-infrastructure domain (rather than a package-specific endpoint) admits a broad class of traffic. Operators can mitigate this by preferring narrow, package-specific domain entries and avoiding shared cloud-storage wildcard allowlisting for sensitive packages.

---

### Finding 335 — `false-positive` | `src/scanning.rs:492-540` | 🚫 Won't Fix

**Summary:** Claim that `extract_dns_map` should heuristically detect whether strace was invoked with the `-xx` flag (by checking for `\x`-escaped bytes in the trace) and emit a warning or error if not, since a missing `-xx` flag would produce un-escaped binary wire data that `unescape_strace_string` cannot parse, yielding an empty DNS map.

**Reason for Not Fixing:** The strace flags are unconditionally assembled in `build_matrix_script` in `src/sandbox.rs`. There is no code path in the production build where `extract_dns_map` receives a trace without `-xx`. A heuristic detector (e.g., checking for `\x` occurrences in the captured DNS payload) would be brittle: a trace with no DNS activity would look identical to a trace generated without `-xx` from the heuristic's perspective, producing false warnings. The safe failure mode when `-xx` is absent is already correct: `unescape_strace_string` returns the raw bytes unchanged, the DNS regex does not match, the DNS map is empty, and the fallback to FCrDNS and then plain-IP membership diff kicks in — both of which are fail-closed for genuinely new endpoints. Adding a `-xx` detection heuristic adds complexity and false-positive risk for a configuration state that cannot arise in the production path.

---

### Finding 336 — `false-positive` | `Cargo.toml` | 🚫 Won't Fix

**Summary:** Claim that version bumps in `Cargo.toml` should be in a separate commit from code changes to keep semantic version history clean and allow `git log` to isolate behavioral changes from release bookkeeping.

**Reason for Not Fixing:** This is a style preference with no correctness or security consequence. The repository has no established policy requiring version bump isolation — reviewing the git log shows version bumps and code changes are regularly combined in single commits. The overhead of splitting every PR into a "code change" commit and a "version bump" commit adds process friction without a compensating benefit for a project of this size and team composition.

**Semver jump rationale (0.6.0→1.0.0):** The 0.6.0→1.0.0 increment was intentional. The per-package allowlist feature changes the YAML config schema in a way that is backward-compatible (new optional keys), but 1.0.0 signals general production readiness after the core security hardening series (Findings 1–341). ROADMAP lists future changes that may further evolve the config schema, but those will each carry their own version bumps when they land. Semver policy for this project: breaking config changes bump major, new backward-compatible features bump minor, fixes bump patch.

**Tag-at-docs-commit concern:** The concern that a combined code+docs commit causes the release tag to point at a "docs commit" rather than the functional feature commit is noted. In practice, the tag points at the HEAD of the PR merge, which contains both the feature code and the version bump in the same commit — there is no separate docs-only commit here. The version bump is in the same commit as the code changes it describes.

---

### Finding 353 — `yagni` | `src/scanning.rs:1573-1614` | 🚫 Won't Fix

**Summary:** `find_new_sensitive_reads`, `find_new_git_clone_signatures`, and `find_new_process_exec_signatures` are each now a single-line delegate to `find_new_items`. Claim: delete the wrappers and call `find_new_items` directly at each call site.

**Reason for Not Fixing:** The named wrappers preserve domain-specific semantics at their call sites — `find_new_sensitive_reads(current, baseline)` is self-documenting in a way that `find_new_items(current, baseline)` is not when read in context of the broader anomaly-detection logic. The thin delegation adds zero runtime cost (inlined by the compiler). Removing the wrappers would save three function definitions but make every call site less readable. The tradeoff favours named domain functions.

---

### Finding 354 — `yagni` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Claim that the `baselines` parameter in `select_effective_baselines` and `fetch_history_with_baselines` should be renamed to `baseline_versions` for clarity.

**Reason for Not Fixing:** The name `baselines` is consistent with the surrounding codebase terminology (type `Vec<String>` holding version strings used as baseline probes). It is unambiguous in context — `select_effective_baselines` makes the intent clear from the function name alone. Renaming is a cosmetic change with no correctness or security benefit.

---

### Finding 355 — `yagni` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** `AllowlistEntry::Global(String)` is declared after `AllowlistEntry::PerPackage(HashMap<String, Vec<String>>)`. With `#[serde(untagged)]`, serde tries variants in declaration order. Moving `Global` first would avoid attempting HashMap deserialization on scalar inputs.

**Reason for Not Fixing:** Config is parsed once at startup over a typically small allowlist. The HashMap attempt on a scalar YAML string fails fast (serde returns a type error immediately on a non-map node); it is not a retry loop or an O(n) scan. The declaration order has no observable impact on performance or correctness. Reordering would be a micro-optimisation with no safety benefit.

---

### Finding 356 — `yagni` | `src/scanning.rs` | 🚫 Won't Fix

**Summary:** `normalize_ip_string` creates an intermediate `String` that it immediately returns. Claim: refactor to avoid the temporary.

**Reason for Not Fixing:** `normalize_ip_string` is called at config-load time over the ip_allowlist entries — typically a handful of strings, once per process startup. The single heap allocation per entry is negligible. Changing the function signature or implementation to avoid the intermediate would not improve any measurable metric and would make the code harder to follow.

---

### Finding 372 — `yagni` | `src/scanning.rs:1577,1619,1644,1671` | 🚫 Won't Fix

**Summary:** Claim that `filter_allowlisted_sensitive_reads`, `filter_allowlisted_process_exec_signatures`, `filter_allowlisted_artifact_findings`, and `filter_allowlisted_git_clone_signatures` should each have a doc comment noting they only look up `get(package_name)` with no `"*"` global chain, so a future developer adding global support to `parse_list_map` knows to update these functions.

**Reason for Not Fixing:** Any developer adding global `"*"` support to `parse_list_map` must audit its callers by definition — that audit is not optional and not guided by comments. A comment saying "update this if you change parse_list_map" is a speculative maintenance note with no present-day value. The four functions already share a visually identical structure (`get(package_name)`, no `"*"` fallback) that is immediately legible. Comments in this style tend to become stale when the function is updated and the comment is not, creating misleading documentation. YAGNI: no global parse_list_map support is planned.

---

### Finding 377 — `false-positive` | `docs/ARCHITECTURE.md`, `AGENTS.md` | 🚫 Won't Fix

**Summary:** Review claimed ARCHITECTURE.md omitted the config-loading helper layer (`validate_allowlist_pkg_key`, `option_zero_to_none`, `parse_list_map`) — the section allegedly covered only the allowlist decision model (step 5) without describing the helper hierarchy or why extraction was necessary.

**Reason for Not Fixing:** The premise was incorrect. FIXED #374 had already added a "Config-loading helpers" subsection to ARCHITECTURE.md describing all three helpers, their validation semantics, merge behavior, and call sites. The finding was raised against a version of the document that had already been updated in the same PR. No action needed.

---

### Finding 373 — `yagni` | `src/lib.rs:1751-1825` | 🚫 Won't Fix

**Summary:** Claim that the 13-block startup info section could be extracted to a macro or slice-of-tuples iterator to eliminate the repeated `if !policy.X.is_empty() { println!(...) }` pattern.

**Reason for Not Fixing:** The blocks are not uniform. They use three different access patterns — `.values().map(|s| s.len()).sum()` for ip/domain (counting total entries), `.len()` for map-keyed allowlists (counting package keys), and `if let Some(v) =` for optional numeric thresholds. They reference different field types (`HashMap<String, HashSet<String>>`, `HashMap<String, String>`, `Vec<String>`, `Option<usize>`). Extracting the uniform subset (the `is_empty()` + `println!` blocks) would require an enum or closure per variant to bridge the type diversity, producing more abstraction than the original. The three `release_burst_threshold` and `minimum_release_age_package` blocks would remain inline regardless, so the extraction is partial. The existing pattern is straightforward to read and extend: adding a new allowlist type is a three-line copy. YAGNI.

**CO-1 partial-extraction proposal considered:** A reviewer proposed extracting the uniform count-based blocks into `fn print_config_summary(policy, config_path)` using a slice-of-tuples iterator for the `is_empty()`+`len()` subset while keeping threshold and exemption blocks inline. This correctly identifies the extractable subset, but the result would still require the non-uniform blocks to remain adjacent (or be moved inside the same function), and the function would need closures or an enum to handle the `.sum()` vs `.len()` access difference. The net outcome is a private helper with mixed-type closure arguments that is harder to extend than the current three-line copy pattern. Extraction deferred until a second caller exists.

---

### Finding 369 — `accepted-risk` | `src/scanning.rs:1577-1599` | 🚫 Won't Fix

**Summary:** No path canonicalization in `filter_allowlisted_sensitive_reads` — allowlist entries and strace-observed paths are compared via string matching (`==` and `ends_with`). Path-complexity variants like `./././.aws/credentials` or `foo/../../.aws/credentials` could bypass the allowlist.

**Reason for Not Fixing:** The paths in strace output are the paths as received by the Linux kernel at the `open`/`openat` syscall boundary. The kernel does not receive the pre-resolution client string — it receives the path after the C library has resolved `./` components through `realpath`-equivalent logic for most callers. Strace traces the syscall argument, not the userspace string before `chdir`/relative resolution. In practice, strace-observed paths in production sandbox traces are already in a normalized form (absolute paths without `./` or `../` components). Additionally, `Path::canonicalize()` performs a live filesystem lookup (`stat` + readlink chain) and requires the path to exist on the *host* filesystem at the time of the call. All paths being evaluated are paths inside a Docker container — they are never present on the host. Every `canonicalize()` call would fail with `No such file or directory` and fall back to string matching anyway, adding overhead with zero benefit. OPEN #270 tracks the related symlink traversal bypass, which is the realistic threat in the sandbox context.

---

### Finding 366 — `yagni` | `src/lib.rs:429-441` | 🚫 Won't Fix

**Summary:** Claim that the `sensitive_file_access_allowlist` value guard only rejects four hardcoded patterns (`"*"`, `"/"`, `"*/"`, `"/*"`) — other wildcard forms like `"**"`, `"*foo*"`, or `"*foo/*"` pass through, creating a maintenance gap if wildcard semantics evolve.

**Reason for Not Fixing:** The filter at `scanning.rs:1592` uses `strip_prefix('*')` to convert any `"*"`-prefixed entry into a suffix match on the stripped remainder. A value like `"**"` becomes a suffix match for paths ending in `"*"` (none exist in practice), and `"*foo*"` becomes a suffix match for paths ending in `"foo*"` (also none). These are dead entries — they never match any real file path and provide no protection, but they also don't over-match. The four rejected forms are the only ones that would produce meaningfully over-broad matches (`"*"` → any path, `"/"` → root, `"*/"` and `"/*"` → effectively anything). No planned change to wildcard semantics exists; adding exhaustive pattern validation is YAGNI in the absence of a concrete threat.

---

### Finding 357 — `yagni` | `src/lib.rs`, `AGENTS.md` | 🚫 Won't Fix

**Summary:** The `"*"` key convention for the global ip_allowlist/domain_allowlist bucket is not explained in user-facing documentation (README).

**Reason for Not Fixing:** The semantics are fully documented in AGENTS.md. A full config-reference page (covering all six allowlists, their keys, value formats, and effective-set semantics) is tracked as a ROADMAP item. Adding a partial note in the README before the full reference exists would create documentation fragmentation. The existing AGENTS.md entry is the authoritative source for contributors; end-users requiring a config reference will be directed to the forthcoming dedicated doc.

---

### Finding 395 — `false-positive` | `docs/FIXED_FINDINGS.md` | 🚫 Won't Fix

**Summary:** Claim that existing FIXED entries (#292–#376) violate the convention added by FIXED #375 by including line numbers (e.g. `src/lib.rs:65-70`, `src/scanning.rs:295-304`).

**Reason for Not Fixing:** FIXED #375 established a forward-looking convention: *new* entries should omit line numbers. It does not retroactively require stripping line numbers from ~60 entries written before the convention existed. The same logic applies as WONT_FIX #350 and #384: retroactive normalization of historical entries has no correctness benefit and would touch every existing entry. The convention applies from the point it was established; prior entries are grandfathered.

---

### Finding 396 — `yagni` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** `!s.contains("")` in a test assertion uses `HashSet::contains` (membership check — correct) but reads like a `String::contains` substring check to a casual reader unfamiliar with the type. Replacing with `!s.iter().any(|d| d.is_empty())` would make the intent explicit.

**Reason for Not Fixing:** The assertion is functionally correct. `HashSet<String>::contains("")` checks whether the empty string is a member of the set — exactly the intended check. The type annotation is visible in context. This is the same class as WONT_FIX #345 (`is_none_or` assertion readability). Cosmetic-only; no correctness risk.

---

### Finding 392 — `yagni` | `src/lib.rs`, `src/scanning.rs` | 🚫 Won't Fix

**Summary:** Global IP/domain allowlist entries are stored under the magic key `"*"` in the same `HashMap` as per-package entries. A filter function that forgets to chain `get("*")` with `get(package_name)` silently skips all global entries. A separate `global: HashSet<String>` field in `PolicyConfig` would make the global/per-package distinction unmissable at compile time.

**Reason for Not Fixing:** Both current filter functions (`filter_allowlisted_new_connections` and `filter_domain_allowlisted_new_connections_with`) correctly chain `get("*").unwrap_or(&empty).iter().chain(get(package_name).unwrap_or(&empty).iter())`. The risk is speculative: a future developer adding a third filter forgetting the chain. Restructuring `PolicyConfig` to split the `HashMap` into `global: HashSet<String>` + `per_package: HashMap<String, HashSet<String>>` would require changes to `load_policy_config`, both filter functions, all test fixtures, and the startup summary — substantial churn for a two-caller pattern that is already visually distinctive. No current bug; YAGNI.

---

### Finding 384 — `false-positive` | `docs/OPEN_FINDINGS_DETAILED.md` | 🚫 Won't Fix

**Summary:** New entries (#378–#382) use `### Finding N: description` while pre-existing entries use `### Finding N — Severity | file | ⚠️ Open`. The formats are inconsistent.

**Reason for Not Fixing:** Same class as WONT_FIX #350, which noted the same inconsistency in FIXED_FINDINGS_DETAILED.md and documented it as not a forward drift — new entries omit severity, old entries include it. Retroactively normalizing hundreds of entries to a single format has no correctness benefit. The inconsistency is cosmetic and benign.

---

### Finding 385 — `yagni` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** Over 20 `println!("⚠️ [gyrseek] ...")` calls in `load_policy_config` follow a near-identical pattern. A helper macro or function could reduce repetition.

**Reason for Not Fixing:** Each call site is at most two lines and carries specific, non-uniform context (allowlist name, package name, entry value, guidance text). Extracting to a helper would require passing these varying fields as parameters, producing a function with 3–4 arguments that is harder to read than the inline calls. Same class as WONT_FIX #373 (non-uniform startup block). No correctness benefit; YAGNI.

---

### Finding 386 — `yagni` | `src/lib.rs` | 🚫 Won't Fix

**Summary:** `validate_allowlist_pkg_key` accepts `&HashMap<String, HashSet<String>>` but only calls `.contains_key()` on it. The parameter type is broader than required; `&HashSet<String>` (the key set) or a `contains_key`-capable trait would be sufficient.

**Reason for Not Fixing:** `validate_allowlist_pkg_key` is a private helper with three callers, all of which pass the full map because they already have it in scope. Narrowing to `&HashSet<String>` would require callers to pass `map.keys().collect()` or a separate set, adding an allocation and a transformation step at each call site. Introducing a trait bound for a single `.contains_key()` call adds abstraction for no correctness gain. The function is already well-scoped and the broader type costs nothing at runtime.

---
