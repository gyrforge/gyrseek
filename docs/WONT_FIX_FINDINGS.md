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
