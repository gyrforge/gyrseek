# Docker Hardening Validation Checklist

This checklist validates seccomp/AppArmor hardening for gyrseek's ptrace-based Docker sandbox without breaking traces or package-manager network access.

## Scope

- Workload: `src/sandbox.rs` Docker path (`--cap-add SYS_PTRACE`, `--security-opt no-new-privileges`, tmpfs `/tmp` + `/work`, root runner + `strace -u gyrseek`, network enabled for package manager registry access).
- Goal: keep traces non-empty and installs working while tightening syscall and LSM policy.

## Files in repo

- Seccomp profile source: `src/sandbox.rs` (`EMBEDDED_SECCOMP_PROFILE_JSON`)
- This checklist: `docs/DOCKER_HARDENING_CHECKLIST.md`

## Platform note

- Seccomp policy applies in Linux container runtime (including Docker Desktop's Linux VM).
- Custom AppArmor profiles generally require native Linux host control over AppArmor profile loading.

## Step 1: Baseline sanity (no custom seccomp/apparmor)

Run from repo root:

```bash
just build
./target/release/gyrseek npm install left-pad
```

Expected:

- Scan runs.
- No "empty trace" error.
- Package can be downloaded from npm registry.

## Step 2: Validate seccomp profile syntax quickly

```bash
cat > /tmp/test_seccomp.json <<'EOF'
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": ["bpf"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }
    ]
}
EOF

docker run --rm \
  --security-opt "seccomp=/tmp/test_seccomp.json" \
  alpine:latest \
  echo 'Seccomp load OK'
```

Expected:

- Exit code 0.
- Message prints.

## Step 3: Smoke test ptrace path with network access

```bash
docker run --rm \
  --cap-add SYS_PTRACE \
  node:26.3-bookworm-slim \
  sh -lc "apt-get update >/dev/null && apt-get install -y strace >/dev/null && id -u gyrseek >/dev/null 2>&1 || useradd -m -d /home/gyrseek -s /bin/sh gyrseek >/dev/null 2>&1 || true; strace -f -e trace=network,execve -u gyrseek -o /tmp/trace.log sh -lc 'echo ok' && test -s /tmp/trace.log"
```

Expected:

- Exit code 0.
- `/tmp/trace.log` is non-empty.
- Able to reach apt registry (network is not isolated).

## Step 4: Run gyrseek e2e recipes with seccomp set

gyrseek enables seccomp by default via an embedded profile. Use the boolean env var for explicit control:

```bash
export GYRSEEK_DOCKER_SECCOMP_PROFILE=true
just build
```

To test the non-seccomp path explicitly:

```bash
export GYRSEEK_DOCKER_SECCOMP_PROFILE=false
just build
```

Then run:

```bash
just test-npm
just test-pnpm
just test-pip
just test-uv
just test-poetry
```

Expected:

- No widespread "empty trace" failures.
- Normal fail-closed behavior only for genuine scan findings/errors.
- Packages successfully downloaded from registries.

## Step 5: AppArmor rollout (Linux hosts)

Start with Docker's default AppArmor profile and verify no regression:

```bash
docker run --rm \
  --security-opt apparmor=docker-default \
  --cap-add SYS_PTRACE \
  node:26.3-bookworm-slim \
  sh -lc "strace -V"
```

If stable, introduce a custom AppArmor profile incrementally and repeat Step 3 + Step 4 after each tighten.

## Regression signals to watch for

- `ptrace(PTRACE_SEIZE): Operation not permitted`
- gyrseek: `empty trace ... strace produced no output`
- abrupt package-manager setup failures or network timeouts in sandbox container

## Backout plan

If scans regress:

1. Remove custom seccomp (`--security-opt seccomp=...`) and retest.
2. Remove custom AppArmor profile and retest.
3. Keep only `no-new-privileges` + `SYS_PTRACE` + resource limits until a narrower policy is validated.

## Suggested next hardening step after stable rollout

- Switch to prebuilt scanner images (`GYRSEEK_PREBUILT_SCANNER_IMAGES=true`) to reduce setup overhead.
- Then tighten capabilities and filesystem controls with less compatibility risk.
- Plan egress controls (allowlist/proxy) for future phases after no-execution-first detection is stable.
