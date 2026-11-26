# Releasing gyrseek

A release is: a version bump merged to `main`, a tag on that commit, the release workflow (build, attest, publish after approval), and then three follow-ups in other repositories. Do the steps in order. Releases are immutable, so a mistake means a new version, never a re-tag (see [When something goes wrong](#when-something-goes-wrong)).

Needs: `git`, `gh` (logged in), `just`, `cargo`, and Docker (for `just image-pins`). In the commands below, `X.Y.Z` is the new version, for example `1.4.4`.

## 1. Prepare the change

```bash
git switch main && git pull
git switch -c Release-X.Y.Z
```

Raise the version in `Cargo.toml` (`version = "X.Y.Z"`), then let Cargo update `Cargo.lock` and check it is consistent:

```bash
cargo check            # rewrites the gyrseek entry in Cargo.lock
cargo check --locked   # must pass: the lock matches Cargo.toml
git diff --stat        # only Cargo.toml and Cargo.lock so far
```

Update the version where the docs show it, and look for any other place the old version appears:

```bash
grep -rn "OLD.VERSION" README.md docs AGENTS.md .github   # replace OLD.VERSION with the current one, for example 1.4.3
```

- `README.md`: the `cargo install ... --tag vX.Y.Z` line, and the `v=X.Y.Z` example with its `prints: gyrseek X.Y.Z` comment in step 2b.
- Leave `.github/workflows/ci.yml` (`GYRSEEK_VERSION`) alone for now: it is the released version the published action installs, and moves in step 7.
- Anything the release must contain, such as a licence change, must be merged **before** the tag. `v1.4.2` shipped under the wrong licence because the tag was made before the relicensing PR was merged.

Before a release, refresh the pinned sandbox images (`AGENTS.md`, "Refresh the pinned sandbox image digests when due"):

```bash
just image-pins        # every line must say ok; fix any DRIFT as described there
```

## 2. Check it locally

```bash
just lint
just test
graphify update .      # keeps graphify-out/ in step, as the repository policy asks
```

## 3. Open the pull request

```bash
git add Cargo.toml Cargo.lock README.md          # plus anything else you changed on purpose
git commit -m "Prepare vX.Y.Z release"
git push -u origin Release-X.Y.Z
gh pr create --fill
```

## 4. Review, then merge

- **CI:** every required check must be green on the PR (the list is in the `main` ruleset: `Rust checks`, the Docker jobs, the advisory scan and so on).
- **CodeRabbit:** read its comments, fix what is valid, resolve the threads.
- **Approval:** a code owner must approve (`@gyrforge/gyrseek-builders`), someone other than whoever pushed last. As the repository admin you can also merge your own PR through your pull-request bypass.
- **Merge:**

```bash
gh pr merge --merge          # or use the button; the branch is deleted on merge
git switch main && git pull
```

## 5. Tag and publish

Wait for CI on `main` to finish. Then, from `main`:

```bash
just tag
```

`just tag` takes the version from `Cargo.toml`. It refuses unless `HEAD` is exactly `origin/main`, waits for the `ci.yml` run on that commit to pass, and refuses a tag `origin` already has. It then pushes `vX.Y.Z`, which starts `release.yml`:

1. **`verify`**: the tag matches `Cargo.toml`, is on `main`, CI passed on it, and no release exists.
2. **`build`**: the four archives (Linux x86_64 and ARM64, macOS Apple Silicon and Intel).
3. **`release`**: waits for your approval. Open the run in the Actions tab, choose **Review deployments**, approve the `release` environment. It then writes `SHA256SUMS`, attests the archives, creates the release as a draft and publishes it. The release is immutable.

## 6. Verify the release

```bash
v=X.Y.Z
repo=$(git rev-parse --show-toplevel)             # run this from inside your clone; the next line leaves it
d=$(mktemp -d) && cd "$d"
gh release download "v$v" --repo gyrforge/gyrseek
shasum -a 256 -c SHA256SUMS                       # sha256sum -c on Linux
for f in gyrseek-v$v-*.tar.gz; do gh attestation verify "$f" --repo gyrforge/gyrseek --signer-workflow gyrforge/gyrseek/.github/workflows/release.yml >/dev/null && echo "attested: $f"; done
for f in gyrseek-v$v-*.tar.gz; do tar -tzf "$f" | sed 's#.*/##' | sort | tr '\n' ' '; echo; done   # LICENSE NOTICE README.md gyrseek, in each
gh api repos/gyrforge/gyrseek/releases/tags/v$v --jq '{immutable,draft}'    # immutable true, draft false

# the tag's commit is the main commit you meant: right after releasing the two hashes are equal (later, origin/main moves on)
git -C "$repo" fetch --quiet origin main --tags
git -C "$repo" rev-parse "v$v^{commit}" origin/main
```

## 7. Follow-ups, in this order

Each of these is its own pull request in its own repository, and each needs the release from step 5 to exist.

1. **gyrseek-action** (`gyrforge/gyrseek-action`; run these in your clone of it): pin the new version, then release the action.

   ```bash
   git switch main && git pull && git switch -c Pin-gyrseek-X.Y.Z
   support/add-version.sh X.Y.Z      # verifies hashes and attestations, writes support/locks/gyrseek-X.Y.Z.txt
   git add support/locks && git commit -m "Pin gyrseek X.Y.Z" && git push -u origin Pin-gyrseek-X.Y.Z
   gh pr create --fill               # merge it once Self-test passed and Lint are green
   git switch main && git pull
   just tag vA.B.C                   # a new gyrseek version is a minor release of the action: v1.0.1 -> v1.1.0
   ```

   The release notes of the new tag show the commit to pin.

2. **This repository, CI:** in `.github/workflows/ci.yml`, point the `gyrseek-action` job at the new action commit and set `GYRSEEK_VERSION` to the new version. Dependabot also proposes the action pin.

3. **homebrew-gyrseek:** regenerate the formula.

   ```bash
   git switch main && git pull && git switch -c Update-gyrseek-X.Y.Z
   support/update.sh X.Y.Z           # verifies hashes and attestations, rewrites Formula/gyrseek.rb
   git add Formula && git commit -m "Update gyrseek to X.Y.Z" && git push -u origin Update-gyrseek-X.Y.Z
   gh pr create --fill               # merge it once Tap tests passed and Lint are green
   ```

## When something goes wrong

- **A tag exists but the release did not publish:** if `verify` failed only because CI had not finished, re-run the failed jobs once it has (`gh run rerun <run-id> --failed`). If a draft release was left behind, delete it on the Releases page first.
- **A published release is wrong:** it cannot be edited or replaced. Fix it on `main`, raise the version and release again. Leave the bad one in place and say so in the next release notes; do not delete a tag that someone may have pinned.
- **`just tag` refuses:** read its message. It means `HEAD` is not `origin/main`, CI is not green, or the tag already exists.
- **Before tagging, check that everything the release needs is merged.** The tag is made on `origin/main` as it is at that moment.
