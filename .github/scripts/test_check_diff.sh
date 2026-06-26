#!/bin/bash
set -euo pipefail

export SKIP_FETCH=1
SCRIPT_PATH="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}/.github/scripts/check_diff.sh"

# 1. Setup isolated dummy git repository
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
cd "$TEST_DIR"
git init
git config user.name "Test"
git config user.email "test@example.com"
echo "base" >file.txt
git add file.txt
git commit -m "Base"
BASE_SHA=$(git rev-parse HEAD)

# 2. Test Scenario A: Diff Present
git checkout -b with-diff
echo "changed" >file.txt
git commit -am "Change"
# Run the actual script logic
has_diff=$(bash "$SCRIPT_PATH" "$BASE_SHA" "pull_request")
if [ "$has_diff" != "true" ]; then
	echo "::error::Smoke test A failed: Expected has_diff=true but got false"
	exit 1
fi
if [ ! -f pr_diff.sha256 ]; then
	echo "::error::Smoke test A failed: pr_diff.sha256 not generated"
	exit 1
fi

# 3. Test Scenario B: No Diff
git checkout "$BASE_SHA"
git checkout -b no-diff
rm -f pr_diff.sha256 pr_diff.txt
has_diff=$(bash "$SCRIPT_PATH" "$BASE_SHA" "pull_request")
if [ "$has_diff" != "false" ]; then
	echo "::error::Smoke test B failed: Expected has_diff=false but got true"
	exit 1
fi
if [ -f pr_diff.sha256 ]; then
	echo "::error::Smoke test B failed: pr_diff.sha256 should not be generated for no diff"
	exit 1
fi

# 4. Test Scenario C: Empty BASE_SHA
rm -f pr_diff.sha256 pr_diff.txt
set +e
has_diff=$(bash "$SCRIPT_PATH" "" "pull_request" 2>/dev/null)
exit_code=$?
set -e
if [ "$has_diff" != "false" ] || [ $exit_code -eq 0 ]; then
	echo "::error::Smoke test C failed: Expected has_diff=false and non-zero exit for empty BASE_SHA"
	exit 1
fi

# 5. Test Scenario D: Non-PR Event
rm -f pr_diff.sha256 pr_diff.txt
has_diff=$(bash "$SCRIPT_PATH" "$BASE_SHA" "push")
if [ "$has_diff" != "false" ]; then
	echo "::error::Smoke test D failed: Expected has_diff=false for push event"
	exit 1
fi

echo "Smoke tests passed!"
