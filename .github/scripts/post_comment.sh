#!/bin/bash
set -euo pipefail

# Required environment variables:
# GH_TOKEN, REPO_NAME, HEAD_SHA
# PR_NUMBER (optional, will fetch if missing)

if [ ! -f "consolidated_gyrseek_review.md" ]; then
	echo "::error::Review artifact missing. Failing closed." >&2
	exit 1
fi

if [ -z "$REPO_NAME" ]; then
	echo "::error::REPO_NAME is empty" >&2
	exit 1
fi

if ! echo "$HEAD_SHA" | grep -qE '^[0-9a-f]{40}$'; then
	echo "::error::HEAD_SHA is malformed or missing: '$HEAD_SHA'" >&2
	exit 1
fi

if [ -z "${PR_NUMBER:-}" ] || [ "$PR_NUMBER" = "null" ]; then
	# Securely fetch the PR number using the workflow_run head SHA
	PR_NUMBER=$(gh api \
		-H "Accept: application/vnd.github+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		/repos/"$REPO_NAME"/commits/"$HEAD_SHA"/pulls \
		--jq '.[0].number' || echo "")
fi

if [ -z "$PR_NUMBER" ] || [ "$PR_NUMBER" = "null" ]; then
	echo "::error::Could not determine PR number for commit $HEAD_SHA. Failing closed." >&2
	exit 1
fi

source_file="consolidated_gyrseek_review.md"
stripped_file=""
sanitized_file=""

cleanup() {
	[ -n "${stripped_file:-}" ] && rm -f "$stripped_file"
	[ -n "${sanitized_file:-}" ] && rm -f "$sanitized_file"
}
trap cleanup EXIT

if [ ! -s "$source_file" ]; then
	echo "::error::Review output is empty; failing closed." >&2
	exit 1
fi

# 1. Truncate (if over 60,000 bytes) and Strip Markdown Links (Phishing Mitigation)
# This prevents prompt-injected URLs from passing through cmark --safe as clickable links.
# (Explicitly hiding GH_TOKEN from the python subprocess)
stripped_file="${source_file}.stripped"
env -u GH_TOKEN python3 .github/scripts/sanitize_review.py "$source_file" "$stripped_file" ||
	{
		echo "::error::sanitize_review.py failed. Failing closed." >&2
		exit 1
	}

if [ ! -s "$stripped_file" ]; then
	echo "::error::Stripped review output is empty — all content was flagged as unsafe. Failing closed." >&2
	exit 1
fi

# 2. Sanitize: securely strip dangerous links and raw HTML using cmark
sanitized_file="${source_file}.sanitized"
env -u GH_TOKEN cmark --safe --to commonmark "$stripped_file" >"$sanitized_file" ||
	{
		echo "::error::cmark failed to sanitize review output. Failing closed." >&2
		exit 1
	}

if [ ! -s "$sanitized_file" ]; then
	echo "::error::Sanitized review output is empty; failing closed." >&2
	exit 1
fi

gh pr comment "$PR_NUMBER" \
	--body-file "$sanitized_file" \
	--repo "$REPO_NAME"
