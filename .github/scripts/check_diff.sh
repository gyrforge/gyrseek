#!/bin/bash
set -euo pipefail

BASE_SHA="${1:-}"
EVENT_NAME="${2:-pull_request}"
SKIP_FETCH="${SKIP_FETCH:-0}"

if [ "$SKIP_FETCH" != "1" ]; then
	if ! git fetch --unshallow >fetch-err.log 2>&1; then
		echo "::warning::Git fetch produced errors/warnings:" >&2
		cat fetch-err.log >&2
	fi
fi

if [ "$EVENT_NAME" != "pull_request" ]; then
	# Only pull_request is supported. Returning false skips diff generation.
	echo "false"
	exit 0
fi

if [ -z "$BASE_SHA" ]; then
	echo "::error::BASE_SHA is empty but event is pull_request" >&2
	echo "false"
	exit 1
fi

# Use accurate method to pull up-to-date diff content
if ! git diff "$BASE_SHA"...HEAD >pr_diff.txt 2>diff-err.log; then
	echo "::warning::git diff failed:" >&2
	cat diff-err.log >&2
	echo "(no diff)" >pr_diff.txt
elif [ -s diff-err.log ]; then
	echo "::warning::git diff produced stderr output:" >&2
	cat diff-err.log >&2
fi

if [ ! -s pr_diff.txt ] || [ "$(cat pr_diff.txt)" = "(no diff)" ] || [ -z "$(cat pr_diff.txt)" ]; then
	echo "false"
else
	sha256sum pr_diff.txt >pr_diff.sha256
	echo "true"
fi
