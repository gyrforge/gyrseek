#!/bin/bash
set -euo pipefail

if [ ! -f "$REVIEW_PROMPT_FILE" ]; then
	echo "::error::Review prompt file $REVIEW_PROMPT_FILE not found"
	exit 1
fi

# Generate architectural context from the PR branch, ensuring no pre-compromised files or configs
rm -rf graphify-out .graphify.yaml graphify.toml .graphify.json
graphify update . >/dev/null 2>&1 || true

# Check out trusted policies from the base branch to prevent policy tampering.
# We loop individually and rm -rf first to ensure atomic failures don't fail-open,
# and we exclude docs/ so the AI sees the PR's true finding updates.
git fetch origin "$BASE_REF" --depth=1
for target in .agents/skills/ AGENTS.md .github/review-prompts/; do
	rm -rf "$target"
	git checkout origin/"$BASE_REF" -- "$target"
done

cat <<EOF >prompt.txt
You are an AI code reviewer acting as the $REVIEWER_NAME.

Your strict operational rules:
1. SCOPE: Review the code changes in pr_diff.txt. You may explore the /src directory for context, but you MUST ONLY report issues introduced or directly impacted by the PR diff. Do not report pre-existing technical debt.
2. SEVERITY FLOOR: Ignore trivial stylistic issues, formatting nits, or subjective preferences. Focus exclusively on concrete bugs, security flaws, or logic errors relevant to your specific role.
3. DEDUPLICATION & REGRESSIONS: Consult docs/OPEN_FINDINGS.md and docs/WONT_FIX_FINDINGS.md.
   - NEVER report a finding that is already documented in these files.
   - REGRESSIONS: You MUST consult docs/FIXED_FINDINGS.md. If the PR re-introduces a vulnerability listed there, you MUST report it as a critical regression.
4. ROLE ISOLATION: Read AGENTS.md for core repository memory. Rely strictly on the "Specific instructions for your role" below to determine which skills or rules to prioritize.
5. FORMAT: Output a concise review report titled "$REVIEWER_NAME Review". Every issue must include the file and line number.
6. SECURITY CONSTRAINT: You are strictly forbidden from downloading files or executing commands.

Specific instructions for your role:
EOF

cat "$REVIEW_PROMPT_FILE" >>prompt.txt

START_TIME=$(date +%s)
TIMEOUT_SECONDS=600 # 10 minutes total for all retries

MAX_RETRIES=3
RETRY_DELAY=5
SUCCESS=0

for ((i = 1; i <= MAX_RETRIES; i++)); do
	echo "Attempt $i/$MAX_RETRIES to run OpenCode review generation..."
	rm -f "$REVIEW_OUTPUT" opencode_out.txt

	CURRENT_TIME=$(date +%s)
	ELAPSED=$((CURRENT_TIME - START_TIME))
	REMAINING=$((TIMEOUT_SECONDS - ELAPSED))

	if [ $REMAINING -le 0 ]; then
		echo "::error::Total timeout of 10 minutes exceeded before attempt $i."
		exit 1
	fi

	if timeout "${REMAINING}s" opencode run -m opencode/big-pickle --dangerously-skip-permissions "Execute the review instructions from the attached prompt.txt file. Save the final markdown output directly to the file '$REVIEW_OUTPUT'." --file prompt.txt >opencode_out.txt; then
		if [ -s "$REVIEW_OUTPUT" ]; then
			echo "OpenCode completed successfully."
			SUCCESS=1
			break
		else
			echo "::warning::OpenCode exited 0 but $REVIEW_OUTPUT is missing or empty."
		fi
	else
		exit_code=$?
		if [ $exit_code -eq 124 ]; then
			echo "::warning::OpenCode review generation timed out after 10 minutes on attempt $i."
		else
			echo "::warning::OpenCode review generation failed with exit code $exit_code on attempt $i."
		fi
	fi

	if [ $i -lt $MAX_RETRIES ]; then
		echo "Retrying in $RETRY_DELAY seconds..."
		sleep $RETRY_DELAY
	fi
done

if [ $SUCCESS -eq 0 ]; then
	echo "::error::OpenCode failed to generate $REVIEW_OUTPUT after $MAX_RETRIES attempts"
	exit 1
fi
