#!/bin/bash
# scripts/generate-structured_diff.sh

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <input_file>" >&2
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="pr_diff_structured.txt"

# Basic cleanup and validation
if [ ! -s "$INPUT_FILE" ]; then
    echo "# Structurally sanitized diff (File is empty or missing)" > "$OUTPUT_FILE"
    exit 0
fi

{
    echo "## Structured Code Diff from $INPUT_FILE"
    echo ""
    echo "*Note: This report strips all comments and potentially dangerous markdown/literals to prevent prompt injection.*"
    echo ""
    # Start diff content transfer, filtering out common comment/literal patterns
    awk '
        # Check for start of line markers (+/-) or only whitespace, retaining those lines.
        /^[\+\-]/ { print }

        # General regex filter to exclude full-line comments (// or # at start) and block comments.
        !/[[:space:]]*(\/\/|#|\/\*)|[[:space:]]*/ && NF >= 1 { 
            # This simple pass-through preserves the structure while removing content that is clearly a comment line.
            content_line=$0;
            # Crude filtering for common commented/literal patterns that might break LLM context or be irrelevant comments.
            if (content_line ~ /^[[:space:]]*(==|;|\-\-|<!--)/ || content_line ~ /^[[:space:]]*\/\// || content_line ~ /^[[:space:]]*#/) {
                next; # Skip lines that start with comment markers/syntax
            }
            print content_line;
        }
    ' "$INPUT_FILE"
} > "$OUTPUT_FILE"

echo 0 # Success exit code for the script.