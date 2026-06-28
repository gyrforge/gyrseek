#!/usr/bin/env python3
import sys
import os
import tempfile
import re


def cap_ledger(filepath="review_ledger.md"):
    try:
        if not os.path.exists(filepath):
            return

        with open(filepath, "r") as f:
            content = f.read()

        # Split strictly on the exact header format followed by the review title to prevent false splits
        reviews = re.split(
            r"\n(?==== REVIEW FROM RUN(?: \d+)? ===\n(?i:# consolidated review))",
            content,
        )

        if len(reviews) > 6:
            kept = reviews[-5:]

            dir_name = os.path.dirname(os.path.abspath(filepath))
            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tf:
                # The first element is pre-text (or empty), we just want the last 5
                tf.write(reviews[0] + "".join(kept))
                temp_name = tf.name
            os.replace(temp_name, filepath)
    except Exception as e:
        print(f"Failed to cap ledger: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cap_ledger()
