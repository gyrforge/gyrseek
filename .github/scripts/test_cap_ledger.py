#!/usr/bin/env python3
import os
import tempfile
import sys
import contextlib
from unittest.mock import patch
from cap_ledger import cap_ledger


@contextlib.contextmanager
def _tmpfile():
    """Context manager yielding filepath; cleans on exit even if unlink raises."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        filepath = tf.name
    try:
        yield filepath
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(filepath)


def test_empty_file():
    """Empty file should remain empty."""
    with _tmpfile() as filepath:
        with open(filepath, "w") as f:
            f.write("")
        cap_ledger(filepath)
        with open(filepath, "r") as f:
            assert f.read() == ""


def test_six_reviews():
    """File with 6 reviews should be capped to 5."""
    with _tmpfile() as filepath:
        content = (
            "\n=== REVIEW FROM RUN 1 ===\n# Consolidated Review\nReview 1\n"
            "\n=== REVIEW FROM RUN 2 ===\n# Consolidated Review\nReview 2\n"
            "\n=== REVIEW FROM RUN 3 ===\n# Consolidated Review\nReview 3\n"
            "\n=== REVIEW FROM RUN 4 ===\n# Consolidated Review\nReview 4\n"
            "\n=== REVIEW FROM RUN 5 ===\n# Consolidated Review\nReview 5\n"
            "\n=== REVIEW FROM RUN 6 ===\n# Consolidated Review\nReview 6\n"
        )
        with open(filepath, "w") as f:
            f.write(content)
        cap_ledger(filepath)
        with open(filepath, "r") as f:
            result = f.read()
        assert "Review 1" not in result
        assert "Review 2" in result
        assert "Review 6" in result
        assert result.count("=== REVIEW FROM RUN") == 5


def test_five_reviews():
    """File with 5 reviews should not be truncated."""
    with _tmpfile() as filepath:
        content = (
            "\n=== REVIEW FROM RUN 1 ===\n# Consolidated Review\nReview 1\n"
            "\n=== REVIEW FROM RUN 2 ===\n# Consolidated Review\nReview 2\n"
            "\n=== REVIEW FROM RUN 3 ===\n# Consolidated Review\nReview 3\n"
            "\n=== REVIEW FROM RUN 4 ===\n# Consolidated Review\nReview 4\n"
            "\n=== REVIEW FROM RUN 5 ===\n# Consolidated Review\nReview 5\n"
        )
        with open(filepath, "w") as f:
            f.write(content)
        cap_ledger(filepath)
        with open(filepath, "r") as f:
            result = f.read()
        assert result.count("=== REVIEW FROM RUN") == 5
        assert "Review 1" in result
        assert "Review 5" in result


def test_delimiter_collision():
    """Embedded '=== REVIEW FROM RUN' in text should not cause a split."""
    with _tmpfile() as filepath:
        content = (
            "\n=== REVIEW FROM RUN 1 ===\n# Consolidated Review\nReview 1\n"
            "\n=== REVIEW FROM RUN 2 ===\n# Consolidated Review\nReview 2 has a mention of\n=== REVIEW FROM RUN 999 ===\non its own line.\n"
            "\n=== REVIEW FROM RUN 3 ===\n# Consolidated Review\nReview 3\n"
            "\n=== REVIEW FROM RUN 4 ===\n# Consolidated Review\nReview 4\n"
            "\n=== REVIEW FROM RUN 5 ===\n# Consolidated Review\nReview 5\n"
            "\n=== REVIEW FROM RUN 6 ===\n# Consolidated Review\nReview 6\n"
        )
        with open(filepath, "w") as f:
            f.write(content)
        cap_ledger(filepath)
        with open(filepath, "r") as f:
            result = f.read()
        assert "Review 1" not in result
        assert "Review 2" in result
        assert "=== REVIEW FROM RUN 999 ===" in result
        assert (
            result.count("=== REVIEW FROM RUN") == 6
        )  # 5 actual headers + 1 inline mention


def test_error_handling():
    """Test that OSError from file operations triggers sys.exit(1)."""
    with _tmpfile() as filepath:
        with open(filepath, "w") as f:
            f.write("test content")
        with patch("builtins.open", side_effect=OSError("Mock IO error")):
            try:
                cap_ledger(filepath)
                assert False, "cap_ledger did not exit on OSError"
            except SystemExit as e:
                assert e.code == 1


if __name__ == "__main__":
    test_empty_file()
    test_five_reviews()
    test_six_reviews()
    test_delimiter_collision()
    test_error_handling()
    print("All tests passed in cap_ledger.py")
