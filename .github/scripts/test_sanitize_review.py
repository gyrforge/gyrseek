#!/usr/bin/env python3
import sys
import doctest
import os
import tempfile
import contextlib

# Add the script's directory to sys.path so we can import sanitize_review
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

import sanitize_review


@contextlib.contextmanager
def _tmpfiles():
    """Context manager yielding (inp_path, out_path); cleans both on exit even if unlink raises."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".md", delete=False) as inp:
        inp_path = inp.name
    out_path = inp_path + ".out"
    try:
        yield inp_path, out_path
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(inp_path)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(out_path)


def test_sanitize_roundtrip():
    """Basic round-trip: sanitize writes stripped content to output file."""
    with _tmpfiles() as (inp_path, out_path):
        with open(inp_path, "wb") as f:
            f.write(b"See [evil](https://evil.com) for details.")
        sanitize_review.sanitize(inp_path, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            result = f.read()
        assert result == "See evil for details.", f"Unexpected output: {result!r}"


def test_sanitize_truncation():
    """Files over MAX_REVIEW_BYTES are truncated and a warning is appended.
    Verifies: truncation warning present, output shorter than input, leading bytes intact.
    """
    known_prefix = "X" * 100
    filler = b"X" * 100 + b"A" * (sanitize_review.MAX_REVIEW_BYTES - 100)
    with _tmpfiles() as (inp_path, out_path):
        with open(inp_path, "wb") as f:
            f.write(filler + b" more content beyond limit")
        sanitize_review.sanitize(inp_path, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            result = f.read()
        assert "Review truncated" in result, "Truncation warning missing"
        assert len(result) < len(filler) + 100, "Output should be shorter than input"
        assert result.startswith(
            known_prefix
        ), f"Leading bytes corrupted: {result[:20]!r}"


def test_sanitize_utf8_boundary():
    """Partial multi-byte UTF-8 at the read boundary is silently dropped (errors='ignore').
    File is also over MAX_REVIEW_BYTES so the truncation path is exercised simultaneously.
    """
    # MAX_REVIEW_BYTES-1 valid bytes + 0xc3 (start of 2-byte seq) + extra bytes beyond the limit.
    # read() stops at MAX_REVIEW_BYTES, capturing the partial 0xc3 as the last byte.
    content = b"B" * (sanitize_review.MAX_REVIEW_BYTES - 1) + b"\xc3" + b"extra"
    with _tmpfiles() as (inp_path, out_path):
        with open(inp_path, "wb") as f:
            f.write(content)
        # Must not raise; errors='ignore' drops the partial byte
        sanitize_review.sanitize(inp_path, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            result = f.read()
        assert "\xc3" not in result, "Partial byte should have been ignored"
        assert "Review truncated" in result, "Truncation warning should be appended"


def test_sanitize_all_links_stripped():
    """When all content is markdown links, sanitize() produces empty/whitespace-only output
    without crashing. Downstream bash guards ([ ! -s ]) catch the empty file."""
    with _tmpfiles() as (inp_path, out_path):
        with open(inp_path, "wb") as f:
            f.write(b"[evil](https://evil.com) [also evil](https://c2.com)")
        sanitize_review.sanitize(inp_path, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            result = f.read()
        # Links are stripped; only whitespace/empty remains — no crash
        assert result == "evil also evil", f"Unexpected: {result!r}"


def test_sanitize_reference_definitions_only():
    """When input is solely reference definitions, sanitize() produces empty output."""
    with _tmpfiles() as (inp_path, out_path):
        with open(inp_path, "wb") as f:
            f.write(b"[1]: https://evil.com\n[2]: https://c2.com\n")
        sanitize_review.sanitize(inp_path, out_path)
        with open(out_path, "r", encoding="utf-8") as f:
            result = f.read()
        assert result == "", f"Expected empty string, got: {result!r}"


def test_sanitize_empty_input():
    """When input is exactly 0 bytes, sanitize() writes 0 bytes."""
    with _tmpfiles() as (inp_path, out_path):
        open(inp_path, "wb").close()
        sanitize_review.sanitize(inp_path, out_path)
        assert os.path.getsize(out_path) == 0, "Output file must be 0 bytes"


def test_sanitize_missing_input():
    """sanitize() calls sys.exit(1) when the input file does not exist."""
    with _tmpfiles() as (_, out_path):
        try:
            sanitize_review.sanitize("/nonexistent/path/review.md", out_path)
            assert False, "Expected sys.exit"
        except SystemExit as e:
            assert e.code == 1, f"Expected exit code 1, got {e.code!r}"


if __name__ == "__main__":
    # 1. Run doctests for strip_markdown_links
    res = doctest.testmod(sanitize_review)
    if res.attempted == 0:
        sys.exit("Error: 0 tests run in sanitize_review.py. Doctest regression!")
    if res.failed > 0:
        sys.exit(1)
    print(f"Doctests: {res.attempted} tests passed in sanitize_review.py")

    # 2. Run sanitize() unit tests
    tests = [
        test_sanitize_roundtrip,
        test_sanitize_truncation,
        test_sanitize_utf8_boundary,
        test_sanitize_all_links_stripped,
        test_sanitize_reference_definitions_only,
        test_sanitize_empty_input,
        test_sanitize_missing_input,
    ]
    for test in tests:
        test()
        print(f"  PASS: {test.__name__}")

    print(f"All {res.attempted} doctests + {len(tests)} unit tests passed.")
