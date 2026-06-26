#!/usr/bin/env python3
import sys
import re
import os

MAX_REVIEW_BYTES = 60000
PARENS_REGEX = r"(?:[^)(]+|\([^)(]*\))*"
# LINK_TEXT_REGEX: supports up to 3 levels of nested brackets in link text.
# Expanded iteratively so depth is explicit and easy to audit.
# Depth-4+ nesting in realistic markdown is vanishingly rare; ReDoS risk rules
# out a fully recursive/parser approach. 3 levels is the documented limit.
_LINK_TEXT = r"[^\[\]]*"
for _ in range(3):
    _LINK_TEXT = rf"(?:[^\[\]]|\[{_LINK_TEXT}\])*"
LINK_TEXT_REGEX = _LINK_TEXT
del _LINK_TEXT


def _defang_url(m):
    url = m.group(0)
    punct_match = re.search(r"[.,;:!?()\'\"*_~]+$", url)
    punct = punct_match.group(0) if punct_match else ""
    if punct:
        url = url[: -len(punct)]

    if "://" in url:
        return url.replace("://", "[://]") + punct
    return url.replace("www.", "www[.]", 1) + punct


def strip_markdown_links(text):
    """
    Strips markdown links and neutralizes images to prevent phishing.

    >>> strip_markdown_links('This is a [phishing link](https://evil.com) in text.')
    'This is a phishing link in text.'

    >>> strip_markdown_links('Nested [click](https://evil.com/path?(a=b)) here.')
    'Nested click here.'

    >>> strip_markdown_links('Image ![](https://evil.com/pixel.gif) bypass.')
    'Image [IMAGE STRIPPED] bypass.'

    >>> strip_markdown_links('Ref image ![][ref]')
    'Ref image [IMAGE STRIPPED]'

    >>> strip_markdown_links('[1]: ftp://evil.com/payload')
    ''
    >>> strip_markdown_links('Bare url https://evil.com/path.js here')
    'Bare url https[://]evil.com/path.js here'
    >>> strip_markdown_links('www.evil-c2.com is a phishing site')
    'www[.]evil-c2.com is a phishing site'
    >>> strip_markdown_links('Link with nested bracket [click [here]](https://evil.com)')
    'Link with nested bracket click [here]'
    >>> strip_markdown_links('[click [nested [deep]]](https://evil.com)')
    'click [nested [deep]]'
    >>> strip_markdown_links('Email autolink <user@host.com> in text')
    'Email autolink [EMAIL STRIPPED] in text'
    >>> strip_markdown_links('IPv6 bare url http://[::1]:8080/path here')
    'IPv6 bare url http[://][::1]:8080/path here'
    >>> strip_markdown_links('Ping @user and @org/team-name for review')
    'Ping @[user] and @[org/team-name] for review'
    >>> strip_markdown_links('See https://evil.com for details.')
    'See https[://]evil.com for details.'
    """
    # 0. Strip explicitly formatted image embeds (handles nested parentheses and empty alt text):
    text = re.sub(
        rf"!\[{LINK_TEXT_REGEX}\]\({PARENS_REGEX}\)", "[IMAGE STRIPPED]", text
    )
    text = re.sub(rf"!\[{LINK_TEXT_REGEX}\]\[[^\]]*\]", "[IMAGE STRIPPED]", text)

    # 1. Strip inline links: [Click Here](https://evil.com) -> Click Here
    #    LINK_TEXT_REGEX allows one level of nested brackets to prevent bypass via [text [inner]](url)
    text = re.sub(rf"\[({LINK_TEXT_REGEX})\]\({PARENS_REGEX}\)", r"\1", text)

    # 2. Strip reference links: [Click Here][1] -> Click Here
    text = re.sub(rf"\[({LINK_TEXT_REGEX})\]\[[^\]]*\]", r"\1", text)

    # 3. Strip reference link definitions: [1]: https://evil.com (bounds to line end, any scheme)
    #    Leading whitespace (up to 3 spaces per CommonMark) is allowed before the label.
    text = re.sub(r"^[ \t]*\[[^\]]*\]:\s*\S+[^\n]*\n?", "", text, flags=re.MULTILINE)

    # 4. Strip autolinks: <ftp://evil.com> -> [LINK STRIPPED], <user@host> -> [EMAIL STRIPPED]
    text = re.sub(r"<[a-zA-Z][a-zA-Z0-9+.-]*://[^>]+>", "[LINK STRIPPED]", text)
    text = re.sub(r"<[^\s@>]+@[^\s@>]+>", "[EMAIL STRIPPED]", text)

    # 5. Defang bare URLs globally:
    #    - scheme URLs: https://evil.com -> https[://]evil.com
    #    - GFM www. bare domains: www.evil.com -> www[.]evil.com
    text = re.sub(
        r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://|www\.)[^\s<>]+",
        _defang_url,
        text,
    )

    # 6. Defang GitHub mentions: @user -> @[user], @org/team -> @[org/team]
    #    Prevents prompt-injected LLM outputs from causing notification spam via github-actions[bot].
    text = re.sub(r"(?<!\w)@(\w[\w/-]*)", r"@[\1]", text)

    return text


def sanitize(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: {input_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(input_path)

    with open(input_path, "rb") as f:
        # Read up to MAX_REVIEW_BYTES to truncate
        raw_bytes = f.read(MAX_REVIEW_BYTES)
        text = raw_bytes.decode("utf-8", errors="ignore")

    # Append truncation warning if necessary
    if file_size > MAX_REVIEW_BYTES:
        text += f"\n\n*(Review truncated at {MAX_REVIEW_BYTES} bytes; full output is {file_size} bytes.)*"

    text = strip_markdown_links(text)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: sanitize_review.py <input_file> <output_file>")
    sanitize(sys.argv[1], sys.argv[2])
