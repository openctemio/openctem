#!/usr/bin/env python3
"""Documentation checks: broken relative links, non-English text, private addresses.

Usage: python3 scripts/docs_check.py [ROOT ...]

Scans every *.md file under each ROOT (default: the current directory) and fails when:
  - a relative link or image points to a file or directory that does not exist,
    or to a heading anchor that does not exist in the target Markdown file;
  - the text contains Vietnamese letters (documentation is English only);
  - the text contains a private IPv4 host address in 192.168.0.0/16 or 172.16.0.0/12,
    or an internal host name. 10.0.0.0/8 stays allowed because design documents use
    it to explain private-range handling (NAT, scan zones); network ranges in CIDR
    notation are allowed too.
    Use example.com and the documentation ranges 192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24 and 2001:db8::/32 instead.

A line that genuinely needs a private address (for example a page that explains how
private ranges are handled) can carry the marker `docs-check: allow-private` in an HTML
comment on the same line.
"""
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", "_site", "vendor", ".jekyll-cache", "changelog.d", "testdata"}
SKIP_FILES = {"CHANGELOG.md"}

VIETNAMESE = re.compile(r"[ăđơưĂĐƠƯẠ-ỹ]")
PRIVATE_IP = re.compile(
    r"(?<![\d.])(192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.]|/\d)"
)
INTERNAL_HOSTS = re.compile(r"manhnv\.com|\.internal\.openctem", re.IGNORECASE)
# The language's own name is allowed (for example in a list of console languages).
LANGUAGE_NAMES = re.compile("Tiếng Việt")
ALLOW_PRIVATE = "docs-check: allow-private"

LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
SPLIT_LINK = re.compile(r"^[^\[`]*\]\((?!\s)[^)\s]+\)")
FENCE = re.compile(r"^\s*(```|~~~)")


def slugify(heading):
    """GitHub/kramdown-style anchor for a heading."""
    text = re.sub(r"<[^>]+>", "", heading).strip().lower()
    text = re.sub(r"[`*_~]", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors_of(path, cache={}):
    if path not in cache:
        found = set()
        seen = {}
        in_fence = False
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if FENCE.match(line):
                        in_fence = not in_fence
                        continue
                    if in_fence:
                        continue
                    m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
                    if m:
                        slug = slugify(m.group(1))
                        n = seen.get(slug, 0)
                        seen[slug] = n + 1
                        found.add(slug if n == 0 else f"{slug}-{n}")
                    for a in re.findall(r"""(?:id|name)=["']([^"']+)["']""", line):
                        found.add(a)
                    for a in re.findall(r"\{:\s*#([\w-]+)\s*\}", line):
                        found.add(a)
        except OSError:
            pass
        cache[path] = found
    return cache[path]


def resolve(src, target):
    base = os.path.dirname(src)
    path = os.path.normpath(os.path.join(base, target))
    candidates = [path]
    if target.endswith("/") or os.path.isdir(path):
        candidates += [os.path.join(path, "index.md"), os.path.join(path, "README.md")]
    if not os.path.splitext(path)[1]:
        candidates += [path + ".md", path + ".html"]
    for c in candidates:
        if os.path.isfile(c):
            return c
    if os.path.isdir(path):
        return path
    return None


def check_file(path, errors):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if VIETNAMESE.search(LANGUAGE_NAMES.sub("", line)):
            errors.append(f"{path}:{lineno}: non-English (Vietnamese) text")
        if ALLOW_PRIVATE not in line:
            m = PRIVATE_IP.search(line)
            if m:
                errors.append(f"{path}:{lineno}: private IP address {m.group(1)} (use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24)")
            m = INTERNAL_HOSTS.search(line)
            if m:
                errors.append(f"{path}:{lineno}: internal host name {m.group(0)}")
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if SPLIT_LINK.search(line):
            errors.append(f"{path}:{lineno}: link text spans lines (keep [text](target) on one line)")
        targets = [m.group(1) for m in LINK.finditer(line)]
        targets += [m.group(1) for m in REF_DEF.finditer(line)]
        for target in targets:
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE) or target.startswith("//"):
                continue  # absolute URL, mailto:, etc.
            if "{{" in target or "{%" in target:
                continue  # Liquid
            file_part, _, anchor = target.partition("#")
            if target.startswith("/"):
                continue  # site-absolute permalink; checked by the Jekyll build
            dest = path if not file_part else resolve(path, file_part)
            if dest is None:
                errors.append(f"{path}:{lineno}: broken link {target}")
                continue
            if anchor and dest.endswith(".md") and anchor not in anchors_of(dest):
                errors.append(f"{path}:{lineno}: missing anchor #{anchor} in {os.path.relpath(dest)}")


def main(roots):
    errors = []
    count = 0
    for root in roots or ["."]:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".md") and name not in SKIP_FILES:
                    count += 1
                    check_file(os.path.join(dirpath, name), errors)
    for e in errors:
        print(e)
    print(f"docs-check: {count} files, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
