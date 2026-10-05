#!/usr/bin/env python3
"""Changelog fragments for the OpenCTEM API.

Every pull request used to add its entry at the top of api/CHANGELOG.md, right
under "## Unreleased". Any two open pull requests therefore edited the same
lines and conflicted, and a merge queue with many entries turned that into a
steady stream of dequeued pull requests (and once, conflict markers committed
to develop).

Unreleased entries now live one file per change in api/changelog.d/. No two
pull requests touch the same file. The release folds them into CHANGELOG.md
once, in a single commit.

Usage:
  changelog.py check                validate fragments; refuse an entry written
                                    into CHANGELOG.md's Unreleased section and
                                    conflict markers in any tracked text file
  changelog.py preview              print the Unreleased section assembled from
                                    the fragments
  changelog.py release VERSION      fold the fragments into CHANGELOG.md under
                                    "## VERSION (YYYY-MM-DD)" and delete them

Fragment format (api/changelog.d/<short-slug>.md):

  ### <Category>: <one-line title>

  - what changed, for whom, and any upgrade note

A fragment may hold several "### " sections. Categories, in release order:
Security, Behaviour change, Removed, Deprecated, Added, Changed, Fixed.
"""
from __future__ import annotations

import datetime as _dt
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "api"
CHANGELOG = API / "CHANGELOG.md"
FRAGMENTS = API / "changelog.d"

CATEGORIES = [
    "Security",
    "Behaviour change",
    "Removed",
    "Deprecated",
    "Added",
    "Changed",
    "Fixed",
]
HEADING = re.compile(r"^### (?P<cat>[^:\n]+?)(?: \([^)]*\))?: (?P<title>\S.*)$")
MARKER = re.compile(r"^(<{7}|>{7})( |$)|^\|{7}( |$)")
UNRELEASED = "## Unreleased"
FRAGMENT_NOTE = (
    "Unreleased changes are kept one file per change in "
    "[`changelog.d/`](changelog.d/README.md) and folded in here at release."
)
TEXT_SUFFIXES = {
    ".md", ".go", ".ts", ".tsx", ".js", ".jsx", ".json", ".yml", ".yaml",
    ".sql", ".sh", ".py", ".toml", ".css", ".html", ".txt", ".mod",
}


def fragments() -> list[pathlib.Path]:
    if not FRAGMENTS.is_dir():
        return []
    return sorted(p for p in FRAGMENTS.glob("*.md") if p.name != "README.md")


def sections(text: str) -> list[tuple[str, str]]:
    """Split a fragment into (category, section text) pairs."""
    out: list[tuple[str, str]] = []
    cur: list[str] = []
    cat = ""
    for line in text.splitlines():
        if line.startswith("### "):
            if cur:
                out.append((cat, "\n".join(cur).rstrip() + "\n"))
            m = HEADING.match(line)
            cat = m.group("cat") if m else ""
            cur = [line]
        elif cur:
            cur.append(line)
        elif line.strip():
            out.append(("", line))  # text before the first heading
    if cur:
        out.append((cat, "\n".join(cur).rstrip() + "\n"))
    return out


def validate() -> list[str]:
    errors: list[str] = []
    for p in fragments():
        rel = p.relative_to(ROOT)
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.md", p.name):
            errors.append(f"{rel}: name must be lowercase letters, digits, '.', '_' or '-'")
        text = p.read_text(encoding="utf-8")
        secs = sections(text)
        if not secs:
            errors.append(f"{rel}: empty; add a '### <Category>: <title>' section")
        for cat, body in secs:
            if not cat:
                errors.append(f"{rel}: every section starts with '### <Category>: <title>' "
                              f"(categories: {', '.join(CATEGORIES)})")
            elif cat not in CATEGORIES:
                errors.append(f"{rel}: unknown category {cat!r} "
                              f"(use one of: {', '.join(CATEGORIES)})")
            elif len(body.strip().splitlines()) < 2:
                errors.append(f"{rel}: section '{body.splitlines()[0]}' has no text")
    return errors


def conflict_markers() -> list[str]:
    files = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode().split("\0")
    hits: list[str] = []
    for name in files:
        if not name or pathlib.PurePath(name).suffix not in TEXT_SUFFIXES:
            continue
        path = ROOT / name
        try:
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if MARKER.match(line):
                    hits.append(f"{name}:{i}: merge-conflict marker")
                    break
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
    return hits


def unreleased_body(text: str) -> str:
    start = text.find(UNRELEASED)
    if start < 0:
        return ""
    rest = text[start + len(UNRELEASED):]
    m = re.search(r"(?m)^## ", rest)
    return rest[: m.start()] if m else rest


def entries_in_unreleased() -> bool:
    """True when CHANGELOG.md's Unreleased section holds an entry ("### ")."""
    text = CHANGELOG.read_text(encoding="utf-8")
    return bool(re.search(r"(?m)^### ", unreleased_body(text)))


def assemble() -> str:
    by_cat: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    for p in fragments():
        for cat, body in sections(p.read_text(encoding="utf-8")):
            by_cat.setdefault(cat, []).append(body)
    return "\n".join(b for c in by_cat for b in by_cat[c])


def cmd_check(argv: list[str]) -> int:
    errors = validate() + conflict_markers()
    if entries_in_unreleased():
        errors.append(
            "api/CHANGELOG.md: an entry was written under Unreleased. Put it in "
            "api/changelog.d/<short-slug>.md instead (see api/changelog.d/README.md)."
        )
    for e in errors:
        print(f"::error::{e}" if "GITHUB_ACTIONS" in os.environ else e)
    if not errors:
        print(f"changelog: {len(fragments())} fragment(s) OK, no conflict markers")
    return 1 if errors else 0


def cmd_preview(_: list[str]) -> int:
    print(UNRELEASED + "\n")
    print(assemble() or "_No unreleased changes._\n")
    return 0


def cmd_release(argv: list[str]) -> int:
    if not argv or not re.fullmatch(r"v\d+\.\d+\.\d+", argv[0]):
        print("usage: changelog.py release vX.Y.Z", file=sys.stderr)
        return 2
    errors = validate()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.find(UNRELEASED)
    if start < 0:
        print("api/CHANGELOG.md has no '## Unreleased' heading", file=sys.stderr)
        return 1
    head = text[: start + len(UNRELEASED)]
    rest = text[start + len(UNRELEASED):]
    m = re.search(r"(?m)^## ", rest)
    older = rest[m.start():] if m else ""
    date = _dt.date.today().isoformat()
    body = assemble().rstrip() or "No notable changes."
    CHANGELOG.write_text(
        f"{head}\n\n{FRAGMENT_NOTE}\n\n## {argv[0]} ({date})\n\n{body}\n\n{older}".rstrip() + "\n",
        encoding="utf-8",
    )
    for p in fragments():
        p.unlink()
    print(f"folded into CHANGELOG.md as {argv[0]}")
    return 0


def main(argv: list[str]) -> int:
    cmds = {"check": cmd_check, "preview": cmd_preview, "release": cmd_release}
    if not argv or argv[0] not in cmds:
        print(__doc__, file=sys.stderr)
        return 2
    return cmds[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
