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
  changelog.py archive HEADING LIST fold only the fragments named in LIST (one
                                    file name per line) into CHANGELOG.md as
                                    "## HEADING", below every existing section,
                                    and delete them (one-off catch-up)
  changelog.py release VERSION [--labels F]
                                    fold the fragments into CHANGELOG.md under
                                    "## VERSION (YYYY-MM-DD)" and delete them

--labels F names a JSON file {"<fragment file>": ["notes:migration", ...]}
(.github/scripts/release/fragment-labels.sh writes it from the labels of the
pull requests that added the fragments). With it, an "Upgrade notes" block at
the top of the section lists the fragments under the operator headings below,
so a reader sees the migrations, destructive migrations, identity changes and
API contract changes before the categories. Without it nothing changes.

Fragment format (api/changelog.d/<short-slug>.md):

  ### <Category>: <one-line title>

  - what changed, for whom, and any upgrade note

A fragment may hold several "### " sections. Categories, in release order:
Security, Behaviour change, Removed, Deprecated, Added, Changed, Fixed.
"""
from __future__ import annotations

import datetime as _dt
import json
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
# Pull-request labels (.github/scripts/pr-labels.py) that give a fragment an
# operator heading, in the order the headings print.
OPERATOR_HEADINGS = [
    ("notes:destructive-migration", "Destructive migrations (read before upgrading)"),
    ("notes:migration", "Database migrations"),
    ("notes:identity", "Finding identity and fingerprint changes"),
    ("notes:api-contract", "API contract changes"),
]
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


def assemble(paths: list[pathlib.Path] | None = None) -> str:
    by_cat: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    for p in fragments() if paths is None else paths:
        for cat, body in sections(p.read_text(encoding="utf-8")):
            by_cat.setdefault(cat, []).append(body)
    return "\n".join(b for c in by_cat for b in by_cat[c])


def read_labels(argv: list[str]) -> tuple[dict[str, list[str]] | None, list[str]]:
    """Pull `--labels FILE` out of argv."""
    if "--labels" not in argv:
        return None, argv
    i = argv.index("--labels")
    if i + 1 >= len(argv):
        raise SystemExit("--labels needs a file")
    data = json.loads(pathlib.Path(argv[i + 1]).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("--labels file must be a JSON object {fragment: [labels]}")
    return data, argv[:i] + argv[i + 2:]


def operator_block(labels: dict[str, list[str]] | None, paths: list[pathlib.Path] | None = None) -> str:
    """The Upgrade notes block: fragment section titles under operator headings."""
    if not labels:
        return ""
    chosen = fragments() if paths is None else paths
    lines: list[str] = []
    for label, heading in OPERATOR_HEADINGS:
        items: list[str] = []
        for p in chosen:
            if label not in labels.get(p.name, []):
                continue
            for cat, body in sections(p.read_text(encoding="utf-8")):
                if cat:
                    items.append(f"- {body.splitlines()[0][4:]} (`{p.name}`)")
        if items:
            lines += [f"#### {heading}", "", *items, ""]
    if not lines:
        return ""
    return "\n".join(["### Upgrade notes", "", *lines]).rstrip() + "\n\n"


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


def cmd_preview(argv: list[str]) -> int:
    labels, _ = read_labels(argv)
    print(UNRELEASED + "\n")
    print(operator_block(labels) + assemble() if fragments() else "_No unreleased changes._\n")
    return 0


def cmd_release(argv: list[str]) -> int:
    labels, argv = read_labels(argv)
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
    body = (operator_block(labels) + assemble()).rstrip() or "No notable changes."
    CHANGELOG.write_text(
        f"{head}\n\n{FRAGMENT_NOTE}\n\n## {argv[0]} ({date})\n\n{body}\n\n{older}".rstrip() + "\n",
        encoding="utf-8",
    )
    for p in fragments():
        p.unlink()
    print(f"folded into CHANGELOG.md as {argv[0]}")
    return 0


def cmd_archive(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[0].strip():
        print("usage: changelog.py archive HEADING LISTFILE", file=sys.stderr)
        return 2
    heading = argv[0].strip()
    names = [n.strip() for n in pathlib.Path(argv[1]).read_text(encoding="utf-8").splitlines() if n.strip()]
    known = {p.name: p for p in fragments()}
    missing = [n for n in names if n not in known]
    if missing:
        print("not a fragment: " + ", ".join(missing), file=sys.stderr)
        return 1
    chosen = sorted((known[n] for n in set(names)), key=lambda p: p.name)
    errors = validate()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    text = CHANGELOG.read_text(encoding="utf-8")
    if UNRELEASED not in text:
        print("api/CHANGELOG.md has no '## Unreleased' heading", file=sys.stderr)
        return 1
    body = assemble(chosen).rstrip() or "No notable changes."
    CHANGELOG.write_text(f"{text.rstrip()}\n\n## {heading}\n\n{body}\n", encoding="utf-8")
    for p in chosen:
        p.unlink()
    print(f"archived {len(chosen)} fragment(s) into CHANGELOG.md as {heading}")
    return 0


def main(argv: list[str]) -> int:
    cmds = {"check": cmd_check, "preview": cmd_preview, "release": cmd_release,
            "archive": cmd_archive}
    if not argv or argv[0] not in cmds:
        print(__doc__, file=sys.stderr)
        return 2
    return cmds[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
