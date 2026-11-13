#!/usr/bin/env python3
"""Changelog fragments for the OpenCTEM API.

Every pull request used to add its entry at the top of server/CHANGELOG.md, right
under "## Unreleased". Any two open pull requests therefore edited the same
lines and conflicted, and a merge queue with many entries turned that into a
steady stream of dequeued pull requests (and once, conflict markers committed
to develop).

Unreleased entries now live one file per change in server/changelog.d/. No two
pull requests touch the same file. The release folds them into CHANGELOG.md
once, in a single commit.

Usage:
  changelog.py check [--docs-base REF]
                                    validate fragments; refuse an entry written
                                    into CHANGELOG.md's Unreleased section and
                                    conflict markers in any tracked text file.
                                    With --docs-base, every fragment added since
                                    REF must say where its user documentation is
                                    ("Docs:" line, see DOCS_LINE)
  changelog.py preview              print the Unreleased section assembled from
                                    the fragments
  changelog.py archive HEADING LIST fold only the fragments named in LIST (one
                                    file name per line) into CHANGELOG.md as
                                    "## HEADING", below every existing section,
                                    and delete them (one-off catch-up)
  changelog.py notes [--labels F]   print the release notes body: the Upgrade
                                    notes block, then the categories
  changelog.py release VERSION [--labels F] [--date YYYY-MM-DD]
                                    fold the fragments into CHANGELOG.md under
                                    "## VERSION (date, default today)" and
                                    delete them

preview, notes and release take the fragments to use from git as well:
  --ref REF      only fragments that exist at REF (a release tag: what shipped)
  --since REF    leave out fragments that exist at REF (the previous release)
  --since-previous TAG
                 --since the newest vX.Y.Z tag below TAG (or below the newest
                 tag when TAG is "latest")
The fragment text is read from the working tree. A release tag's tree still
holds the fragments of the releases before it until develop folded them, so
"--ref vX.Y.Z --since-previous vX.Y.Z" is exactly that release's changes,
whether or not the earlier releases were folded.

The Upgrade notes block lists, for every chosen fragment, its "Upgrade note:"
lines under "Before you upgrade" and the titles of its Behaviour change,
Removed and Deprecated sections; with --labels it also lists the fragments
under the operator headings below.

--labels F names a JSON file {"<fragment file>": ["notes:migration", ...]}
(.github/scripts/release/fragment-labels.sh writes it from the labels of the
pull requests that added the fragments). With it, an "Upgrade notes" block at
the top of the section lists the fragments under the operator headings below,
so a reader sees the migrations, destructive migrations, identity changes and
API contract changes before the categories.

Fragment format (server/changelog.d/<short-slug>.md):

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
API = ROOT / "server"
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
# Categories whose titles the Upgrade notes block repeats: what an operator
# notices without reading every entry.
NOTICE_CATEGORIES = ["Behaviour change", "Removed", "Deprecated"]
# "- **Upgrade note:** text" (bold or not, "notes" too) inside a fragment.
UPGRADE_NOTE = re.compile(
    r"^(?P<indent>\s*)[-*]\s+(?:\*\*)?Upgrade notes?(?::\*\*|\*\*:|:)\s*(?P<text>\S.*)$",
    re.IGNORECASE,
)
FRAGMENT_DIRS = ("server/changelog.d", "api/changelog.d")  # tags before the rename; rename-guard: allow
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
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


def names_at(ref: str) -> set[str]:
    """Fragment file names in the tree of ref (either backend directory name)."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-tree", "--name-only", ref, *(d + "/" for d in FRAGMENT_DIRS)],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit(f"cannot read the fragments at {ref}: {out.stderr.strip()}")
    names = {pathlib.PurePosixPath(n).name for n in out.stdout.split()}
    return {n for n in names if n.endswith(".md") and n != "README.md"}


def tag_key(tag: str) -> tuple[int, int, int]:
    m = TAG.match(tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (-1, -1, -1)


def previous_tag(tag: str) -> str:
    """The newest stable vX.Y.Z tag below tag ("latest": the newest tag of all)."""
    tags = subprocess.run(["git", "-C", str(ROOT), "tag", "-l", "v*"],
                          capture_output=True, text=True, check=True).stdout.split()
    tags = sorted((t for t in tags if TAG.match(t)), key=tag_key)
    if tag == "latest":
        if not tags:
            raise SystemExit("no vX.Y.Z tag in this clone (fetch the tags)")
        return tags[-1]
    if not TAG.match(tag):
        raise SystemExit(f"--since-previous needs vX.Y.Z or latest, got {tag!r}")
    below = [t for t in tags if tag_key(t) < tag_key(tag)]
    if not below:
        raise SystemExit(f"no release tag below {tag} in this clone (fetch the tags)")
    return below[-1]


def pop_option(argv: list[str], name: str) -> tuple[str | None, list[str]]:
    if name not in argv:
        return None, argv
    i = argv.index(name)
    if i + 1 >= len(argv):
        raise SystemExit(f"{name} needs a value")
    return argv[i + 1], argv[:i] + argv[i + 2:]


def select(argv: list[str]) -> tuple[list[pathlib.Path], list[str]]:
    """The fragments chosen by --ref / --since / --since-previous."""
    ref, argv = pop_option(argv, "--ref")
    since, argv = pop_option(argv, "--since")
    prev, argv = pop_option(argv, "--since-previous")
    if since and prev:
        raise SystemExit("--since and --since-previous exclude each other")
    if prev:
        since = previous_tag(prev)
    chosen = fragments()
    if ref:
        keep = names_at(ref)
        chosen = [p for p in chosen if p.name in keep]
    if since:
        drop = names_at(since)
        chosen = [p for p in chosen if p.name not in drop]
    return chosen, argv


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


# A fragment added by a pull request names the user documentation of its change,
# so a release never ships an undocumented feature: a page of the public docs
# site, a path in one of the project's repositories, or "none" with a reason.
#   Docs: https://docs.openctem.io/sensors/proxies/
#   Docs: server/docs/architecture/task-secrets.md
#   Docs: none (internal refactor, no behaviour change)
DOCS_LINE = re.compile(
    r"^\s*(?:-\s*)?\**Docs:?\**:?\s*(?P<target>"
    r"https://docs\.openctem\.io/\S*"
    r"|https://github\.com/openctemio/\S+"
    r"|(?:server|web|deploy|docs)/\S+\.md\S*"
    r"|none\s*[(:-]\s*\S.{4,})",
    re.IGNORECASE | re.MULTILINE,
)


def added_fragments(base: str) -> list[pathlib.Path]:
    """Fragments this branch adds relative to base (merge base, so other merges do not count)."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--diff-filter=A", "--name-only", f"{base}...HEAD", "--",
         str(FRAGMENTS.relative_to(ROOT))],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    return [ROOT / n for n in out if n.endswith(".md") and not n.endswith("README.md")]


def docs_links(paths: list[pathlib.Path]) -> list[str]:
    errors = []
    for p in paths:
        if p.is_file() and not DOCS_LINE.search(p.read_text(encoding="utf-8")):
            errors.append(
                f"{p.relative_to(ROOT)}: name the user documentation of this change in a line "
                "'Docs: <https://docs.openctem.io/... or a repository path>' or "
                "'Docs: none (<why no user documentation is needed>)' (server/changelog.d/README.md)"
            )
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


def upgrade_notes(body: str) -> list[str]:
    """The "Upgrade note:" bullets of a section, continuation lines joined."""
    notes: list[str] = []
    cur: list[str] | None = None
    indent = ""
    for line in body.splitlines():
        m = UPGRADE_NOTE.match(line)
        if m:
            if cur:
                notes.append(" ".join(cur))
            cur, indent = [m.group("text").strip()], m.group("indent")
            continue
        if cur is not None:
            stripped = line.strip()
            starts_item = re.match(r"^\s*[-*]\s", line) and len(line) - len(line.lstrip()) <= len(indent)
            if not stripped or starts_item or line.startswith("#"):
                notes.append(" ".join(cur))
                cur = None
            else:
                cur.append(stripped)
    if cur:
        notes.append(" ".join(cur))
    return notes


def operator_block(labels: dict[str, list[str]] | None, paths: list[pathlib.Path] | None = None) -> str:
    """The Upgrade notes block: what to do before upgrading, what behaves
    differently, and fragment section titles under the operator headings."""
    chosen = fragments() if paths is None else paths
    labels = labels or {}
    lines: list[str] = []
    before: list[tuple[int, str]] = []
    notice: list[tuple[int, str]] = []
    for p in chosen:
        for cat, body in sections(p.read_text(encoding="utf-8")):
            if not cat:
                continue
            title = body.splitlines()[0][4:]
            rank = CATEGORIES.index(cat) if cat in CATEGORIES else len(CATEGORIES)
            for note in upgrade_notes(body):
                # Notes that need no action follow the ones that do.
                no_action = note.lower().startswith("no action")
                before.append((rank + (100 if no_action else 0), f"- **{title}**: {note}"))
            if cat in NOTICE_CATEGORIES:
                notice.append((rank, f"- {title} (`{p.name}`)"))
    # In release order of the categories (stable: fragment order within one),
    # notes that need an action first.
    if before:
        lines += ["#### Before you upgrade", "", *(t for _, t in sorted(before, key=lambda x: x[0])), ""]
    if notice:
        lines += ["#### Behaviour changes, removals and deprecations", "",
                  *(t for _, t in sorted(notice, key=lambda x: x[0])), ""]
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
    if "--docs-base" in argv:
        errors += docs_links(added_fragments(argv[argv.index("--docs-base") + 1]))
    if entries_in_unreleased():
        errors.append(
            "server/CHANGELOG.md: an entry was written under Unreleased. Put it in "
            "server/changelog.d/<short-slug>.md instead (see server/changelog.d/README.md)."
        )
    for e in errors:
        print(f"::error::{e}" if "GITHUB_ACTIONS" in os.environ else e)
    if not errors:
        print(f"changelog: {len(fragments())} fragment(s) OK, no conflict markers")
    return 1 if errors else 0


def cmd_preview(argv: list[str]) -> int:
    labels, argv = read_labels(argv)
    chosen, _ = select(argv)
    print(UNRELEASED + "\n")
    print(operator_block(labels, chosen) + assemble(chosen) if chosen else "_No unreleased changes._\n")
    return 0


def cmd_notes(argv: list[str]) -> int:
    labels, argv = read_labels(argv)
    chosen, _ = select(argv)
    print((operator_block(labels, chosen) + assemble(chosen)).rstrip() if chosen else "No notable changes.")
    return 0


def cmd_release(argv: list[str]) -> int:
    labels, argv = read_labels(argv)
    chosen, argv = select(argv)
    date, argv = pop_option(argv, "--date")
    if date is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        print("--date must be YYYY-MM-DD", file=sys.stderr)
        return 2
    if not argv or not re.fullmatch(r"v\d+\.\d+\.\d+", argv[0]):
        print("usage: changelog.py release vX.Y.Z [--ref REF] [--since REF | --since-previous TAG] "
              "[--date YYYY-MM-DD] [--labels F]", file=sys.stderr)
        return 2
    errors = validate()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    text = CHANGELOG.read_text(encoding="utf-8")
    start = text.find(UNRELEASED)
    if start < 0:
        print("server/CHANGELOG.md has no '## Unreleased' heading", file=sys.stderr)
        return 1
    head = text[: start + len(UNRELEASED)]
    rest = text[start + len(UNRELEASED):]
    m = re.search(r"(?m)^## ", rest)
    older = rest[m.start():] if m else ""
    if f"\n## {argv[0]} (" in text:
        print(f"server/CHANGELOG.md already has a section for {argv[0]}", file=sys.stderr)
        return 1
    date = date or _dt.date.today().isoformat()
    body = (operator_block(labels, chosen) + assemble(chosen)).rstrip() or "No notable changes."
    CHANGELOG.write_text(
        f"{head}\n\n{FRAGMENT_NOTE}\n\n## {argv[0]} ({date})\n\n{body}\n\n{older}".rstrip() + "\n",
        encoding="utf-8",
    )
    for p in chosen:
        p.unlink()
    print(f"folded {len(chosen)} fragment(s) into CHANGELOG.md as {argv[0]}")
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
        print("server/CHANGELOG.md has no '## Unreleased' heading", file=sys.stderr)
        return 1
    body = assemble(chosen).rstrip() or "No notable changes."
    CHANGELOG.write_text(f"{text.rstrip()}\n\n## {heading}\n\n{body}\n", encoding="utf-8")
    for p in chosen:
        p.unlink()
    print(f"archived {len(chosen)} fragment(s) into CHANGELOG.md as {heading}")
    return 0


def main(argv: list[str]) -> int:
    cmds = {"check": cmd_check, "preview": cmd_preview, "notes": cmd_notes, "release": cmd_release,
            "archive": cmd_archive}
    if not argv or argv[0] not in cmds:
        print(__doc__, file=sys.stderr)
        return 2
    return cmds[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
