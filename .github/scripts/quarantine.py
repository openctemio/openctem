#!/usr/bin/env python3
"""Flaky-test quarantine: .github/quarantine.yml lists the tests that are
skipped on pull requests and in the merge queue while their race is fixed.

Commands (run from the repository root):

  quarantine.py check            validate the list (Workflow Lint): schema, an
                                 issue and an owner per entry, a fix date at most
                                 MAX_DAYS after the entry was added, no
                                 security test, no Go name that exists in two
                                 packages. Expired entries are reported, not
                                 failed: an expired entry simply stops applying.
  quarantine.py go-skip          the `go test -skip` regexp of the active Go
                                 entries ("" when none).
  quarantine.py pw-grep-invert   the Playwright title regexp of the active
                                 Playwright entries ("" when none).
  quarantine.py list             the active entries, one per line (nightly job).

Rules (api/docs/development/ci-cd.md#flaky-test-quarantine):
- An entry stops applying the day after `fix_by`; the test runs (and fails
  flakily) again, so the fix SLA enforces itself without turning CI red for
  everyone on the deadline.
- Tests whose name says they guard security (tenant isolation, authorization,
  scope, RLS, secrets, signatures) are never quarantined: they are fixed.
- The list is a security-sensitive path: adding an entry needs the
  maintainer's `security-ack`, so a pull request cannot silence the test it
  breaks.

The file is a YAML list of mappings with scalar values only, parsed here
without a YAML library (the runners' system Python has none):

  - test: go:github.com/openctemio/openctem/api/tests/integration.TestName
    issue: 3031
    owner: area-or-login
    added: 2026-10-25
    fix_by: 2026-11-01
    reason: one line
  - test: "pw:e2e/specs/19-scan-lifecycle.spec.ts::a single scan: create, edit, run"
    ...
"""

from __future__ import annotations

import datetime
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]  # the repository root, whatever the working directory
PATH = pathlib.Path(os.environ.get("QUARANTINE_FILE", ROOT / ".github/quarantine.yml"))
MAX_DAYS = 14
FIELDS = ("test", "issue", "owner", "added", "fix_by", "reason")
PROTECTED = re.compile(
    r"(tenant|isolation|cross.?tenant|authz|authori[sz]|permission|privilege|scope|rls|"
    r"secret|signature|sign(ed|er|ing)|csrf|ssrf|xss|inject|leak|redact|auth)",
    re.I,
)
GO_TEST = re.compile(r"^go:(?P<pkg>[A-Za-z0-9_./-]+)\.(?P<name>(Test|Example|Fuzz)[A-Za-z0-9_]*)$")
PW_TEST = re.compile(r"^pw:(?P<spec>e2e/[A-Za-z0-9_./-]+\.spec\.ts)::(?P<title>.+)$")
MODULE = "github.com/openctemio/openctem/api"


def today() -> datetime.date:
    v = os.environ.get("QUARANTINE_TODAY")
    return datetime.date.fromisoformat(v) if v else datetime.date.today()


def _scalar(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v.split(" #", 1)[0].strip()


def parse(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.strip() == "[]":
            continue
        m = re.match(r"^- (\w+):\s*(.*)$", line) or re.match(r"^  (\w+):\s*(.*)$", line)
        if not m:
            raise ValueError(f"line {n}: expected `- key: value` or `  key: value`")
        if line.startswith("- "):
            cur = {}
            entries.append(cur)
        elif cur is None:
            raise ValueError(f"line {n}: a field outside an entry")
        key, val = m.group(1), _scalar(m.group(2))
        if key in cur:
            raise ValueError(f"line {n}: `{key}` twice in one entry")
        cur[key] = val
    return entries


def problems(entries: list[dict[str, str]], go_names: dict[str, set[str]] | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for i, e in enumerate(entries, 1):
        where = f"entry {i} ({e.get('test', '?')})"
        missing = [f for f in FIELDS if not e.get(f)]
        if missing:
            out.append(f"{where}: missing {', '.join(missing)}")
            continue
        extra = sorted(set(e) - set(FIELDS))
        if extra:
            out.append(f"{where}: unknown field(s) {', '.join(extra)}")
        t = e["test"]
        if t in seen:
            out.append(f"{where}: listed twice")
        seen.add(t)
        go, pw = GO_TEST.match(t), PW_TEST.match(t)
        if not go and not pw:
            out.append(f"{where}: `test` must be go:<import path>.<TestName> or pw:e2e/<spec>.spec.ts::<title>")
            continue
        name = go.group("name") if go else pw.group("title")
        if PROTECTED.search(name) or (go and PROTECTED.search(go.group("pkg").rsplit("/", 1)[-1])):
            out.append(f"{where}: a security test is fixed, never quarantined")
        if go and go_names is not None:
            pkgs = go_names.get(go.group("name"), set())
            if go.group("pkg") not in pkgs:
                out.append(f"{where}: no top-level {go.group('name')} in {go.group('pkg')}")
            elif len(pkgs) > 1:
                out.append(f"{where}: {go.group('name')} also exists in {', '.join(sorted(pkgs - {go.group('pkg')}))}; "
                           "`go test -skip` cannot tell them apart, rename the test")
        if not re.fullmatch(r"\d+", e["issue"]):
            out.append(f"{where}: `issue` is the tracking issue number")
        try:
            added = datetime.date.fromisoformat(e["added"])
            fix_by = datetime.date.fromisoformat(e["fix_by"])
        except ValueError:
            out.append(f"{where}: `added` and `fix_by` are YYYY-MM-DD")
            continue
        if fix_by < added or (fix_by - added).days > MAX_DAYS:
            out.append(f"{where}: `fix_by` must be within {MAX_DAYS} days of `added`")
    return out


def active(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    d = today()
    out = []
    for e in entries:
        try:
            if datetime.date.fromisoformat(e["fix_by"]) >= d:
                out.append(e)
        except (KeyError, ValueError):
            # A missing or malformed fix_by is not active; problems() reports it.
            continue
    return out


def go_top_level_names(root: pathlib.Path) -> dict[str, set[str]]:
    """Top-level test name -> import paths that declare it (from the source)."""
    names: dict[str, set[str]] = {}
    pat = re.compile(r"^func ((?:Test|Example|Fuzz)[A-Za-z0-9_]*)\(", re.M)
    for f in (root / "api").rglob("*_test.go"):
        pkg = MODULE + "/" + str(f.parent.relative_to(root / "api")) if f.parent != root / "api" else MODULE
        for m in pat.finditer(f.read_text(errors="replace")):
            names.setdefault(m.group(1), set()).add(pkg)
    return names


def load() -> list[dict[str, str]]:
    return parse(PATH.read_text()) if PATH.exists() else []


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    try:
        entries = load()
    except ValueError as e:
        print(f"{PATH}: {e}", file=sys.stderr)
        return 1
    if cmd == "check":
        errs = problems(entries, go_top_level_names(ROOT))
        for e in errs:
            print(f"::error file={PATH}::{e}")
        for e in entries:
            if e not in active(entries):
                print(f"::warning file={PATH}::{e.get('test')} passed its fix date {e.get('fix_by')} "
                      f"(issue #{e.get('issue')}, owner {e.get('owner')}); it runs again. Fix it or remove the entry.")
        print(f"quarantine: {len(entries)} entries, {len(active(entries))} active, {len(errs)} problems")
        return 1 if errs else 0
    if cmd in ("go-skip", "pw-grep-invert", "list"):
        if problems(entries):
            print(f"{PATH} is invalid; run quarantine.py check", file=sys.stderr)
            return 1
        act = active(entries)
        if cmd == "list":
            for e in act:
                print(f"{e['test']}\t#{e['issue']}\t{e['owner']}\t{e['fix_by']}")
            return 0
        if cmd == "go-skip":
            names = sorted({m.group("name") for e in act if (m := GO_TEST.match(e["test"]))})
            print(f"^({'|'.join(names)})$" if names else "")
            return 0
        titles = sorted({m.group("title") for e in act if (m := PW_TEST.match(e["test"]))})
        print("|".join(re.sub(r"[.*+?^${}()|\[\]\\/]", r"\\\g<0>", t) for t in titles))  # JS RegExp escapes
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
