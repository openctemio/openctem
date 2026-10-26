#!/usr/bin/env python3
"""Compare the tool versions pinned inline in this repository with the newest
stable upstream releases.

  python3 .github/scripts/tool-pins.py [--manifest FILE] [--report FILE]

The pins are listed in .github/tool-pins.tsv (tab separated): the tool name,
its GitHub repository, where upstream versions come from (`releases` or
`tags`), the highest major version we follow (`-` for no limit), the file that
holds the pin, a regular expression with exactly one group that captures the
pinned version, and flags (`optional` = the pin may not exist yet,
`checksum` = a SHA-256 sits next to the pin and must be updated with it).

A pin that cannot be found fails the run: a renamed variable must not turn
the freshness check into a check of nothing.

Exit code: 0 when every pin is current, 10 when at least one needs a bump
(the report is still written), 1 on an error. The workflow
.github/workflows/tool-pins.yml turns the report into one issue.

For tests, TOOL_PINS_FIXTURE names a JSON file {"owner/repo": ["v1.2.3", ...]}
that replaces the GitHub API.
"""
import argparse
import json
import os
import re
import subprocess
import sys

STABLE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def parse(tag):
    m = STABLE.match(tag.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def read_manifest(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) not in (6, 7):
                raise SystemExit(f"{path}:{n}: expected 6 or 7 tab separated columns, got {len(cols)}")
            name, repo, source, major, file, regex = cols[:6]
            flags = set(filter(None, (cols[6] if len(cols) == 7 else "").split(",")))
            if source not in ("releases", "tags"):
                raise SystemExit(f"{path}:{n}: source must be releases or tags")
            if re.compile(regex).groups != 1:
                raise SystemExit(f"{path}:{n}: the regular expression needs exactly one group")
            rows.append(dict(name=name, repo=repo, source=source,
                             major=None if major == "-" else int(major),
                             file=file, regex=regex, flags=flags, line=n))
    return rows


def gh_json(endpoint):
    out = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"gh api {endpoint} failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def upstream_tags(repo, source, fixture):
    if fixture is not None:
        return fixture.get(repo, [])
    names = []
    for page in range(1, 4):
        if source == "releases":
            items = gh_json(f"repos/{repo}/releases?per_page=100&page={page}")
            names += [i["tag_name"] for i in items if not i.get("prerelease") and not i.get("draft")]
        else:
            items = gh_json(f"repos/{repo}/tags?per_page=100&page={page}")
            names += [i["name"] for i in items]
        if len(items) < 100:
            break
    return names


def latest(tags, max_major, calendar):
    best = None
    for t in tags:
        v = parse(t)
        if v is None or (max_major is not None and v[0] > max_major):
            continue
        # Some repositories carry two schemes (v0.8.2 and 2026.2.2): stay on
        # the scheme of the pin.
        if (v[0] >= 1000) != calendar:
            continue
        if best is None or v > best[0]:
            best = (v, t)
    return best[1] if best else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=os.path.join(REPO_ROOT, ".github", "tool-pins.tsv"))
    ap.add_argument("--root", default=REPO_ROOT, help="directory the pin files are relative to")
    ap.add_argument("--report", help="write the markdown report here")
    args = ap.parse_args()

    fixture = None
    if os.environ.get("TOOL_PINS_FIXTURE"):
        with open(os.environ["TOOL_PINS_FIXTURE"], encoding="utf-8") as fh:
            fixture = json.load(fh)

    rows = read_manifest(args.manifest)
    cache = {}
    outdated, current, skipped = [], [], []
    for r in rows:
        path = os.path.join(args.root, r["file"])
        if not os.path.exists(path):
            if "optional" in r["flags"]:
                skipped.append(r)
                continue
            raise SystemExit(f"{r['name']}: {r['file']} does not exist (manifest line {r['line']})")
        with open(path, encoding="utf-8") as fh:
            found = re.findall(r["regex"], fh.read(), flags=re.M)
        if not found:
            if "optional" in r["flags"]:
                skipped.append(r)
                continue
            raise SystemExit(f"{r['name']}: no pin matches in {r['file']} (manifest line {r['line']}); "
                             "fix the pattern or remove the entry")
        key = (r["repo"], r["source"])
        if key not in cache:
            cache[key] = upstream_tags(r["repo"], r["source"], fixture)
        for pinned in sorted(set(found)):
            pv = parse(pinned)
            if pv is None:
                raise SystemExit(f"{r['name']}: pinned value {pinned!r} in {r['file']} is not a version")
            newest = latest(cache[key], r["major"], pv[0] >= 1000)
            if newest is None:
                raise SystemExit(f"{r['name']}: no stable upstream version found for {r['repo']}")
            row = dict(r, pinned=pinned, newest=newest)
            (outdated if parse(newest) > pv else current).append(row)

    lines = []
    if outdated:
        lines += ["Pinned tools with a newer stable release. Open one pull request that bumps the pins,",
                  "so CI runs on the change. Where a SHA-256 is listed, update it from the release's checksums.",
                  "",
                  "| Tool | Pinned | Newest | File | Note |",
                  "|---|---|---|---|---|"]
        for o in outdated:
            note = []
            if "checksum" in o["flags"]:
                note.append("update the SHA-256 next to the pin")
            if parse(o["newest"])[0] > parse(o["pinned"])[0]:
                note.append("new major version: read the release notes")
            if o["major"] is not None:
                note.append(f"stays on major {o['major']} on purpose")
            lines.append(f"| [{o['name']}](https://github.com/{o['repo']}) | `{o['pinned']}` | `{o['newest']}` "
                         f"| `{o['file']}` | {'; '.join(note)} |")
        lines.append("")
    lines.append(f"{len(current)} pin(s) current, {len(outdated)} to bump"
                 + (f", {len(skipped)} not present yet" if skipped else "") + ".")
    report = "\n".join(lines) + "\n"
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)
    sys.stdout.write(report)
    return 10 if outdated else 0


if __name__ == "__main__":
    sys.exit(main())
