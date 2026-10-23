#!/usr/bin/env python3
"""Label a pull request with the release-note sections its files belong to.

  pr-labels.py --pr N [--repo OWNER/REPO] [--apply]
  pr-labels.py --files FILE.json            (test input: the pulls/files array)

The labels group the pull request's changelog fragment under an operator
heading in the release notes (api/scripts/changelog.py, `--labels`):

  notes:migration              a migration is added or changed
  notes:destructive-migration  a migration drops, renames or truncates
  notes:identity               finding fingerprint or identity code, or the
                               CTIS module version, changes
  notes:api-contract           an HTTP handler, a route or the sensor protocol
                               changes

The changed files and their diffs are read through the API as data; nothing
from the pull request runs. Labels are only ever added: a person can add one
by hand, and one that no longer matches is removed by hand. Without --apply the
labels are printed, one per line.
"""
import argparse
import fnmatch
import json
import re
import subprocess
import sys

MIGRATION = "notes:migration"
DESTRUCTIVE = "notes:destructive-migration"
IDENTITY = "notes:identity"
API_CONTRACT = "notes:api-contract"
ALL_LABELS = {
    MIGRATION: ("1d76db", "Release notes: the pull request adds or changes a migration"),
    DESTRUCTIVE: ("b60205", "Release notes: a migration drops, renames or truncates"),
    IDENTITY: ("fbca04", "Release notes: finding fingerprint or identity change"),
    API_CONTRACT: ("0e8a16", "Release notes: API handler, route or sensor protocol change"),
}

# A statement that removes or renames something a running pod may still use.
# Same families as api/scripts/check-migrations.sh.
DESTRUCTIVE_SQL = re.compile(
    r"\bdrop\s+(table|column|schema|type)\b"
    r"|\btruncate\b"
    r"|\brename\s+(to|column|constraint)\b"
    r"|\balter\s+table\s+\S+\s+rename\b"
    r"|\balter\s+column\s+\S+\s+(set\s+data\s+)?type\b",
    re.I,
)

IDENTITY_PATHS = [
    "api/pkg/domain/vulnerability/identity*.go",
    "api/pkg/domain/vulnerability/fingerprint*.go",
    "api/pkg/domain/vulnerability/secret_fingerprint*.go",
    "api/internal/app/ingest/identity*.go",
]
CONTRACT_PATHS = [
    "api/internal/infra/http/handler/*.go",
    "api/internal/infra/http/routes/*.go",
    "api/pkg/sensorproto/*",
    "api/pkg/sensorproto/**/*",
]
CTIS_REQUIRE = re.compile(r"^[+-]\s*github\.com/openctemio/ctis\s")


def is_test(path):
    return path.endswith("_test.go") or "/testdata/" in path


def matches(path, patterns):
    # fnmatch's * crosses /, which is what the directory patterns above want.
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def sql_without_comments(line):
    return re.sub(r"--.*$", "", line)


def labels_for(files):
    """files: the entries of GET /repos/{r}/pulls/{n}/files."""
    out = set()
    for f in files:
        path = f.get("filename", "")
        status = f.get("status", "")
        patch = f.get("patch") or ""
        if re.fullmatch(r"api/migrations/[^/]+\.up\.sql", path):
            out.add(MIGRATION)
            # A removed file is not a change that runs; an added or edited
            # one is judged by the lines it adds.
            if status != "removed":
                added = [sql_without_comments(ln[1:]) for ln in patch.splitlines()
                         if ln.startswith("+") and not ln.startswith("+++")]
                if DESTRUCTIVE_SQL.search("\n".join(added)):
                    out.add(DESTRUCTIVE)
        if not is_test(path) and matches(path, IDENTITY_PATHS):
            out.add(IDENTITY)
        if path == "api/go.mod" and any(CTIS_REQUIRE.match(ln) for ln in patch.splitlines()):
            out.add(IDENTITY)
        if not is_test(path) and matches(path, CONTRACT_PATHS):
            out.add(API_CONTRACT)
    return sorted(out)


def gh(*args, check=True):
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise SystemExit(f"gh {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", type=int)
    ap.add_argument("--repo", default="")
    ap.add_argument("--files", help="JSON file with the pulls/files array (tests)")
    ap.add_argument("--apply", action="store_true", help="add the labels to the pull request")
    args = ap.parse_args()

    if args.files:
        with open(args.files, encoding="utf-8") as fh:
            files = json.load(fh)
    elif args.pr and args.repo:
        files = []
        page = 1
        while True:
            chunk = json.loads(gh("api", f"repos/{args.repo}/pulls/{args.pr}/files?per_page=100&page={page}"))
            files += chunk
            if len(chunk) < 100:
                break
            page += 1
            if page > 30:  # the API lists at most 3000 files
                break
    else:
        ap.error("give --files, or --pr and --repo")

    labels = labels_for(files)
    for name in labels:
        print(name)
    if args.apply and labels:
        if not (args.pr and args.repo):
            ap.error("--apply needs --pr and --repo")
        existing = {x["name"] for x in json.loads(gh("api", f"repos/{args.repo}/labels?per_page=100"))}
        for name in labels:
            if name not in existing:
                color, desc = ALL_LABELS[name]
                gh("label", "create", name, "--repo", args.repo, "--color", color, "--description", desc, check=False)
        gh("pr", "edit", str(args.pr), "--repo", args.repo, "--add-label", ",".join(labels))
    return 0


if __name__ == "__main__":
    sys.exit(main())
