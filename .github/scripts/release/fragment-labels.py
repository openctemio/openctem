#!/usr/bin/env python3
"""Write {fragment file: [release-note labels]} for the changelog fragments.

  fragment-labels.py [--repo-dir DIR] [--github-repo OWNER/REPO] [--out FILE]

For each api/changelog.d/*.md it finds the commit that added the file, asks
GitHub which pull request that commit belongs to, and keeps the labels that
start with `notes:` (set by .github/scripts/pr-labels.py or by hand). The result
feeds `api/scripts/changelog.py preview|release --labels FILE`, which groups the
fragments under operator headings (migrations, destructive migrations,
identity changes, API contract changes) in the release notes.

A fragment whose pull request cannot be found is reported on stderr and listed
in the summary line; it gets no labels. Nothing here is fatal for the
release: the notes just lack the operator heading for that fragment.
"""
import argparse
import json
import os
import subprocess
import sys

PREFIX = "notes:"


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-dir", default=".")
    ap.add_argument("--github-repo", default=os.environ.get("GITHUB_REPOSITORY", "openctemio/openctem"))
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    frag_dir = os.path.join(args.repo_dir, "api", "changelog.d")
    names = sorted(n for n in os.listdir(frag_dir) if n.endswith(".md") and n != "README.md") \
        if os.path.isdir(frag_dir) else []

    result, unresolved = {}, []
    for name in names:
        rel = f"api/changelog.d/{name}"
        rc, out, err = run(["git", "log", "--diff-filter=A", "--format=%H", "-n", "1", "--", rel], args.repo_dir)
        sha = out.strip()
        if rc != 0 or not sha:
            unresolved.append(name)
            print(f"fragment-labels: {name}: no commit adds it ({err.strip()})", file=sys.stderr)
            continue
        rc, out, err = run(["gh", "api", f"repos/{args.github_repo}/commits/{sha}/pulls"], args.repo_dir)
        if rc != 0:
            unresolved.append(name)
            print(f"fragment-labels: {name}: pull request lookup failed for {sha[:12]}: {err.strip()}", file=sys.stderr)
            continue
        prs = json.loads(out or "[]")
        if not prs:
            unresolved.append(name)
            print(f"fragment-labels: {name}: no pull request for {sha[:12]}", file=sys.stderr)
            continue
        labels = sorted({lb["name"] for pr in prs for lb in pr.get("labels", []) if lb["name"].startswith(PREFIX)})
        if labels:
            result[name] = labels

    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(f"fragment-labels: {len(names)} fragment(s), {len(result)} with operator labels, "
          f"{len(unresolved)} without a pull request", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
