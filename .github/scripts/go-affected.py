#!/usr/bin/env python3
"""Which Go packages of api/ does a change affect?

Used by the fast tier of API CI (pull_request): the unit job runs `go test` for
these packages only. The merge queue runs the whole suite, so a package this
script leaves out is still tested before anything reaches develop.

  go-affected.py <changed-file-list>   run from api/; the file lists repository
                                       paths, one per line (git diff --name-only)

Prints `ALL` when the change cannot be mapped to packages (go.mod, go.sum,
go.work, a file under api/ outside every Go package directory), else the import
paths of every package that changed or imports (directly or through any chain,
including its test files) a changed package, one per line. Prints nothing when
no Go file of api/ changed. Any error prints `ALL`: when in doubt, test.
"""
import json
import os
import subprocess
import sys

ALL_FILES = {"go.mod", "go.sum", "go.work", "go.work.sum"}


def go_list():
    out = subprocess.run(
        ["go", "list", "-json=ImportPath,Dir,Deps,TestImports,XTestImports", "./..."],
        check=True, capture_output=True, text=True,
    ).stdout
    dec, pos, pkgs = json.JSONDecoder(), 0, []
    while pos < len(out):
        while pos < len(out) and out[pos].isspace():
            pos += 1
        if pos >= len(out):
            break
        obj, pos = dec.raw_decode(out, pos)
        pkgs.append(obj)
    return pkgs


def affected(changed, pkgs, root):
    """changed: repository paths. root: absolute path of api/."""
    by_dir = {os.path.realpath(p["Dir"]): p["ImportPath"] for p in pkgs}
    seeds = set()
    for f in changed:
        if not f.startswith("api/"):
            continue  # shared files and web/ change no Go package of api/
        rel = f[len("api/"):]
        if rel in ALL_FILES:
            return None
        if "/" not in rel and not rel.endswith(".go"):
            # a top-level api/ file that is not code (Makefile, Dockerfile): no package
            continue
        d = os.path.realpath(os.path.join(root, os.path.dirname(rel)))
        while True:
            if d in by_dir:
                seeds.add(by_dir[d])
                break
            if d == root or not d.startswith(root):
                if rel.endswith(".go"):
                    return None
                break  # a non-Go file outside every package (docs, scripts, configs)
            d = os.path.dirname(d)
    if not seeds:
        return set()
    out = set(seeds)
    for p in pkgs:
        reach = set(p.get("Deps") or [])
        for t in (p.get("TestImports") or []) + (p.get("XTestImports") or []):
            reach.add(t)
            for q in pkgs:
                if q["ImportPath"] == t:
                    reach.update(q.get("Deps") or [])
        if reach & seeds:
            out.add(p["ImportPath"])
    return out


def main():
    root = os.path.realpath(os.getcwd())
    try:
        with open(sys.argv[1]) as fh:
            changed = [l.strip() for l in fh if l.strip()]
        res = affected(changed, go_list(), root)
    except Exception as e:  # noqa: BLE001
        print(f"go-affected: {e}", file=sys.stderr)
        print("ALL")
        return 0
    if res is None:
        print("ALL")
    else:
        print("\n".join(sorted(res)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
