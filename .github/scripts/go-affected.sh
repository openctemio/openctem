#!/usr/bin/env bash
# The Go packages of api/ whose tests a pull request can affect: the packages
# it changes, and every package that imports one of them (directly or through
# others, test files included). Run from api/.
#
#   go-affected.sh <base-ref>
#
# Prints `ALL` (one line) when the change cannot be narrowed, otherwise one
# import path per line (possibly none). Callers treat anything unexpected as
# ALL: the selection only ever removes work that cannot change the result.
#
# ALL when a changed file
#   - is outside api/ and not documentation or web/ (the root Makefile,
#     deploy/, .github/, go.work: shared inputs),
#   - is inside api/ but not in a Go package's directory tree: go.mod, go.sum,
#     migrations/, configs/, deploy/, scripts/, Makefile. Tests read these
#     files, so every test may depend on them,
#   - is api/docs/configuration/environment-variables.md (a test compares it).
# Ignored: Markdown, api/docs/, api/changelog.d/, web/, .claude/.
# A file inside a package's directory tree (code, testdata, embedded files)
# belongs to its nearest enclosing package.
#
# The graph is the module's own import graph (`go list`: Imports, TestImports,
# XTestImports), the same relation `go list -deps -test` follows.
set -euo pipefail

base="${1:?usage: go-affected.sh <base-ref>}"
root="$(git rev-parse --show-toplevel)"
prefix="$(git rev-parse --show-prefix)"        # "api/"
prefix="${prefix%/}"

changed="$(git diff --name-only "$base"...HEAD)" || { echo ALL; exit 0; }

GOWORK=off go list -e -json=ImportPath,Dir,Imports,TestImports,XTestImports ./... > "${TMPDIR:-/tmp}/go-affected.$$.json" \
  || { rm -f "${TMPDIR:-/tmp}/go-affected.$$.json"; echo ALL; exit 0; }

CHANGED="$changed" ROOT="$root" PREFIX="$prefix" python3 -I - "${TMPDIR:-/tmp}/go-affected.$$.json" <<'PY'
import json, os, sys

raw = open(sys.argv[1]).read()
os.unlink(sys.argv[1])
root, prefix = os.environ["ROOT"], os.environ["PREFIX"]
dec, i, pkgs = json.JSONDecoder(), 0, []
while True:
    while i < len(raw) and raw[i].isspace():
        i += 1
    if i >= len(raw):
        break
    obj, i = dec.raw_decode(raw, i)
    pkgs.append(obj)

mod = {p["ImportPath"] for p in pkgs}
by_dir = {os.path.relpath(p["Dir"], os.path.join(root, prefix)): p["ImportPath"] for p in pkgs}
rdeps = {}
for p in pkgs:
    for q in set(p.get("Imports", []) + p.get("TestImports", []) + p.get("XTestImports", [])):
        if q in mod:
            rdeps.setdefault(q, set()).add(p["ImportPath"])

def ignored(path):
    return (path.endswith(".md") or path.startswith(("web/", ".claude/", "api/docs/", "api/changelog.d/"))
            or "/.claude/" in path)

hit = set()
for path in os.environ["CHANGED"].splitlines():
    if not path:
        continue
    if path == prefix + "/docs/configuration/environment-variables.md":
        print("ALL"); sys.exit(0)
    if ignored(path):
        continue
    if not path.startswith(prefix + "/"):
        print("ALL"); sys.exit(0)
    d = os.path.dirname(path[len(prefix) + 1:]) or "."
    while d not in by_dir:
        if d in (".", ""):
            print("ALL"); sys.exit(0)
        d = os.path.dirname(d) or "."
    hit.add(by_dir[d])

seen, todo = set(hit), list(hit)
while todo:
    for r in rdeps.get(todo.pop(), ()):
        if r not in seen:
            seen.add(r); todo.append(r)
print("\n".join(sorted(seen)))
PY
