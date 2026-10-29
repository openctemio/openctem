#!/usr/bin/env bash
# pr-no-package-write.sh [<workflows dir>]
#
# Fails when a pull_request or pull_request_target workflow has a job that can
# hold `packages: write` (its own permissions, the workflow's when the job sets
# none, or those of a local reusable workflow it calls) without an `if` that
# keeps pull requests out. A pull request (fork or not) runs code from the
# branch under review; with packages: write it could overwrite release caches
# or mirror tags in GHCR. Pull requests use a read-only job instead
# (resolve-images.yml); the write job carries
# `github.event_name != 'pull_request'`.
#
# This is a tripwire for the configuration, not a proof: the repository's
# GHCR package settings ("Manage Actions access") are the second layer.
set -euo pipefail
dir="${1:-.github/workflows}"
exec python3 -I - "$dir" <<'PY'
import re, sys, glob, os
import yaml

d = sys.argv[1]
GUARD = re.compile(r"github\.event_name\s*(!=\s*'pull_request(_target)?'|==\s*'(push|merge_group|schedule|workflow_dispatch|release)')")

def load(p):
    with open(p) as f:
        return yaml.safe_load(f) or {}

def triggers(w):
    on = w.get(True, w.get("on", {}))  # YAML 1.1 reads a bare `on` as True
    if isinstance(on, str): return {on}
    if isinstance(on, list): return set(on)
    return set(on or {})

def writes(perms):
    if perms == "write-all": return True
    return isinstance(perms, dict) and perms.get("packages") == "write"

wf = {os.path.basename(p): load(p) for p in sorted(glob.glob(os.path.join(d, "*.y*ml")))}
cache = {}
def workflow_writes(name):  # does any job of a local reusable workflow hold packages: write
    if name in cache: return cache[name]
    cache[name] = False
    w = wf.get(name)
    if w:
        top = w.get("permissions")
        for j in (w.get("jobs") or {}).values():
            p = j.get("permissions", top)
            if writes(p) or ("uses" in j and local(j["uses"]) and workflow_writes(local(j["uses"]))):
                cache[name] = True
    return cache[name]

def local(uses):
    m = re.match(r"^\./\.github/workflows/([^@]+)$", str(uses))
    return m.group(1) if m else None

bad = []
for name, w in wf.items():
    if not triggers(w) & {"pull_request", "pull_request_target"}:
        continue
    top = w.get("permissions")
    for jid, j in (w.get("jobs") or {}).items():
        p = j.get("permissions", top)
        can = writes(p) or (local(j.get("uses", "")) and workflow_writes(local(j["uses"])))
        if can and not GUARD.search(str(j.get("if", ""))):
            bad.append(f"{name}: job '{jid}' can hold packages: write on a pull request; guard it with `github.event_name != 'pull_request'` and give pull requests a read-only job")
if bad:
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
print("pr-no-package-write: ok")
PY
