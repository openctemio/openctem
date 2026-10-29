#!/usr/bin/env bash
# Fails when a workflow job could run where it must not.
#
#   bash .github/scripts/check-runners.sh [workflows-dir]   (default .github/workflows)
#
# Threat model: the repository is public, so a pull request from a fork carries
# untrusted code. It must never reach the self-hosted runners, which keep
# caches and a Docker daemon between jobs. A job picks its runner with
# `runs-on`; this check accepts only:
#
#   - a GitHub-hosted label literal (ubuntu-*, macos-*, windows-*);
#   - `${{ matrix.<key> }}` when every `runner:` value in that file is such a
#     literal (the release builds that need a native arm64 runner);
#   - one of the approved selector expressions below, character for character
#     apart from white space (api/docs/development/ci-cd.md, "Self-hosted
#     runner (opt-in)").
#
# Each approved expression is also evaluated for every event and every
# combination of set/empty repository variables, and must give:
#   - a hosted label for a pull request from a fork, whatever is set;
#   - a hosted label when no variable is set;
#   - in a merge group, a hosted label, the value of CI_RUNNER_MERGE (or a
#     per-job override CI_RUNNER_CODEQL / CI_RUNNER_E2E_BUILD) or the pool the
#     run's `changes` job picked (needs.changes.outputs.pool), never the value
#     of CI_RUNNER_LIGHT or CI_RUNNER_HEAVY;
#   - the pool output (which is `openctem-ci` for a share of runs, see
#     .github/actions/ci-pool) reaches neither a fork pull request nor a light
#     job; only the heavy selectors use it.
set -euo pipefail

dir="${1:-.github/workflows}"

python3 - "$dir" <<'PY'
import glob
import itertools
import os
import re
import sys

FORK_GUARD = "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)"
MERGE = "(github.event_name == 'merge_group' && (vars.CI_RUNNER_MERGE || 'ubuntu-latest'))"
# Heavy jobs also take the pool the run's `changes` job picked
# (.github/actions/ci-pool: run_id modulo 100 against CI_SELFHOSTED_SHARE).
POOL = "needs.changes.outputs.pool"
MERGE_POOL = f"(github.event_name == 'merge_group' && (vars.CI_RUNNER_MERGE || {POOL} || 'ubuntu-latest'))"
HEAVY_VAR = f"({FORK_GUARD} && (vars.CI_RUNNER_HEAVY || {POOL}))"
APPROVED = {
    # Light jobs: change detection, plans, gates, hygiene, docs, workflow lint.
    "light": f"{MERGE} || ({FORK_GUARD} && vars.CI_RUNNER_LIGHT) || 'ubuntu-latest'",
    # Heavy jobs: builds and tests.
    "heavy": f"{MERGE_POOL} || {HEAVY_VAR} || 'ubuntu-latest'",
    # Per-job overrides (they win over CI_RUNNER_MERGE / CI_RUNNER_HEAVY).
    "codeql": f"({FORK_GUARD} && vars.CI_RUNNER_CODEQL) || {MERGE_POOL} || {HEAVY_VAR} || 'ubuntu-latest'",
    "e2e-build": f"({FORK_GUARD} && vars.CI_RUNNER_E2E_BUILD) || {MERGE_POOL} || {HEAVY_VAR} || 'ubuntu-latest'",
}
HOSTED = re.compile(r"^(ubuntu|macos|windows)-[A-Za-z0-9.-]+$")
VARS = ["CI_RUNNER_LIGHT", "CI_RUNNER_HEAVY", "CI_RUNNER_MERGE", "CI_RUNNER_CODEQL", "CI_RUNNER_E2E_BUILD"]
MERGE_OK = {"CI_RUNNER_MERGE", "CI_RUNNER_CODEQL", "CI_RUNNER_E2E_BUILD", "POOL"}
SELF_POOL = "openctem-ci"  # the self-hosted pool the automatic split may pick
REPO = "openctemio/openctem"
IDENTS = {
    "github.event_name": "event",
    "github.event.pull_request.head.repo.full_name": "head",
    "github.repository": "repo",
    "needs.changes.outputs.pool": "pool",
}
TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||==|!=|'[^']*'|[A-Za-z_][A-Za-z0-9_.-]*)")


def norm(s):
    return " ".join(s.split())


def to_python(expr):
    """Translate a selector expression into Python; None when it uses anything else.

    `&&` and `||` in workflow expressions return an operand, like Python's
    `and`/`or`, and an empty string is falsy in both.
    """
    out, pos = [], 0
    while pos < len(expr):
        m = TOKEN.match(expr, pos)
        if not m:
            if expr[pos:].strip() == "":
                break
            return None
        t, pos = m.group(1), m.end()
        if t == "&&":
            out.append(" and ")
        elif t == "||":
            out.append(" or ")
        elif t in ("(", ")", "==", "!="):
            out.append(t)
        elif t.startswith("'"):
            out.append(repr(t[1:-1]))
        elif t in IDENTS:
            out.append(IDENTS[t])
        elif t.startswith("vars.") and t[5:] in VARS:
            out.append(f"v[{t[5:]!r}]")
        else:
            return None
    return "".join(out)


def contexts():
    events = [
        ("pull_request", "someone/fork"),
        ("pull_request", REPO),
        ("push", ""),
        ("merge_group", ""),
        ("schedule", ""),
        ("workflow_dispatch", ""),
    ]
    for (event, head), bits in itertools.product(events, itertools.product([False, True], repeat=len(VARS))):
        v = {name: (f"self-hosted-{name}" if on else "") for name, on in zip(VARS, bits)}
        # The pool output of the `changes` job: not run, hosted, or self-hosted.
        for pool in ("", "ubuntu-latest", SELF_POOL):
            yield event, head, v, pool


def unsafe(expr):
    """Why the expression could route a job where it must not, or None."""
    code = to_python(expr)
    if code is None:
        return "uses something other than the approved contexts and variables"
    for event, head, v, pool in contexts():
        try:
            got = eval(code, {"__builtins__": {}}, {"event": event, "head": head, "repo": REPO, "v": v, "pool": pool})
        except Exception as e:  # noqa: BLE001 - any failure is a refusal
            return f"does not evaluate ({e})"
        source = next((n for n in VARS if v[n] and got == v[n]), None)
        if source is None and got == SELF_POOL and pool == SELF_POOL:
            source = "POOL"
        where = f"{event}{' from a fork' if head == 'someone/fork' else ''} with {sorted(n for n in VARS if v[n]) or 'no variables'}{' and pool ' + pool if pool else ''}"
        if not isinstance(got, str) or not got:
            return f"gives no runner for {where}"
        if source is None and not HOSTED.match(got):
            return f"gives '{got}' for {where}"
        if event == "pull_request" and head != REPO and source is not None:
            return f"sends a fork pull request to {source} ({where})"
        if not any(v.values()) and source is not None and source != "POOL":
            return f"is not hosted with no variable set ({where})"
        if event == "merge_group" and source is not None and source not in MERGE_OK:
            return f"sends a merge group to {source} ({where})"
    return None


errors = []
for name, expr in APPROVED.items():
    why = unsafe(expr)
    if why:
        errors.append(f"approved expression '{name}' {why}")

approved = {norm(e) for e in APPROVED.values()}
RUNS_ON = re.compile(r"^\s*runs-on:\s*(.*?)\s*$")
RUNNER_VALUE = re.compile(r"""["']?runner["']?\s*:\s*["']?([^"',}\s]+)""")
files = sorted(glob.glob(os.path.join(sys.argv[1], "*.yml")) + glob.glob(os.path.join(sys.argv[1], "*.yaml")))
count = 0
for path in files:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for n, line in enumerate(text.splitlines(), 1):
        m = RUNS_ON.match(line)
        if not m:
            continue
        count += 1
        value = m.group(1)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        where = f"{path}:{n}"
        if HOSTED.match(value):
            continue
        em = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", value)
        if not em:
            errors.append(f"{where}: runs-on must be a hosted label or an approved expression, got: {value or '(multi-line)'}")
            continue
        expr = em.group(1)
        if re.fullmatch(r"matrix\.[A-Za-z0-9_.-]+", expr):
            bad = [r for r in RUNNER_VALUE.findall(text) if not HOSTED.match(r)]
            if bad:
                errors.append(f"{where}: runs-on {value} with a non-hosted matrix runner: {', '.join(bad)}")
            elif not RUNNER_VALUE.search(text):
                errors.append(f"{where}: runs-on {value} but no hosted 'runner:' values in the file")
            continue
        if norm(expr) not in approved:
            why = unsafe(expr)
            errors.append(f"{where}: runs-on is not an approved expression" + (f" (it {why})" if why else ""))

if errors:
    for e in errors:
        print(f"::error::{e}")
    sys.exit(1)
print(f"{count} runs-on in {len(files)} workflows: hosted labels or approved selectors; fork pull requests stay hosted.")
PY
