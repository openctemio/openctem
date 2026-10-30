#!/usr/bin/env python3
"""security-gate: classify a pull request against .github/security-paths.yml,
review its diff for high-risk patterns, collect new code-scanning alerts, and
decide whether it may merge.

Design and operator guide: openctemio/openctem api/docs/development/ci-cd.md#security-gate
(this file is shared verbatim by the openctemio repositories that use the gate).

Threat model. The gate routes security-sensitive changes to a deliberate human
acknowledgement; it is not a sandbox. It never runs code from the pull request:
the diff is read through the GitHub API as data (for a pull request of 3000
files or more, whose API file list is cut off, through `git diff` of the two
fetched commits, which are never checked out), and the workflow runs this
script and the path list from the base commit. It fails closed: any API or git
error or an unknown merge-queue ref fails the check.
An ack is trusted only through records GitHub writes itself (the `labeled`
issue event, or - when the label came from the `/security-ack` comment command,
whose label event names the Actions bot - the comment itself, whose author
GitHub sets; and the branch push log for which commit was the head at that
moment); the gate comment is output only, because any workflow on any branch
of the repository writes as the same bot. The workflow file itself comes from
the pull request on `pull_request` events, so the required check must be
pinned to the default branch's workflow file (a "require workflows" ruleset);
see the guide. Such a pinned run starts only on opened/synchronize/reopened,
not on a label, so the `rerun` command (security-gate-label.yml) re-runs it
when the label changes; the decision never depends on that run existing.
Labels and the review comment are written only when the token can write (same
repository pull requests); fork pull requests get the verdict in the job
summary and the check result.

Commands:
  gate                     evaluate the pull request named by the GitHub event
  rerun                    on a label event or ack comment: re-run the gate run of the pull request's head
  ackcmd                   on an `issue_comment`: obey /security-ack and /security-unack from an acker
  codeowners --check       fail if CODEOWNERS' security block is out of date
  codeowners --write       rewrite CODEOWNERS' security block
Only the Python standard library is used.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

GUIDE = "https://github.com/openctemio/openctem/blob/develop/api/docs/development/ci-cd.md#security-gate"
SENSITIVE_LABEL = "security-sensitive"
ACK_LABEL = "security-ack"
COMMENT_MARKER = "<!-- security-gate -->"
# Which commit an ack was given on comes only from data GitHub itself writes:
# the `labeled` issue event (actor, server time) and the head branch's push log
# (the repository activity API: every push, force push, creation and deletion
# of the branch with its server time and new tip). Never from commit dates
# (author and committer dates are whatever the pusher wrote), never from
# comments or check suites (any workflow token can write those).
GATE_WORKFLOW = "security-gate.yml"  # .github/workflows/<this>; override with GATE_WORKFLOW_FILE
MAX_EVENTS = 3000  # an issue-event list this long may be cut off: the gate fails closed
# A push this many seconds or less before the label may not have reached the
# pull request page the acker was looking at: the gate cannot tell which of the
# two heads was acknowledged and fails closed.
ACK_SETTLE = 60
MAX_ACTIVITY_PAGES = 30  # 3000 branch activities; a longer push log fails closed
ZERO_SHA = "0" * 40
SHA = re.compile(r"^[0-9a-f]{40}$")
RERUN_WAIT = 600  # seconds the `rerun` command waits for the head's gate run to finish
RERUN_POLL = 15
# A pull request that changes any of these gets no carried-over ack: its own
# workflow runs (pull_request events run the PR's workflow files) could act on
# the pull request, so the ack covers only the exact commit it was given on.
ACK_PINNED_PATHS = (".github/workflows/**", ".github/actions/**", ".github/security-paths.yml",
                    ".github/scripts/security_gate.py")
# A migration's version prefix: the merge queue renumbers a pull request's
# migrations above the base branch (same name, same content, new number), which
# is not a change an ack has to see again.
MIGRATION_VERSION = re.compile(r"(^|/)migrations/[0-9]+_(?=[^/]+$)")
BOT_LOGIN = "github-actions[bot]"
# The comment commands (security-ack-command.yml): an acker's comment on a pull
# request. The workflow adds/removes the label with its own token, so the label's
# `labeled` event names the bot; the gate then reads the acker from the comment.
ACK_COMMAND = "/security-ack"
UNACK_COMMAND = "/security-unack"
ACK_COMMAND_WINDOW = 600  # seconds a command comment may precede the label it caused
MAX_FILES = 3000  # GitHub's pull request file list stops here; from this many files on the gate diffs with git
MAX_PATCH_LINES = 20000  # a larger single-file patch counts as "no diff sent", like the API does
CODEOWNERS_BEGIN = "# BEGIN security-paths (generated from .github/security-paths.yml; do not edit)"
CODEOWNERS_END = "# END security-paths"



# --------------------------------------------------------------------------
# Path list


def load_config(text: str) -> dict[str, list[str]]:
    """Parse the `key:` + `  - item` subset used by security-paths.yml."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            continue
        m = re.fullmatch(r"([A-Za-z0-9_-]+):", line)
        if m:
            current = m.group(1)
            if current in out:
                raise ValueError(f"line {n}: duplicate key {current}")
            out[current] = []
            continue
        m = re.fullmatch(r"  - (.+)", line)
        if m and current is not None:
            item = m.group(1).strip()
            if len(item) >= 2 and item[0] == item[-1] and item[0] in "'\"":
                item = item[1:-1]
            out[current].append(item)
            continue
        raise ValueError(f"line {n}: unsupported syntax: {raw!r}")
    if not out.get("ackers"):
        raise ValueError("security-paths.yml: `ackers` must list at least one user")
    return out


def glob_to_regex(glob: str) -> re.Pattern[str]:
    i, out = 0, []
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z")


RESERVED = ("ackers", "removal-only")


def categories(config: dict[str, list[str]]) -> dict[str, list[re.Pattern[str]]]:
    return {k: [glob_to_regex(g) for g in v] for k, v in config.items() if k not in RESERVED}


@dataclass
class ChangedFile:
    filename: str
    status: str = "modified"
    deletions: int = 0
    patch: str | None = None
    previous_filename: str | None = None
    sha: str = ""  # blob of the head version; stands in for a patch GitHub did not send


def counts(f: ChangedFile, removal_only: list[re.Pattern[str]]) -> bool:
    """A `removal-only` file counts only when the change removes lines."""
    if any(p.match(f.filename) for p in removal_only):
        return f.status == "removed" or f.deletions > 0
    return True


def classify(files: list[ChangedFile], config: dict[str, list[str]]) -> dict[str, list[str]]:
    cats = categories(config)
    removal_only = [glob_to_regex(g) for g in config.get("removal-only", [])]
    hits: dict[str, list[str]] = {}
    for f in files:
        if not counts(f, removal_only):
            continue
        names = {f.filename} | ({f.previous_filename} if f.previous_filename else set())
        for cat, pats in cats.items():
            if any(p.match(name) for p in pats for name in names):
                hits.setdefault(cat, []).append(f.filename)
    return hits


# --------------------------------------------------------------------------
# Diff review: high-precision patterns on added lines only. A line can waive a
# rule with `security-review: allow <RULE-ID> <reason>` in a comment, which
# stays visible in the diff and in git history.


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # HIGH (blocks), MEDIUM (reported), SENSITIVE (needs an ack, no finding)
    path: re.Pattern[str]
    line: re.Pattern[str]
    message: str


def _r(id_: str, sev: str, path: str, line: str, msg: str) -> Rule:
    return Rule(id_, sev, re.compile(path), re.compile(line), msg)


NOT_TEST = r"^(?!.*(?:_test\.go$|\.test\.tsx?$|\.spec\.tsx?$|/testdata/|/__tests__/))"
WORKFLOW = r"^\.github/(workflows|actions)/.*\.ya?ml$"

RULES: list[Rule] = [
    _r("GO-TLS-NOVERIFY", "HIGH", NOT_TEST + r".*\.go$", r"InsecureSkipVerify\s*:\s*true",
       "TLS certificate verification disabled"),
    _r("JWT-UNVERIFIED", "HIGH", NOT_TEST + r".*\.go$", r"ParseUnverified\(|SigningMethodNone|UnsafeAllowNoneSignatureType",
       "JWT parsed without signature verification"),
    _r("GHA-PR-TARGET", "HIGH", WORKFLOW, r"\bpull_request_target\b",
       "`pull_request_target` runs with a write token in the base context"),
    _r("GHA-WRITE-ALL", "HIGH", WORKFLOW, r"permissions\s*:\s*write-all",
       "workflow token with every write permission"),
    _r("GHA-UNPINNED", "HIGH", WORKFLOW, r"^\s*-?\s*uses\s*:\s*(?!\./)(?!docker://)[^\s#@]+@(?![0-9a-f]{40}\b)",
       "action not pinned to a full commit SHA"),
    _r("GHA-INJECTION", "HIGH", WORKFLOW,
       r"\$\{\{\s*github\.(event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body|review\.body|head_commit\.message|commits)|head_ref)",
       "untrusted event text interpolated into the workflow (use an env variable)"),
    _r("WEB-RAW-HTML", "HIGH", NOT_TEST + r"^web/.*\.(tsx?|jsx?)$", r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=",
       "raw HTML sink"),
    _r("WEB-EVAL", "HIGH", NOT_TEST + r"^web/.*\.(tsx?|jsx?|mjs)$", r"\beval\(|new Function\(",
       "dynamic code evaluation"),
    _r("SQL-RLS-OFF", "HIGH", r"^api/migrations/.*\.up\.sql$", r"(?i)disable\s+row\s+level\s+security|\bbypassrls\b|grant\s+.*\bto\s+public\b",
       "row-level security disabled or a grant to PUBLIC"),
    _r("GO-RAW-HTTP", "MEDIUM", NOT_TEST + r"^api/(?!pkg/httpsec/).*\.go$", r"\bhttp\.(Get|Post|PostForm|Head)\(|http\.DefaultClient|&http\.Client\{",
       "outbound HTTP outside pkg/httpsec (SSRF guard)"),
    _r("GO-RAW-CLIENT-IP", "MEDIUM", NOT_TEST + r"^api/(?!pkg/httpsec/).*\.go$", r"\"X-(Forwarded-For|Real-IP)\"",
       "client IP read from a raw header (use pkg/httpsec)"),
    _r("GO-EXEC", "MEDIUM", NOT_TEST + r"^api/.*\.go$", r"\"os/exec\"",
       "process execution in the API"),
    _r("GO-SQL-FORMAT", "MEDIUM", NOT_TEST + r"^api/.*\.go$", r"(?i)Sprintf\(\s*[`\"][^`\"]*\b(select|insert\s+into|update|delete\s+from)\s",
       "SQL built with Sprintf (check every interpolated value is not user input)"),
    _r("CORS-WILDCARD", "MEDIUM", NOT_TEST + r".*(\.(go|tsx?|jsx?|mjs|conf)|Caddyfile)$", r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*|AllowedOrigins\s*:\s*\[\]string\{\s*\"\*\"",
       "CORS allows every origin"),
    _r("DOCKER-PRIVILEGED", "MEDIUM", r"(^|/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml)$", r"privileged\s*:\s*true|--privileged|chmod\s+(-R\s+)?777",
       "privileged container or world-writable files"),
    _r("SQL-PERMISSIONS", "SENSITIVE", r"^api/migrations/.*\.up\.sql$",
       r"(?i)row\s+level\s+security|\b(create|drop|alter)\s+policy\b|^\s*(grant|revoke)\s|\bbypassrls\b|\b(insert\s+into|update)\s+role_permissions\b",
       "migration changes row-level security, database grants or which roles hold a permission"),
    _r("CONFIG-SECURITY-DEFAULT", "SENSITIVE", r"^api/internal/config/config\.go$",
       r"(?i)(cookie\w*secure|secure_?cookie|csrf|cors|allow\w*origin|app_?debug|insecure|allow\w*private|trusted\w*prox|skip\w*verif|hsts|require\w*(mfa|email|verif))",
       "configuration default of a security control"),
]

ALLOW = re.compile(r"security-review:\s*allow\s+([A-Z0-9-]+)")
COMMENT_LINE = re.compile(r"^\s*(//|--|#|/\*|\*)")


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    excerpt: str


def added_lines(patch: str):
    """Yield (new-file line number, text) for every added line of a unified diff."""
    new = 0
    for raw in patch.splitlines():
        if raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            new = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+"):
            yield new, raw[1:]
            new += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            new += 1


def review(files: list[ChangedFile]) -> tuple[list[Finding], list[str]]:
    """Return findings and the files whose patch GitHub did not include."""
    findings: list[Finding] = []
    unreviewed: list[str] = []
    for f in files:
        if f.status == "removed":
            continue
        if f.patch is None:
            unreviewed.append(f.filename)
            continue
        rules = [r for r in RULES if r.path.search(f.filename)]
        if not rules:
            continue
        for n, text in added_lines(f.patch):
            if COMMENT_LINE.match(text):
                continue
            waived = set(ALLOW.findall(text))
            for r in rules:
                if r.id in waived or not r.line.search(text):
                    continue
                findings.append(Finding(r.id, r.severity, f.filename, n, r.message, text.strip()[:160]))
    return findings, unreviewed


def stable_path(path: str | None) -> str | None:
    """The path without a migration's version number (renumbering keeps it)."""
    return MIGRATION_VERSION.sub(r"\1migrations/#_", path) if path else path


def sensitive_names(files: list[ChangedFile], config: dict[str, list[str]], findings: list[Finding]) -> set[str]:
    """The files whose changes an ack covers."""
    names = {f for fs in classify(files, config).values() for f in fs}
    return names | {f.path for f in findings if f.severity in ("HIGH", "SENSITIVE")}


def sensitive_digest(files: list[ChangedFile], config: dict[str, list[str]], findings: list[Finding]) -> str:
    """Fingerprint of what an ack approves: the pull request's own changed
    lines (added and removed, without context or hunk positions) in every file
    that makes it security-sensitive. The file list is the diff against the
    merge base, so merging the base branch in moves the context but not these
    lines, and the fingerprint stays; a commit that changes a sensitive line,
    adds a sensitive file or resolves a conflict inside one changes it. A file
    GitHub sent no patch for is represented by its head blob, which is
    stricter (any change to that file counts). A migration counts by name
    without its version number, in version order, so renumbering a pull
    request's migrations (same names, same order, same content) keeps the
    digest and reordering them does not."""
    names = sensitive_names(files, config, findings)
    h = hashlib.sha256()
    for f in sorted(files, key=lambda f: f.filename):
        if f.filename not in names:
            continue
        h.update(f"file\0{stable_path(f.filename)}\0{stable_path(f.previous_filename) or ''}\0{f.status}\n".encode())
        if f.patch is None:
            h.update(f"blob\0{f.sha}\n".encode())
            continue
        for line in f.patch.splitlines():
            if line[:1] in ("+", "-"):
                h.update(line.encode() + b"\n")
    return h.hexdigest()


# --------------------------------------------------------------------------
# CODEOWNERS mirror


def codeowners_block(config: dict[str, list[str]]) -> str:
    owners = " ".join("@" + a for a in config["ackers"])
    lines = [CODEOWNERS_BEGIN]
    for cat, globs in config.items():
        if cat in RESERVED:
            continue
        lines.append(f"# {cat}")
        lines += [f"/{g.lstrip('/')} {owners}" for g in globs]
    lines.append(CODEOWNERS_END)
    return "\n".join(lines) + "\n"


def splice_codeowners(text: str, block: str) -> str:
    start, end = text.find(CODEOWNERS_BEGIN), text.find(CODEOWNERS_END)
    if start == -1 or end == -1:
        return text.rstrip("\n") + "\n\n" + block
    end += len(CODEOWNERS_END)
    if text[end:end + 1] == "\n":
        end += 1
    return text[:start] + block + text[end:]


# --------------------------------------------------------------------------
# GitHub API


class GitHub:
    def __init__(self, repo: str, token: str, api: str = "https://api.github.com"):
        self.repo, self.token, self.api = repo, token, api.rstrip("/")

    def request(self, method: str, path: str, body: object | None = None, ok404: bool = False):
        url = path if path.startswith("http") else f"{self.api}/repos/{self.repo}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "openctem-security-gate",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                link = resp.headers.get("Link", "")
                return (json.loads(raw) if raw else None), link
        except urllib.error.HTTPError as e:
            if ok404 and e.code == 404:
                return None, ""
            detail = e.read().decode(errors="replace")[:300]
            raise RuntimeError(f"GitHub API {method} {path}: HTTP {e.code}: {detail}") from None

    def get(self, path: str, ok404: bool = False):
        return self.request("GET", path, ok404=ok404)[0]

    def paginate(self, path: str, ok404: bool = False) -> list:
        sep = "&" if "?" in path else "?"
        url: str | None = f"{path}{sep}per_page=100"
        out: list = []
        while url:
            data, link = self.request("GET", url, ok404=ok404)
            if data is None:
                return out
            out += data if isinstance(data, list) else data.get("check_runs", data.get("workflow_runs", []))
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m.group(1) if m else None
        return out


def changed_file(f: dict) -> ChangedFile:
    return ChangedFile(f["filename"], f.get("status", "modified"), int(f.get("deletions", 0)),
                       f.get("patch"), f.get("previous_filename"), f.get("sha") or "")


def pr_files(gh: GitHub, number: int) -> list[ChangedFile]:
    return [changed_file(f) for f in gh.paginate(f"pulls/{number}/files")]


def _git(gitdir: str, *args: str, env: dict[str, str] | None = None, stderr: int = subprocess.PIPE) -> subprocess.Popen:
    """Run git on the fetched objects without ever executing PR-controlled
    code: no checkout happens, and external diff drivers and text conversion
    filters are off."""
    cmd = ["git", "-C", gitdir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
           "--literal-pathspecs", *args]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr,
                            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_EXTERNAL_DIFF": "", **(env or {})})


def _git_out(gitdir: str, *args: str, env: dict[str, str] | None = None) -> bytes:
    p = _git(gitdir, *args, env=env)
    out, err = p.communicate()
    if p.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {err.decode(errors='replace')[:300]}")
    return out


GATE_REMOTE = "security-gate"


def git_auth_env(server: str, token: str) -> dict[str, str]:
    """The token as an HTTP header for git, in the environment only (never in
    the repository's config), so blobs git fetches on demand later are
    authorised the same way."""
    auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{server}/.extraheader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}"}


def fetch_pr_commits(gitdir: str, repo: str, server: str, token: str, base_sha: str, head_sha: str,
                     *more: str) -> None:
    """Fetch the base and head commits (and any `more`; history and trees,
    blobs on demand from the gate's own promisor remote) into the gate's own
    checkout. Nothing is checked out or run."""
    if not os.path.isdir(os.path.join(gitdir, ".git")):
        raise RuntimeError(f"{gitdir} is not a git checkout; cannot diff a pull request of {MAX_FILES}+ files")
    env = git_auth_env(server, token)
    url = f"{server}/{repo}.git"
    remotes = _git_out(gitdir, "remote").decode().split()
    if GATE_REMOTE not in remotes:
        _git_out(gitdir, "remote", "add", GATE_REMOTE, url)
    args = ["fetch", "--no-tags", "--filter=blob:none", "--quiet"]
    if _git_out(gitdir, "rev-parse", "--is-shallow-repository").strip() == b"true":
        args.append("--unshallow")
    _git_out(gitdir, *args, GATE_REMOTE, head_sha, base_sha, *more, env=env)


def _blobs(gitdir: str, treeish: str, paths: list[str], env: dict[str, str] | None = None) -> dict[str, str]:
    """path -> blob id in treeish, for the given paths (absent paths left out)."""
    if not paths:
        return {}
    out = _git_out(gitdir, "ls-tree", "-r", "-z", "--full-tree", treeish, "--", *paths, env=env)
    blobs = {}
    for rec in out.decode("utf-8", "surrogateescape").split("\0"):
        if rec:
            meta, path = rec.split("\t", 1)
            blobs[path] = meta.split()[2]
    return blobs


def git_digest(gitdir: str, base_sha: str, head_sha: str, config: dict[str, list[str]],
               env: dict[str, str] | None = None) -> tuple[str, set[str]]:
    """sensitive_digest of base...head computed from git (never from a
    recorded value), and the sensitive file names of that diff."""
    files = git_changed_files(gitdir, base_sha, head_sha, config, env)
    findings = review(files)[0]
    return sensitive_digest(files, config, findings), sensitive_names(files, config, findings)


def ack_still_covers(gitdir: str, base_sha: str, acked: str, head_sha: str, config: dict[str, list[str]],
                     env: dict[str, str] | None = None) -> bool:
    """Does an ack given on `acked` still cover `head`? Both digests are
    recomputed from git against the same base: equal digests (the
    security-sensitive lines did not change) keep it, and so does a head that
    only merged the base branch into `acked` (covered_by_merges). Every git
    error counts as not covered."""
    try:
        acked_digest, _ = git_digest(gitdir, base_sha, acked, config, env)
        head_digest, names = git_digest(gitdir, base_sha, head_sha, config, env)
    except (RuntimeError, ValueError, IndexError, OSError):
        return False
    if acked_digest == head_digest:
        return True
    return covered_by_merges(gitdir, acked, base_sha, head_sha, names, env)


def covered_by_merges(gitdir: str, acked: str, base_sha: str, head_sha: str, names: set[str],
                      env: dict[str, str] | None = None) -> bool:
    """Does `head` hold exactly the acknowledged security-sensitive content,
    brought up to date with the base branch by clean merges only?

    True when `acked` (the head the ack was confirmed on) is an ancestor of
    `head`, and every sensitive file of the pull request is the same blob in
    `head` as in a clean merge of `acked` with the newest base commit `head`
    contains (git merge-tree). So merging the base branch in, also when the
    base changed the same files, keeps the ack; a sensitive change in a
    non-merge commit, a conflict resolved inside a sensitive file, or a
    rebase/force-push does not. Migrations compare by name without their
    version (stable_path), and the pull request's migrations must keep their
    order. Every git error counts as not covered."""
    try:
        anc = _git(gitdir, "merge-base", "--is-ancestor", acked, head_sha, env=env)
        anc.communicate()
        if anc.returncode != 0:
            return False
        newest_base = _git_out(gitdir, "merge-base", head_sha, base_sha, env=env).decode().split()[0]
        p = _git(gitdir, "merge-tree", "--write-tree", "--no-messages", acked, newest_base, env=env)
        out, _ = p.communicate()
        if p.returncode not in (0, 1):  # 1 = conflicts somewhere; a conflicted sensitive file differs below
            return False
        merged_tree = out.decode().split()[0]
        plain = sorted(n for n in names if stable_path(n) == n)
        if _blobs(gitdir, head_sha, plain, env) != _blobs(gitdir, merged_tree, plain, env):
            return False
        migrations = sorted(n for n in names if stable_path(n) != n)
        if migrations:
            dirs = sorted({n.rsplit("/", 1)[0] + "/" for n in migrations})
            want = {stable_path(n) for n in migrations}

            def by_name(treeish: str) -> list[tuple[str, str]]:
                listed = _blobs(gitdir, treeish, dirs, env)
                return [(stable_path(p), b) for p, b in sorted(listed.items()) if stable_path(p) in want]
            if by_name(head_sha) != by_name(merged_tree):
                return False
        return True
    except (RuntimeError, IndexError, OSError):
        return False


def only_base_merges(gitdir: str, acked: str, base_sha: str, head_sha: str,
                     env: dict[str, str] | None = None) -> bool:
    """For a pull request that changes the gate or a workflow: is `head`
    exactly `acked` brought up to date with the base branch, and nothing else?

    True when `acked` is an ancestor of `head`, merging the newest base commit
    `head` contains into `acked` has no conflict, and `head`'s whole tree is
    that merge's tree. Not one byte beyond what the base branch brought in: a
    workflow, action or script edit, a conflict resolved by hand, or any other
    change in a merge or a later commit gives a different tree, and a rebase or
    force-push loses the ancestry. Every git error counts as not covered."""
    try:
        anc = _git(gitdir, "merge-base", "--is-ancestor", acked, head_sha, env=env)
        anc.communicate()
        if anc.returncode != 0:
            return False
        newest_base = _git_out(gitdir, "merge-base", head_sha, base_sha, env=env).decode().split()[0]
        p = _git(gitdir, "merge-tree", "--write-tree", "--no-messages", acked, newest_base, env=env)
        out, _ = p.communicate()
        if p.returncode != 0:  # a conflict needs a hand-made resolution: the maintainer looks again
            return False
        merged_tree = out.decode().split()[0]
        head_tree = _git_out(gitdir, "rev-parse", f"{head_sha}^{{tree}}", env=env).decode().split()[0]
        return head_tree == merged_tree
    except (RuntimeError, IndexError, OSError):
        return False


def git_changed_files(gitdir: str, base_sha: str, head_sha: str, config: dict[str, list[str]],
                      env: dict[str, str] | None = None) -> list[ChangedFile]:
    """The changed-file list of base...head from git, shaped like the API's:
    the same file set GitHub shows (the diff against the merge base, renames
    as a delete plus an add), with a patch (hunks only, like the API) for every
    file a rule or a path category looks at. Other files get an empty patch:
    nothing reads it."""
    rng = f"{base_sha}...{head_sha}"
    common = ("diff", "--no-renames", "--no-ext-diff", "--no-textconv", "-z")
    raw = _git_out(gitdir, *common, "--raw", "--no-abbrev", rng, env=env).decode("utf-8", "surrogateescape").split("\0")
    stat = _git_out(gitdir, *common, "--numstat", rng, env=env).decode("utf-8", "surrogateescape").split("\0")
    entries = []  # (status, blob sha, path)
    for meta, path in zip(raw[0::2], raw[1::2]):
        fields = meta.lstrip(":").split()
        letter = fields[4][:1]
        entries.append(("removed" if letter == "D" else "added" if letter == "A" else "modified", fields[3], path))
    numstat = {}
    for rec in stat:
        if rec:
            added, deleted, path = rec.split("\t", 2)
            numstat[path] = (added, deleted)
    files: list[ChangedFile] = []
    wanted: list[bool] = []
    for status, blob, path in entries:
        added, deleted = numstat.get(path, ("0", "0"))
        probe = ChangedFile(path, status, int(deleted) if deleted.isdigit() else 0, None, None, blob)
        files.append(probe)
        wanted.append(added != "-" and (any(r.path.search(path) for r in RULES) or bool(classify([probe], config))))
    # One streamed full diff; sections come in the same order as the raw list.
    proc = _git(gitdir, "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "-U3", rng, env=env,
                stderr=subprocess.DEVNULL)
    section = -1
    in_hunk = False
    patches: dict[int, list[str]] = {}
    for line in proc.stdout:
        text = line.decode("utf-8", "replace").rstrip("\n")
        if text.startswith("diff --git "):  # a content line starts with +, -, space or backslash
            section, in_hunk = section + 1, False
            continue
        if section < 0 or section >= len(files) or not wanted[section]:
            continue
        in_hunk = in_hunk or text.startswith("@@")
        if in_hunk:
            lines = patches.setdefault(section, [])
            if len(lines) <= MAX_PATCH_LINES:
                lines.append(text)
    proc.stdout.close()
    if proc.wait() != 0:
        raise RuntimeError("git diff of the pull request failed")
    if section + 1 != len(files):
        raise RuntimeError(f"git diff listed {section + 1} files but {len(files)} changed")
    for i, f in enumerate(files):
        if numstat.get(f.filename, ("0", "0"))[0] == "-":
            f.patch = None  # binary: no diff, like the API
        elif not wanted[i]:
            f.patch = ""
        elif len(patches.get(i, [])) > MAX_PATCH_LINES:
            f.patch = None
        else:
            f.patch = "\n".join(patches.get(i, []))
    return files


def last_ack_event(gh: GitHub, number: int) -> dict | None:
    """The newest `labeled` issue event for `security-ack` (GitHub writes
    these; the actor is whoever added the label), as a copy with
    `retargeted_after` set when the pull request's base branch changed later."""
    events = gh.paginate(f"issues/{number}/events")
    if len(events) >= MAX_EVENTS:
        raise RuntimeError(f"pull request has {len(events)}+ issue events; the list may be cut off (fail closed)")
    last, newest, base_changes = None, None, []
    for e in events:
        if e.get("event") in ("labeled", "unlabeled") and (e.get("label") or {}).get("name") == ACK_LABEL:
            newest = e.get("event")
        if e.get("event") == "labeled" and (e.get("label") or {}).get("name") == ACK_LABEL:
            last = dict(e, retargeted_after=False)
        elif e.get("event") == "base_ref_changed" and last is not None:
            last["retargeted_after"] = True
            base_changes.append(e.get("created_at") or "")
    if newest != "labeled":
        return None  # the label is on the pull request, so a complete list ends with its `labeled` event
    if last is not None:
        last["base_changes"] = base_changes
    return last


def command_of(body: str) -> str | None:
    """`ack` or `unack` when the first line of a comment is exactly that slash
    command (nothing else on the line); None otherwise."""
    lines = (body or "").strip().splitlines()
    first = lines[0].strip() if lines else ""
    return {ACK_COMMAND: "ack", UNACK_COMMAND: "unack"}.get(first)


def command_ack(gh: GitHub, number: int, label_event: dict, ackers: list[str]) -> dict | None:
    """The ack record behind a `security-ack` label that the command workflow
    (security-ack-command.yml) added, whose `labeled` event names the Actions
    bot as the actor: the newest `/security-ack` comment WRITTEN BY an acker
    (GitHub sets the comment's author; only that account, or its token, can
    write as it) that

    - was posted no later than the label and at most ACK_COMMAND_WINDOW seconds
      before it (the workflow labels within seconds; a stale comment cannot
      vouch for a label added much later by something else),
    - was never edited (an edited comment's time is not the time of the intent),
    - has no `/security-unack` by an acker between it and the label.

    The record carries the acker, the comment's time (the moment the acker
    decided, so the push-log lookup and the settle rule use it, exactly as for
    a `labeled` event by an acker) and the retarget flag. None when there is no
    such comment."""
    names = {a.lower() for a in ackers}
    t_label = _ts(label_event["created_at"]) if label_event.get("created_at") else None
    if t_label is None:
        return None
    comments = gh.paginate(f"issues/{number}/comments")
    if len(comments) >= MAX_EVENTS:
        raise RuntimeError(f"pull request has {len(comments)}+ comments; the list may be cut off (fail closed)")
    cmds = []
    for c in comments:
        user = c.get("user") or {}
        login = (user.get("login") or "").lower()
        kind = command_of(c.get("body") or "")
        if kind is None or login not in names or user.get("type") == "Bot" or not c.get("created_at"):
            continue
        if c.get("updated_at") and c["updated_at"] != c["created_at"]:
            continue
        t = _ts(c["created_at"])
        if t <= t_label:
            cmds.append((t, int(c.get("id") or 0), kind, user["login"], c["created_at"]))
    cmds.sort()
    acks = [c for c in cmds if c[2] == "ack"]
    if not acks:
        return None
    t, _, _, login, created = acks[-1]
    if (t_label - t).total_seconds() > ACK_COMMAND_WINDOW:
        return None
    if any(c[2] == "unack" and c[0] > t for c in cmds):
        return None
    after = [b for b in label_event.get("base_changes", []) if b and _ts(b) > t]
    return {"event": "labeled", "label": label_event.get("label"), "actor": {"login": login},
            "created_at": created, "via": "comment",
            "retargeted_after": bool(label_event.get("retargeted_after") or after)}


def ack_state(gh: GitHub, number: int, labels: set[str], ackers: list[str]) -> tuple[bool, str, dict | None]:
    """Is the `security-ack` label an acker's decision? Two records count:
    the `labeled` event by an acker, or (the label was added by the Actions bot,
    as the comment command does) a `/security-ack` comment by an acker."""
    if ACK_LABEL not in labels:
        return False, f"no `{ACK_LABEL}` label", None
    last = last_ack_event(gh, number)
    actor = ((last or {}).get("actor") or {}).get("login", "")
    names = {a.lower() for a in ackers}
    if actor and actor.lower() in names:
        return True, f"`{ACK_LABEL}` added by {actor}", last
    if last is not None and actor.lower() == BOT_LOGIN:
        rec = command_ack(gh, number, last, ackers)
        if rec is not None:
            return True, f"`{ACK_COMMAND}` commented by {rec['actor']['login']}", rec
        return False, (f"`{ACK_LABEL}` was added by {BOT_LOGIN} without a `{ACK_COMMAND}` comment of a user listed "
                       "under `ackers` just before it"), None
    return False, f"`{ACK_LABEL}` was added by {actor or 'an unknown user'}, who is not listed under `ackers`", None


def _ts(value: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def acked_head(gh: GitHub, pr: dict, ack_event: dict) -> str | None:
    """The head commit the acker labelled: the tip of the pull request's head
    branch at the time of the `labeled` event, read from the branch's push log
    (GET /repos/{head repo}/activity). GitHub writes each entry on the push
    with its own clock; a pull request, its workflows or a workflow token can
    add entries only by really moving the branch, which the log then records
    truthfully. None (fail closed) when:
    - the log has no entry at or before the label, or is longer than
      MAX_ACTIVITY_PAGES pages (it is sorted by time here, whatever order the
      API returns);
    - the branch moved within ACK_SETTLE seconds before the label (the page the
      acker saw may still have shown the previous head);
    - the entry at the label is a deletion, or the API call fails."""
    at = ack_event.get("created_at")
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    if not at or not head_repo or not pr["head"].get("ref"):
        return None
    t = _ts(at)
    settled = t - datetime.timedelta(seconds=ACK_SETTLE)
    ref = "refs/heads/" + pr["head"]["ref"]
    url: str | None = (f"{gh.api}/repos/{head_repo}/activity?ref={urllib.parse.quote(ref, safe='')}"
                       "&direction=desc&per_page=100")
    log: list[tuple[datetime.datetime, int, str]] = []
    try:
        for _ in range(MAX_ACTIVITY_PAGES):
            data, link = gh.request("GET", url)
            for item in data or []:
                if item.get("ref") == ref and item.get("timestamp"):
                    log.append((_ts(item["timestamp"]), int(item.get("id") or 0), (item.get("after") or "").lower()))
            m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
            url = m.group(1) if m else None
            if url is None:
                break
        else:
            return None  # longer than MAX_ACTIVITY_PAGES pages: it may be cut off
    except (RuntimeError, ValueError, TypeError) as e:
        print(f"::warning::security-gate: cannot read the push log of {head_repo} {ref}: {e}")
        return None
    before = sorted(e for e in log if e[0] <= t)  # time order whatever order the API used
    if not before or before[-1][0] > settled:
        return None  # nothing at the label, or the branch moved moments before it
    after = before[-1][2]
    return after if SHA.match(after) and after != ZERO_SHA else None


def required_gate_ref(gh: GitHub, pr: dict) -> str | None:
    """The ref of the gate workflow a "require workflows" ruleset runs for the
    pull request's base branch (e.g. refs/heads/develop), or None when no
    active ruleset requires it. Read from GitHub's rules API."""
    workflow = f".github/workflows/{os.environ.get('GATE_WORKFLOW_FILE', GATE_WORKFLOW)}"
    repo_id = ((pr.get("base") or {}).get("repo") or {}).get("id")
    base = urllib.parse.quote(pr["base"]["ref"], safe="")
    for rule in gh.paginate(f"rules/branches/{base}"):
        if rule.get("type") != "workflows":
            continue
        for w in (rule.get("parameters") or {}).get("workflows", []):
            if w.get("path") == workflow and w.get("ref") and (repo_id is None or w.get("repository_id") == repo_id):
                return w["ref"]
    return None


def touches_gate(files: list[ChangedFile]) -> list[str]:
    """Files of the pull request under ACK_PINNED_PATHS (either name of a rename)."""
    pats = [glob_to_regex(g) for g in ACK_PINNED_PATHS]
    return sorted({f.filename for f in files
                   for name in (f.filename, f.previous_filename) if name and any(p.match(name) for p in pats)})


def carry_reason(event_name: str, event: dict, pr: dict, files: list[ChangedFile], ack_event: dict,
                 find_head, still_covers, base_merges_only=None) -> tuple[str, str | None]:
    """Why a valid `security-ack` no longer covers this head ("" = it does),
    and the commit the ack was given on (None when unknown).

    - This run is the acker's own label event on the current head: covered.
      (Only without a ruleset: a required workflow does not run on labels.)
    - The base branch changed after the label (a retargeted stacked pull
      request now carries its parent's changes): not covered.
    - The commit the ack was given on (find_head(): acked_head, from the
      branch push log) is unknown: not covered.
    - It is the head: covered.
    - A pull request that changes workflows, actions, the path list or the
      gate script: the ack covers the exact commit it was added on, and a head
      that only merged the base branch into it with no conflict and no other
      byte changed (`base_merges_only(acked)`: only_base_merges).
    - Otherwise `still_covers(acked)` (ack_still_covers, digests recomputed
      from git) decides.
    """
    head = pr["head"]["sha"]
    actor = ((ack_event.get("actor") or {}).get("login") or "").lower()
    if (event_name == "pull_request" and event.get("action") == "labeled"
            and (event.get("label") or {}).get("name") == ACK_LABEL
            and ((event.get("sender") or {}).get("login") or "").lower() == actor
            and ((event.get("pull_request") or {}).get("head") or {}).get("sha") == head):
        return "", head
    if ack_event.get("retargeted_after"):
        return f"the base branch changed after `{ACK_LABEL}` was added; a maintainer adds it again", None
    pinned = touches_gate(files)
    acked = find_head()
    if acked is None:
        return f"cannot tell which commit `{ACK_LABEL}` was given on; a maintainer adds it again", None
    if acked == head:
        return "", acked
    if pinned:
        if base_merges_only is not None and base_merges_only(acked):
            return "", acked
        return (f"this pull request changes the gate or a workflow ({', '.join(f'`{f}`' for f in pinned[:3])}), "
                f"so `{ACK_LABEL}` covers only the exact commit it was added on and clean merges of the base branch into it; "
                f"a maintainer adds it again"), acked
    if not still_covers(acked):
        return (f"the security-sensitive lines changed after `{ACK_LABEL}` was added; "
                "a maintainer adds it again"), acked
    return "", acked


def new_code_scanning_alerts(gh: GitHub, number: int, base_ref: str,
                             analysis_ref: str = "") -> tuple[list[dict], str]:
    """Open high/critical alerts on the PR's analysis that are not open on the base branch.

    analysis_ref is the ref whose analysis is read: the pull request's merge
    ref by default, the merge group's own ref in the merge queue. The PR merge
    ref keeps its last analysis, taken against an older base, so it can still
    list alerts the base fixed since; a merge group is a fresh commit."""
    ref = analysis_ref or f"refs/pull/{number}/merge"
    pr = gh.paginate(f"code-scanning/alerts?ref={ref}&state=open", ok404=True)
    if not pr:
        return [], "no code-scanning analysis of this pull request yet (or none found)"
    base = gh.paginate(f"code-scanning/alerts?ref=refs/heads/{base_ref}&state=open", ok404=True)
    known = {a["number"] for a in base}
    high = []
    for a in pr:
        if a["number"] in known:
            continue
        rule = a.get("rule") or {}
        if (rule.get("security_severity_level") or "").lower() in ("high", "critical"):
            high.append(a)
    return high, ""


SECURITY_CHECK = re.compile(r"(?i)codeql|semgrep|govulncheck|go vulnerabilities|trivy|snyk|secret scanning|dependency review|api lint")


def security_checks(gh: GitHub, sha: str) -> list[dict]:
    runs = gh.paginate(f"commits/{sha}/check-runs")
    latest: dict[str, dict] = {}
    for r in runs:
        name = r.get("name", "")
        if SECURITY_CHECK.search(name) and name not in latest:
            latest[name] = r
    return sorted(latest.values(), key=lambda r: r["name"])


# --------------------------------------------------------------------------
# Verdict and report


@dataclass
class Result:
    number: int
    hits: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    unreviewed: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    alerts_note: str = ""
    checks: list[dict] = field(default_factory=list)
    acked: bool = False
    ack_note: str = ""
    ack_dropped: bool = False
    ack_commit: str | None = None
    head_sha: str = ""
    gate_unpinned: bool = False  # touches the gate and no ruleset pins the gate workflow  # the commit the ack was given on, shown so the acker can confirm it

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def sensitive(self) -> bool:
        return bool(self.hits) or any(f.severity in ("HIGH", "SENSITIVE") for f in self.findings)

    @property
    def passed(self) -> bool:
        return not self.sensitive or (self.acked and not self.high and not self.alerts)


def verdict_line(r: Result) -> str:
    if not r.sensitive:
        return "PASS: no security-sensitive change."
    blockers = []
    if r.high:
        blockers.append(f"{len(r.high)} HIGH diff finding(s)")
    if r.alerts:
        blockers.append(f"{len(r.alerts)} new high/critical code-scanning alert(s)")
    if not r.acked:
        blockers.append(r.ack_note)
    return "PASS: security-sensitive, acknowledged, no open HIGH." if not blockers else "BLOCKED: " + "; ".join(blockers) + "."


def render(r: Result, repo: str, server: str) -> str:
    out = [COMMENT_MARKER, "## Security gate", "", f"**{verdict_line(r)}**", ""]
    if not r.sensitive:
        out.append("This pull request no longer changes a security-sensitive path.")
        return "\n".join(out) + "\n"
    if r.ack_dropped:
        out += [f"The previous `{ACK_LABEL}` was removed: {r.ack_note}. Merging the base branch alone "
                "keeps it, unless the pull request changes workflows or the gate.", ""]
    out += ["### Why this is security-sensitive", ""]
    for cat, files in sorted(r.hits.items()):
        shown = ", ".join(f"`{f}`" for f in files[:8]) + (f" and {len(files) - 8} more" if len(files) > 8 else "")
        out.append(f"- **{cat}**: {shown}")
    content = sorted({f.rule for f in r.findings if f.severity == "SENSITIVE"})
    if content:
        out.append(f"- **content**: {', '.join(content)}")
    out += ["", "### Diff review", ""]
    shown = [f for f in r.findings if f.severity != "SENSITIVE"]
    if shown:
        out += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in sorted(shown, key=lambda f: (f.severity != "HIGH", f.path, f.line))[:50]:
            url = f"{server}/{repo}/pull/{r.number}/files"
            excerpt = f.excerpt.replace("|", "\\|").replace("`", "'")
            out.append(f"| {f.severity} | {f.rule} | [`{f.path}:{f.line}`]({url}) | {f.message}: `{excerpt}` |")
        out += ["", "A HIGH blocks the gate until the line changes, or carries a reviewed waiver comment "
                "`security-review: allow <RULE-ID> <reason>`. MEDIUM findings are for the reviewer."]
    else:
        out.append("No high-risk pattern on the added lines.")
    if r.unreviewed:
        out += ["", f"GitHub sent no diff for {len(r.unreviewed)} file(s) (too large or binary); review them by hand: "
                + ", ".join(f"`{f}`" for f in r.unreviewed[:10])]
    out += ["", "### Code scanning", ""]
    if r.alerts:
        for a in r.alerts[:20]:
            rule = a.get("rule") or {}
            loc = ((a.get("most_recent_instance") or {}).get("location") or {})
            out.append(f"- **{(rule.get('security_severity_level') or '').upper()}** {a.get('tool', {}).get('name', '')} "
                       f"`{rule.get('id', '')}` at `{loc.get('path', '')}:{loc.get('start_line', '')}`: [alert {a['number']}]({a.get('html_url', '')})")
        out.append("")
        out.append("Fix them, or dismiss a false positive in the alert (the dismissal is audited).")
    else:
        out.append(r.alerts_note or "No new high or critical alert.")
    if r.checks:
        out += ["", "### Security checks on the head commit", ""]
        for c in r.checks:
            state = c.get("conclusion") or c.get("status")
            out.append(f"- {c['name']}: {state}")
    out += ["", "### Acknowledge", "",
            f"A maintainer reviews the change and adds the **`{ACK_LABEL}`** label, or replies `{ACK_COMMAND}`. The gate runs again on the label. "
            f"Status: {r.ack_note}.", ""]
    if r.ack_commit:
        out += [f"Acknowledged commit: `{r.ack_commit}` (head now `{r.head_sha}`).", ""]
    if r.gate_unpinned:
        out += ["This pull request changes workflows or the gate, and no ruleset requires the gate workflow "
                "from a fixed branch yet: its own workflow files decide what this check runs. Read the workflow "
                "changes before adding the label.", ""]
    out += [f"<sub>Path list: `.github/security-paths.yml` · [how the gate works]({GUIDE})</sub>"]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Entry points


def env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"{name} is not set")
    return v


def merge_group_pr(head_ref: str) -> int:
    m = re.search(r"/pr-(\d+)-[0-9a-f]+$", head_ref)
    if not m:
        raise RuntimeError(f"cannot find the pull request number in merge group ref {head_ref!r}")
    return int(m.group(1))


RELEASE_HEAD = re.compile(r"^release/v\d")


def release_files(gh: GitHub, pr: dict) -> list[ChangedFile] | None:
    """In a repository with an integration branch (INTEGRATION_BRANCH, e.g.
    develop), a release PR (release/vX.Y.Z -> main) carries that branch, whose
    commits already passed this gate: only what the release branch adds on top
    of it is evaluated. None means "use the PR's own files"."""
    integration = os.environ.get("INTEGRATION_BRANCH", "")
    if not integration or pr["base"]["ref"] != "main" or not RELEASE_HEAD.match(pr["head"]["ref"]):
        return None
    cmp_ = gh.get(f"compare/{integration}...{pr['head']['sha']}")
    files = cmp_.get("files", [])
    if len(files) >= 300:
        return None  # the compare API truncates; fall back to the full diff
    return [changed_file(f) for f in files]


def gate_comment(gh: GitHub, number: int) -> dict | None:
    """The gate's comment, updated in place. Display only: nothing in it is
    ever read back as a decision (any workflow token can write as the bot)."""
    for c in gh.paginate(f"issues/{number}/comments"):
        if COMMENT_MARKER in (c.get("body") or "") and (c.get("user") or {}).get("login") == BOT_LOGIN:
            return c
    return None


def upsert_comment(gh: GitHub, number: int, existing: dict | None, body: str, create: bool) -> None:
    if existing is not None:
        if existing.get("body") != body:
            gh.request("PATCH", f"issues/comments/{existing['id']}", {"body": body})
        return
    if create:
        gh.request("POST", f"issues/{number}/comments", {"body": body})


def cmd_gate() -> int:
    repo, token = env("GITHUB_REPOSITORY"), env("GITHUB_TOKEN")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    event_name = env("GITHUB_EVENT_NAME")
    event = json.loads(pathlib.Path(env("GITHUB_EVENT_PATH")).read_text())
    config = load_config(pathlib.Path(os.environ.get("SECURITY_PATHS", ".github/security-paths.yml")).read_text())
    gh = GitHub(repo, token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))

    analysis_ref = ""
    if event_name == "pull_request":
        number = int(event["pull_request"]["number"])
    elif event_name == "merge_group":
        analysis_ref = event["merge_group"]["head_ref"]
        number = merge_group_pr(analysis_ref)
    else:
        raise RuntimeError(f"unsupported event {event_name}")

    pr = gh.get(f"pulls/{number}")
    labels = {lbl["name"] for lbl in pr.get("labels", [])}
    same_repo = (pr["head"].get("repo") or {}).get("full_name") == repo
    files = release_files(gh, pr) if same_repo else None
    if files is None and int(pr.get("changed_files", 0)) >= MAX_FILES:
        # The API file list stops at 3000 files: diff the two commits with git.
        gitdir = os.environ.get("GATE_DIR", "base")
        fetch_pr_commits(gitdir, repo, server, token, pr["base"]["sha"], pr["head"]["sha"])
        files = git_changed_files(gitdir, pr["base"]["sha"], pr["head"]["sha"], config)
    elif files is None:
        files = pr_files(gh, number)
    # Writes need a same-repository head and a pull_request event: fork tokens are read-only.
    can_write = event_name == "pull_request" and same_repo

    r = Result(number, head_sha=pr["head"]["sha"])
    r.hits = classify(files, config)
    r.findings, r.unreviewed = review(files)
    comment = gate_comment(gh, number) if r.sensitive or can_write else None
    if r.sensitive:
        gate_ref = required_gate_ref(gh, pr) if touches_gate(files) else None
        r.gate_unpinned = bool(touches_gate(files)) and gate_ref is None
        r.acked, r.ack_note, ack_event = ack_state(gh, number, labels, config["ackers"])
        if r.acked:
            def still_covers(acked: str) -> bool:
                gitdir = os.environ.get("GATE_DIR", "base")
                try:
                    fetch_pr_commits(gitdir, repo, server, token, pr["base"]["sha"], pr["head"]["sha"], acked)
                except RuntimeError as e:
                    print(f"::warning::security-gate: cannot fetch the acknowledged head {acked}: {e}")
                    return False
                return ack_still_covers(gitdir, pr["base"]["sha"], acked, pr["head"]["sha"], config,
                                        git_auth_env(server, token))
            def base_merges_only(acked: str) -> bool:
                gitdir = os.environ.get("GATE_DIR", "base")
                try:
                    fetch_pr_commits(gitdir, repo, server, token, pr["base"]["sha"], pr["head"]["sha"], acked)
                except RuntimeError as e:
                    print(f"::warning::security-gate: cannot fetch the acknowledged head {acked}: {e}")
                    return False
                return only_base_merges(gitdir, acked, pr["base"]["sha"], pr["head"]["sha"],
                                        git_auth_env(server, token))
            reason, r.ack_commit = carry_reason(event_name, event, pr, files, ack_event,
                                                lambda: acked_head(gh, pr, ack_event), still_covers,
                                                base_merges_only)
            if reason:
                if can_write:
                    gh.request("DELETE", f"issues/{number}/labels/{ACK_LABEL}", ok404=True)
                    r.ack_dropped = True
                labels.discard(ACK_LABEL)
                r.acked, r.ack_note = False, reason
        r.alerts, r.alerts_note = new_code_scanning_alerts(gh, number, pr["base"]["ref"], analysis_ref)
        r.checks = security_checks(gh, pr["head"]["sha"])

    body = render(r, repo, server)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(body.replace(COMMENT_MARKER, ""))
    print(verdict_line(r))

    if can_write:
        # Best effort: some same-repository runs (Dependabot) get a read-only
        # token. The verdict above never depends on these writes.
        try:
            if r.sensitive and SENSITIVE_LABEL not in labels:
                gh.request("POST", f"issues/{number}/labels", {"labels": [SENSITIVE_LABEL]})
            if not r.sensitive and SENSITIVE_LABEL in labels:
                gh.request("DELETE", f"issues/{number}/labels/{SENSITIVE_LABEL}", ok404=True)
            upsert_comment(gh, number, comment, body, create=r.sensitive)
        except RuntimeError as e:
            print(f"::warning::security-gate could not label or comment: {e}")
    return 0 if r.passed else 1


def rerun_wanted(event_name: str, event: dict, repo: str) -> str:
    """Why the `rerun` command does nothing for this event ("" = re-run)."""
    if event_name == "issue_comment":
        # After the comment command changed the label (the bot's label event
        # starts no workflow). A fork pull request is refused in cmd_rerun,
        # which reads the head repository from the API.
        if event.get("action") != "created":
            return f"`{event.get('action')}` does not change the ack"
        if not (event.get("issue") or {}).get("pull_request"):
            return "the comment is not on a pull request"
        if command_of((event.get("comment") or {}).get("body") or "") is None:
            return "the comment is not an ack command"
        return ""
    if event_name != "pull_request":
        return f"unsupported event {event_name}"
    action = event.get("action")
    if action in ("labeled", "unlabeled"):
        if (event.get("label") or {}).get("name") != ACK_LABEL:
            return f"the label is not `{ACK_LABEL}`"
    elif action != "edited" or "base" not in (event.get("changes") or {}):
        return f"`{action}` does not change the ack"
    head_repo = (((event.get("pull_request") or {}).get("head") or {}).get("repo") or {}).get("full_name")
    if head_repo != repo:
        return "a fork pull request has a read-only token; a maintainer re-runs the gate by hand"
    return ""


def cmd_rerun(sleep=None, now=None) -> int:
    """After a `security-ack` label change (or a retarget), make the head's
    gate run evaluate again. A "require workflows" ruleset starts its pinned
    gate run only on opened/synchronize/reopened, so without this the run
    that read the labels before the change stays the check result.

    Re-runs the newest gate workflow run of the pull request's current head
    (a re-run keeps its event and workflow version and the script reads the
    labels again), after waiting for it to finish; nothing when that run
    started after this job was created, since it then read the labels after
    the change. The decision stays in the gate: this command only asks for
    an evaluation, so a missing or extra re-run never changes a verdict."""
    import time
    sleep = sleep or time.sleep
    now = now or (lambda: datetime.datetime.now(datetime.timezone.utc))
    repo, token = env("GITHUB_REPOSITORY"), env("GITHUB_TOKEN")
    event_name = env("GITHUB_EVENT_NAME")
    event = json.loads(pathlib.Path(env("GITHUB_EVENT_PATH")).read_text())
    why_not = rerun_wanted(event_name, event, repo)
    if why_not:
        print(f"security-gate rerun: nothing to do: {why_not}")
        return 0
    gh = GitHub(repo, token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    run_id = int(env("GITHUB_RUN_ID"))
    if event_name == "issue_comment":
        number = int(event["issue"]["number"])
        # This job starts after the command job changed the label: its own
        # start (GitHub's clock) is the moment from which a gate run has read it.
        jobs = [j for j in (gh.get(f"actions/runs/{run_id}/jobs") or {}).get("jobs", [])
                if j.get("status") == "in_progress" and j.get("started_at")]
        if not jobs:
            raise RuntimeError("cannot tell when this job started")
        anchor = max(_ts(j["started_at"]) for j in jobs)
    else:
        number = int(event["pull_request"]["number"])
        own = gh.get(f"actions/runs/{run_id}")
        anchor = _ts(own["created_at"])  # GitHub's clock, after the label event
    workflow = f".github/workflows/{os.environ.get('GATE_WORKFLOW_FILE', GATE_WORKFLOW)}"
    deadline = now() + datetime.timedelta(seconds=RERUN_WAIT)
    while True:
        pr = gh.get(f"pulls/{number}")
        if pr.get("state") != "open":
            print("security-gate rerun: the pull request is closed")
            return 0
        if event_name == "issue_comment" and (pr["head"].get("repo") or {}).get("full_name") != repo:
            print("security-gate rerun: a fork pull request has a read-only token; a maintainer re-runs the gate by hand")
            return 0
        head = pr["head"]["sha"]
        runs = [r for r in gh.paginate(f"actions/runs?event=pull_request&head_sha={head}")
                if (r.get("path") or "").partition("@")[0] == workflow
                and r.get("event") == "pull_request" and r.get("head_sha") == head
                and (r.get("head_repository") or {}).get("full_name") == repo]
        if runs:
            newest = max(runs, key=lambda r: (_ts(r["created_at"]), int(r["id"])))
            started = _ts(newest.get("run_started_at") or newest["created_at"])
            if started >= anchor:
                print(f"security-gate rerun: run {newest['id']} started after the change; nothing to do")
                return 0
            if newest.get("status") == "completed":
                gh.request("POST", f"actions/runs/{int(newest['id'])}/rerun")
                print(f"security-gate rerun: re-running gate run {newest['id']} for {head}")
                return 0
        if now() >= deadline:
            print(f"::error::security-gate rerun: no finished gate run for {head} within {RERUN_WAIT}s; "
                  "re-run the security-gate check by hand")
            return 1
        sleep(RERUN_POLL)


def cmd_ackcmd() -> int:
    """`/security-ack` and `/security-unack` as a pull request comment: add or
    remove the `security-ack` label and react with +1 or -1. Runs from
    security-ack-command.yml on `issue_comment`, from the default branch, with
    no pull request code checked out.

    Only a user listed under `ackers` is obeyed (anyone else's command is
    ignored silently). The label this writes carries the Actions bot as its
    actor, so it is no ack by itself: the gate counts it only next to the
    acker's comment (command_ack). The comment is re-read through the API
    first, so an edit between the event and this run cancels the command.
    Writes GITHUB_OUTPUT `acted=true` when it changed the label."""
    repo, token = env("GITHUB_REPOSITORY"), env("GITHUB_TOKEN")
    event = json.loads(pathlib.Path(env("GITHUB_EVENT_PATH")).read_text())
    if env("GITHUB_EVENT_NAME") != "issue_comment" or event.get("action") != "created":
        print("security-gate ackcmd: not a new comment")
        return 0
    issue, comment = event.get("issue") or {}, event.get("comment") or {}
    if not issue.get("pull_request"):
        print("security-gate ackcmd: not a pull request")
        return 0
    kind = command_of(comment.get("body") or "")
    if kind is None:
        print("security-gate ackcmd: not a command")
        return 0
    config = load_config(pathlib.Path(os.environ.get("SECURITY_PATHS", ".github/security-paths.yml")).read_text())
    gh = GitHub(repo, token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    number, cid = int(issue["number"]), int(comment["id"])
    live = gh.get(f"issues/comments/{cid}")
    user = live.get("user") or {}
    login = user.get("login") or ""
    if (command_of(live.get("body") or "") != kind or user.get("type") == "Bot"
            or live.get("created_at") != live.get("updated_at")):
        print("security-gate ackcmd: the comment changed; ignoring it")
        return 0
    if login.lower() not in {a.lower() for a in config["ackers"]}:
        print(f"security-gate ackcmd: {login} is not listed under `ackers`; ignoring the command")
        return 0
    pr = gh.get(f"pulls/{number}")
    if pr.get("state") != "open":
        print("security-gate ackcmd: the pull request is closed")
        return 0
    if kind == "ack":
        gh.request("POST", f"issues/{number}/labels", {"labels": [ACK_LABEL]})
        reaction = "+1"
    else:
        gh.request("DELETE", f"issues/{number}/labels/{ACK_LABEL}", ok404=True)
        reaction = "-1"
    gh.request("POST", f"issues/comments/{cid}/reactions", {"content": reaction})
    print(f"security-gate ackcmd: {login}: {kind} on #{number}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("acted=true\n")
    return 0


def cmd_codeowners(argv: list[str]) -> int:
    root = pathlib.Path(os.environ.get("REPO_ROOT", "."))
    config = load_config((root / ".github/security-paths.yml").read_text())
    path = root / ".github/CODEOWNERS"
    text = path.read_text()
    want = splice_codeowners(text, codeowners_block(config))
    if argv[:1] == ["--write"]:
        path.write_text(want)
        return 0
    if want != text:
        print("CODEOWNERS security block differs from .github/security-paths.yml; run:\n"
              "  python3 .github/scripts/security_gate.py codeowners --write", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["gate"]:
            return cmd_gate()
        if argv[:1] == ["rerun"]:
            return cmd_rerun()
        if argv[:1] == ["ackcmd"]:
            return cmd_ackcmd()
        if argv[:1] == ["codeowners"]:
            return cmd_codeowners(argv[1:])
    except (RuntimeError, ValueError, KeyError) as e:
        print(f"security-gate: {e}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
