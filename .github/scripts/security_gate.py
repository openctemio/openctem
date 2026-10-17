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
Labels and the review comment are written only when the token can write (same
repository pull requests); fork pull requests get the verdict in the job
summary and the check result.

Commands:
  gate                     evaluate the pull request named by the GitHub event
  codeowners --check       fail if CODEOWNERS' security block is out of date
  codeowners --write       rewrite CODEOWNERS' security block
Only the Python standard library is used.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field

GUIDE = "https://github.com/openctemio/openctem/blob/develop/api/docs/development/ci-cd.md#security-gate"
SENSITIVE_LABEL = "security-sensitive"
ACK_LABEL = "security-ack"
COMMENT_MARKER = "<!-- security-gate -->"
# The gate comment records which security-sensitive diff the ack covers (see
# sensitive_digest). Only the comment the workflow itself wrote counts.
DIGEST_MARKER = re.compile(r"<!-- security-gate:ack-digest=([0-9a-f]{64}) -->")
BOT_LOGIN = "github-actions[bot]"
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


def sensitive_digest(files: list[ChangedFile], config: dict[str, list[str]], findings: list[Finding]) -> str:
    """Fingerprint of what an ack approves: the pull request's own changed
    lines (added and removed, without context or hunk positions) in every file
    that makes it security-sensitive. The file list is the diff against the
    merge base, so merging the base branch in moves the context but not these
    lines, and the fingerprint stays; a commit that changes a sensitive line,
    adds a sensitive file or resolves a conflict inside one changes it. A file
    GitHub sent no patch for is represented by its head blob, which is
    stricter (any change to that file counts)."""
    names = {f for fs in classify(files, config).values() for f in fs}
    names |= {f.path for f in findings if f.severity in ("HIGH", "SENSITIVE")}
    h = hashlib.sha256()
    for f in sorted(files, key=lambda f: f.filename):
        if f.filename not in names:
            continue
        h.update(f"file\0{f.filename}\0{f.previous_filename or ''}\0{f.status}\n".encode())
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
            out += data if isinstance(data, list) else data.get("check_runs", [])
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


def fetch_pr_commits(gitdir: str, repo: str, server: str, token: str, base_sha: str, head_sha: str) -> None:
    """Fetch the base and head commits (history and trees, blobs on demand)
    into the gate's own checkout. Nothing is checked out or run."""
    if not os.path.isdir(os.path.join(gitdir, ".git")):
        raise RuntimeError(f"{gitdir} is not a git checkout; cannot diff a pull request of {MAX_FILES}+ files")
    auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{server}/.extraheader",
           "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}"}
    args = ["fetch", "--no-tags", "--filter=blob:none", "--quiet"]
    if _git_out(gitdir, "rev-parse", "--is-shallow-repository").strip() == b"true":
        args.append("--unshallow")
    _git_out(gitdir, *args, f"{server}/{repo}.git", head_sha, base_sha, env=env)


def git_changed_files(gitdir: str, base_sha: str, head_sha: str, config: dict[str, list[str]]) -> list[ChangedFile]:
    """The changed-file list of base...head from git, shaped like the API's:
    the same file set GitHub shows (the diff against the merge base, renames
    as a delete plus an add), with a patch (hunks only, like the API) for every
    file a rule or a path category looks at. Other files get an empty patch:
    nothing reads it."""
    rng = f"{base_sha}...{head_sha}"
    common = ("diff", "--no-renames", "--no-ext-diff", "--no-textconv", "-z")
    raw = _git_out(gitdir, *common, "--raw", "--no-abbrev", rng).decode("utf-8", "surrogateescape").split("\0")
    stat = _git_out(gitdir, *common, "--numstat", rng).decode("utf-8", "surrogateescape").split("\0")
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
    proc = _git(gitdir, "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "-U3", rng, stderr=subprocess.DEVNULL)
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


def ack_state(gh: GitHub, number: int, labels: set[str], ackers: list[str]) -> tuple[bool, str]:
    if ACK_LABEL not in labels:
        return False, f"no `{ACK_LABEL}` label"
    events = gh.paginate(f"issues/{number}/events")
    last = None
    for e in events:
        if e.get("event") == "labeled" and (e.get("label") or {}).get("name") == ACK_LABEL:
            last = e
    actor = ((last or {}).get("actor") or {}).get("login", "")
    if actor.lower() in {a.lower() for a in ackers}:
        return True, f"`{ACK_LABEL}` added by {actor}"
    return False, f"`{ACK_LABEL}` was added by {actor or 'an unknown user'}, who is not listed under `ackers`"


def new_code_scanning_alerts(gh: GitHub, number: int, base_ref: str) -> tuple[list[dict], str]:
    """Open high/critical alerts on the PR's analysis that are not open on the base branch."""
    pr = gh.paginate(f"code-scanning/alerts?ref=refs/pull/{number}/merge&state=open", ok404=True)
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
    ack_digest: str = ""  # the sensitive diff the ack covers, recorded in the comment

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
        out += [f"New commits changed the security-sensitive lines of this pull request, so the previous "
                f"`{ACK_LABEL}` was removed. Merging the base branch alone keeps it.", ""]
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
            f"A maintainer reviews the change and adds the **`{ACK_LABEL}`** label. The gate re-runs on the label. "
            f"Status: {r.ack_note}.", "",
            f"<sub>Path list: `.github/security-paths.yml` · [how the gate works]({GUIDE})</sub>"]
    if r.acked and r.ack_digest:
        out.append(f"<!-- security-gate:ack-digest={r.ack_digest} -->")
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


def push_touches_sensitive(gh: GitHub, event: dict, files: list[ChangedFile],
                           config: dict[str, list[str]]) -> bool:
    """For an ack without a recorded digest (given before the gate stored
    one): does this push change a sensitive file of the PR? A force-push, a
    rebase or a truncated comparison counts as yes."""
    before, after = event.get("before"), event.get("after")
    sensitive_here = {f for fs in classify(files, config).values() for f in fs}
    if not sensitive_here:
        return False
    cmp_ = gh.get(f"compare/{before}...{after}", ok404=True) if before and after else None
    if cmp_ is None or cmp_.get("status") not in ("ahead", "identical") or len(cmp_.get("files", [])) >= 300:
        return True  # force-push or rebase: the acknowledged commits are gone
    pushed = [ChangedFile(f["filename"], f.get("status", "modified"), int(f.get("deletions", 0)),
                          None, f.get("previous_filename")) for f in cmp_.get("files", [])]
    changed = {f for fs in classify(pushed, config).values() for f in fs}
    return bool(changed & sensitive_here)


def recorded_digest(comment: dict | None) -> str | None:
    m = DIGEST_MARKER.search((comment or {}).get("body") or "")
    return m.group(1) if m else None


def settle_ack(gh: GitHub, event_name: str, event: dict, r: Result, digest: str, recorded: str | None,
               files: list[ChangedFile], config: dict[str, list[str]], labels: set[str],
               can_write: bool) -> None:
    """Decide whether an existing `security-ack` still covers the pull request,
    and which digest the comment records for it.

    - This run is the `security-ack` label event: record the digest.
    - The comment holds a digest: the ack stands while the sensitive diff is
      unchanged (pushes and base-branch merges that leave those lines alone),
      and is removed (on a read-only run: ignored) once it differs.
    - No digest yet, and a push: the earlier rule (does the push touch a
      sensitive file?); if it does not, record the digest.
    - Anything else keeps the label, as before, without recording a digest.
    """
    if ACK_LABEL not in labels:
        return
    action = event.get("action")
    if event_name == "pull_request" and action == "labeled" and (event.get("label") or {}).get("name") == ACK_LABEL:
        r.ack_digest = digest  # the maintainer acknowledged what is there now
        return
    if recorded is not None:
        if recorded == digest:
            r.ack_digest = digest
            return
    elif event_name == "pull_request" and action == "synchronize":
        if not push_touches_sensitive(gh, event, files, config):
            r.ack_digest = digest
            return
    else:
        return
    if can_write:
        gh.request("DELETE", f"issues/{r.number}/labels/{ACK_LABEL}", ok404=True)
        r.ack_dropped = True
    labels.discard(ACK_LABEL)
    r.ack_note = f"the security-sensitive lines changed after `{ACK_LABEL}` was added; a maintainer adds it again"


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
    """The gate's own comment: it carries the marker and the workflow token
    wrote it, so a comment someone else posts cannot plant a digest."""
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

    if event_name == "pull_request":
        number = int(event["pull_request"]["number"])
    elif event_name == "merge_group":
        number = merge_group_pr(event["merge_group"]["head_ref"])
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

    r = Result(number)
    r.hits = classify(files, config)
    r.findings, r.unreviewed = review(files)
    comment = gate_comment(gh, number) if r.sensitive or can_write else None
    if r.sensitive:
        settle_ack(gh, event_name, event, r, sensitive_digest(files, config, r.findings),
                   recorded_digest(comment), files, config, labels, can_write)
        stale_note = r.ack_note
        r.acked, r.ack_note = ack_state(gh, number, labels, config["ackers"])
        if not r.acked and stale_note:
            r.ack_note = stale_note
        r.alerts, r.alerts_note = new_code_scanning_alerts(gh, number, pr["base"]["ref"])
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
        if argv[:1] == ["codeowners"]:
            return cmd_codeowners(argv[1:])
    except (RuntimeError, ValueError, KeyError) as e:
        print(f"security-gate: {e}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
