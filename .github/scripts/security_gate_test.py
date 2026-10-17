#!/usr/bin/env python3
"""Tests for security_gate.py. Run: python3 .github/scripts/security_gate_test.py"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import security_gate as sg  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = sg.load_config((ROOT / ".github/security-paths.yml").read_text())


def patch(*added: str, start: int = 10) -> str:
    return f"@@ -{start},1 +{start},{len(added) + 1} @@\n context\n" + "\n".join("+" + a for a in added)


def F(name: str, *added: str, status: str = "modified", deletions: int = 0, prev: str | None = None) -> sg.ChangedFile:
    return sg.ChangedFile(name, status, deletions, patch(*added) if added else "", prev)


class GlobTest(unittest.TestCase):
    def test_semantics(self):
        m = lambda g, p: bool(sg.glob_to_regex(g).match(p))  # noqa: E731
        self.assertTrue(m("api/pkg/httpsec/**", "api/pkg/httpsec/ssrf.go"))
        self.assertTrue(m("api/pkg/httpsec/**", "api/pkg/httpsec/sub/x.go"))
        self.assertFalse(m("api/pkg/httpsec/**", "api/pkg/httpsecure/x.go"))
        self.assertTrue(m("**/Dockerfile*", "Dockerfile"))
        self.assertTrue(m("**/Dockerfile*", "api/Dockerfile.seed"))
        self.assertFalse(m("web/src/features/*/actions/**", "web/src/features/a/b/actions/x.ts"))
        self.assertTrue(m("web/src/features/*/actions/**", "web/src/features/auth/actions/x.ts"))
        self.assertFalse(m("api/internal/infra/http/handler/*auth*.go", "api/internal/infra/http/handler/x/auth.go"))
        self.assertFalse(m("a/b.go", "a/b.go.orig"))


class ConfigTest(unittest.TestCase):
    def test_repo_config_parses_and_has_ackers(self):
        self.assertIn("0xmanhnv", CONFIG["ackers"])
        self.assertGreater(len(sg.categories(CONFIG)), 5)

    def test_every_pattern_matches_a_tracked_file(self):
        # A typo in the list silently exempts a path; fail instead.
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        for cat, globs in CONFIG.items():
            if cat == "ackers":
                continue
            for g in globs:
                rx = sg.glob_to_regex(g)
                self.assertTrue(any(rx.match(f) for f in files), f"{cat}: {g} matches no tracked file")

    def test_rejects_unsupported_syntax(self):
        with self.assertRaises(ValueError):
            sg.load_config("ackers:\n  - a\nx: [1, 2]\n")
        with self.assertRaises(ValueError):
            sg.load_config("cat:\n  - a\n")  # no ackers
        with self.assertRaises(ValueError):
            sg.load_config("ackers:\n  - a\nackers:\n  - b\n")

    def test_codeowners_in_sync(self):
        text = (ROOT / ".github/CODEOWNERS").read_text()
        self.assertEqual(sg.splice_codeowners(text, sg.codeowners_block(CONFIG)), text,
                         "run: python3 .github/scripts/security_gate.py codeowners --write")

    def test_splice_is_idempotent(self):
        block = sg.codeowners_block(CONFIG)
        once = sg.splice_codeowners("* @x\n", block)
        self.assertEqual(sg.splice_codeowners(once, block), once)
        self.assertNotIn("removal-only", block)
        self.assertNotIn("# ackers", block)


class ClassifyTest(unittest.TestCase):
    def test_sensitive_and_plain(self):
        hits = sg.classify([F("api/internal/infra/http/middleware/csrf.go"), F("web/src/app/page.tsx")], CONFIG)
        self.assertEqual(hits, {"authn-authz": ["api/internal/infra/http/middleware/csrf.go"]})
        self.assertEqual(sg.classify([F("api/internal/app/asset/service.go"), F("README.md")], CONFIG), {})

    def test_added_test_does_not_count_weakened_test_does(self):
        added = F("api/internal/infra/http/middleware/new_test.go", "func TestX(t *testing.T) {}", status="added")
        self.assertEqual(sg.classify([added], CONFIG), {})
        weakened = F("api/internal/infra/http/middleware/csrf_test.go", deletions=3)
        self.assertIn("authn-authz", sg.classify([weakened], CONFIG))
        removed = F("api/internal/infra/http/middleware/csrf_test.go", status="removed", deletions=40)
        self.assertIn("authn-authz", sg.classify([removed], CONFIG))

    def test_guard_list_addition_is_not_sensitive_removal_is(self):
        self.assertEqual(sg.classify([F("api/tools/lint/tenantsql/tenant_tables.txt", "new_table")], CONFIG), {})
        self.assertIn("tenant-isolation",
                      sg.classify([F("api/tools/lint/tenantsql/tenant_tables.txt", deletions=1)], CONFIG))

    def test_rename_out_of_a_sensitive_path_counts(self):
        f = F("api/internal/app/asset/x.go", status="renamed", prev="api/pkg/httpsec/ssrf.go")
        self.assertIn("outbound-ssrf", sg.classify([f], CONFIG))

    def test_workflow_and_gate_files_are_sensitive(self):
        for name in (".github/workflows/security-gate.yml", ".github/security-paths.yml",
                     ".github/scripts/security_gate.py", ".github/CODEOWNERS"):
            self.assertIn("ci-release", sg.classify([F(name)], CONFIG), name)


class ReviewTest(unittest.TestCase):
    def rules(self, name: str, *lines: str) -> set[str]:
        return {f.rule for f in sg.review([F(name, *lines)])[0]}

    def test_high_rules_fire(self):
        cases = {
            "GO-TLS-NOVERIFY": ("api/internal/x.go", "tls.Config{InsecureSkipVerify: true}"),
            "JWT-UNVERIFIED": ("api/pkg/jwt/x.go", "tok, _, err := p.ParseUnverified(s, c)"),
            "GHA-PR-TARGET": (".github/workflows/x.yml", "  pull_request_target:"),
            "GHA-WRITE-ALL": (".github/workflows/x.yml", "permissions: write-all"),
            "GHA-UNPINNED": (".github/workflows/x.yml", "      - uses: actions/checkout@v4"),
            "GHA-INJECTION": (".github/workflows/x.yml", "        run: echo \"${{ github.event.pull_request.title }}\""),
            "WEB-RAW-HTML": ("web/src/components/x.tsx", "<div dangerouslySetInnerHTML={{ __html: s }} />"),
            "WEB-EVAL": ("web/src/lib/x.ts", "const f = new Function(src)"),
            "SQL-RLS-OFF": ("api/migrations/000001_x.up.sql", "ALTER TABLE assets DISABLE ROW LEVEL SECURITY;"),
        }
        for rule, (name, line) in cases.items():
            findings = sg.review([F(name, line)])[0]
            self.assertIn(rule, {f.rule for f in findings}, rule)
            self.assertEqual({f.severity for f in findings if f.rule == rule}, {"HIGH"}, rule)

    def test_negatives(self):
        self.assertEqual(self.rules(".github/workflows/x.yml",
                                    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                                    "      - uses: ./.github/actions/setup",
                                    "        run: echo \"$TITLE\""), set())
        self.assertEqual(self.rules("api/internal/x_test.go", "InsecureSkipVerify: true"), set())
        self.assertEqual(self.rules("api/internal/x.go", "// InsecureSkipVerify: true is never allowed"), set())
        self.assertEqual(self.rules("web/src/x.test.tsx", "dangerouslySetInnerHTML"), set())
        self.assertEqual(self.rules("api/migrations/000001_x.down.sql", "DROP POLICY p ON t;"), set())
        self.assertEqual(self.rules("api/pkg/httpsec/ssrf.go", "c := &http.Client{}"), set())
        self.assertEqual(self.rules("docs/x.md", "InsecureSkipVerify: true"), set())

    def test_waiver_on_the_same_line(self):
        line = "tls.Config{InsecureSkipVerify: true} // security-review: allow GO-TLS-NOVERIFY loopback probe"
        self.assertEqual(self.rules("api/internal/x.go", line), set())
        other = "tls.Config{InsecureSkipVerify: true} // security-review: allow GO-EXEC wrong rule"
        self.assertEqual(self.rules("api/internal/x.go", other), {"GO-TLS-NOVERIFY"})

    def test_content_rules_mark_sensitive_without_a_finding(self):
        r = sg.Result(1)
        r.findings, _ = sg.review([F("api/migrations/000002_x.up.sql", "INSERT INTO role_permissions (role_id, permission_id)")])
        self.assertTrue(r.sensitive)
        self.assertEqual(r.high, [])
        r.findings, _ = sg.review([F("api/migrations/000002_x.up.sql", "INSERT INTO permissions (id) VALUES ('a:b');")])
        self.assertFalse(r.sensitive)

    def test_line_numbers(self):
        p = "@@ -1,3 +1,4 @@\n a\n-b\n+c\n+d\n e\n@@ -20,1 +21,2 @@\n x\n+y"
        self.assertEqual(list(sg.added_lines(p)), [(2, "c"), (3, "d"), (22, "y")])

    def test_missing_patch_is_reported_unreviewed(self):
        f = sg.ChangedFile("api/internal/big.go", "modified", 0, None)
        self.assertEqual(sg.review([f])[1], ["api/internal/big.go"])


class VerdictTest(unittest.TestCase):
    def test_matrix(self):
        r = sg.Result(1)
        self.assertTrue(r.passed)  # not sensitive
        r.hits = {"authn-authz": ["x"]}
        self.assertFalse(r.passed)  # sensitive, no ack
        r.acked = True
        self.assertTrue(r.passed)
        r.alerts = [{"number": 1}]
        self.assertFalse(r.passed)  # new high alert
        r.alerts = []
        r.findings = [sg.Finding("GO-TLS-NOVERIFY", "HIGH", "x.go", 1, "m", "e")]
        self.assertFalse(r.passed)  # HIGH diff finding
        r.findings = [sg.Finding("GO-EXEC", "MEDIUM", "x.go", 1, "m", "e")]
        self.assertTrue(r.passed)  # MEDIUM does not block

    def test_merge_group_ref(self):
        self.assertEqual(sg.merge_group_pr("refs/heads/gh-readonly-queue/develop/pr-1234-0123abcd"), 1234)
        with self.assertRaises(RuntimeError):
            sg.merge_group_pr("refs/heads/develop")


class DigestTest(unittest.TestCase):
    def digest(self, *files: sg.ChangedFile) -> str:
        files_ = list(files)
        findings, _ = sg.review(files_)
        return sg.sensitive_digest(files_, CONFIG, findings)

    def test_context_and_position_do_not_count(self):
        a = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch="@@ -10,2 +10,3 @@\n ctx\n+x := 1\n ctx2")
        b = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch="@@ -40,2 +52,3 @@\n other\n+x := 1\n other2")
        self.assertEqual(self.digest(a), self.digest(b))

    def test_changed_line_counts(self):
        a = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch=patch("x := 1"))
        b = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch=patch("x := 2"))
        self.assertNotEqual(self.digest(a), self.digest(b))

    def test_plain_files_do_not_count_new_sensitive_files_do(self):
        s = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch=patch("x := 1"))
        plain = sg.ChangedFile("web/src/app/page.tsx", patch=patch("y"))
        self.assertEqual(self.digest(s), self.digest(s, plain))
        mig = sg.ChangedFile("api/migrations/000999_x.up.sql", status="added", patch=patch("GRANT SELECT ON t TO app;"))
        self.assertNotEqual(self.digest(s), self.digest(s, mig))

    def test_missing_patch_uses_the_blob(self):
        a = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch=None, sha="a" * 40)
        b = sg.ChangedFile("api/pkg/httpsec/ssrf.go", patch=None, sha="b" * 40)
        self.assertNotEqual(self.digest(a), self.digest(b))


class FakeGitHub:
    """Serves canned API responses and records writes."""

    def __init__(self, routes: dict[str, object]):
        self.routes, self.writes = routes, []

    def request(self, method, path, body=None, ok404=False):
        if method != "GET":
            self.writes.append((method, path, body))
            return None, ""
        key, _, query = path.split("/repos/o/r/", 1)[-1].partition("?")
        ref = [q for q in query.split("&") if q.startswith("ref=")]
        key += "?" + ref[0] if ref else ""
        if key not in self.routes:
            if ok404:
                return None, ""
            raise RuntimeError(f"unexpected GET {key}")
        return self.routes[key], ""


class GateTest(unittest.TestCase):
    def run_gate(self, event_name, event, routes):
        fake = FakeGitHub(routes)
        with tempfile.TemporaryDirectory() as d:
            ev = pathlib.Path(d, "event.json")
            ev.write_text(json.dumps(event))
            env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "t", "GITHUB_EVENT_NAME": event_name,
                   "GITHUB_EVENT_PATH": str(ev), "SECURITY_PATHS": str(ROOT / ".github/security-paths.yml"),
                   "GITHUB_STEP_SUMMARY": str(pathlib.Path(d, "summary.md")), "INTEGRATION_BRANCH": "develop"}
            with mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch.object(sg.GitHub, "request", lambda self, *a, **k: fake.request(*a, **k)), \
                    mock.patch("builtins.print"):
                code = sg.cmd_gate()
        return code, fake

    def pr(self, labels=(), head_repo="o/r", base="develop", head_ref="feature/x"):
        return {"number": 7, "changed_files": 1, "labels": [{"name": n} for n in labels],
                "head": {"sha": "h" * 40, "ref": head_ref, "repo": {"full_name": head_repo}},
                "base": {"ref": base}}

    def routes(self, pr, files, events=()):
        return {"pulls/7": pr, "pulls/7/files": files, "issues/7/events": list(events),
                "issues/7/comments": [], "commits/" + "h" * 40 + "/check-runs": {"check_runs": []}}

    SENSITIVE = [{"filename": "api/pkg/httpsec/ssrf.go", "status": "modified", "deletions": 1, "patch": patch("x := 1")}]
    PLAIN = [{"filename": "web/src/app/page.tsx", "status": "modified", "deletions": 0, "patch": patch("x")}]
    ACK_BY_OWNER = [{"event": "labeled", "label": {"name": "security-ack"}, "actor": {"login": "0xmanhnv"}}]

    def test_plain_pr_passes_without_comment(self):
        code, fake = self.run_gate("pull_request", {"pull_request": {"number": 7}}, self.routes(self.pr(), self.PLAIN))
        self.assertEqual(code, 0)
        self.assertEqual(fake.writes, [])

    def test_sensitive_without_ack_blocks_labels_and_comments(self):
        code, fake = self.run_gate("pull_request", {"pull_request": {"number": 7}}, self.routes(self.pr(), self.SENSITIVE))
        self.assertEqual(code, 1)
        self.assertIn(("POST", "issues/7/labels", {"labels": ["security-sensitive"]}), fake.writes)
        self.assertTrue(any(m == "POST" and p == "issues/7/comments" for m, p, _ in fake.writes))

    def test_sensitive_with_owner_ack_passes(self):
        routes = self.routes(self.pr(labels=("security-sensitive", "security-ack")), self.SENSITIVE, self.ACK_BY_OWNER)
        code, _ = self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)
        self.assertEqual(code, 0)

    def test_ack_by_someone_else_does_not_count(self):
        events = [{"event": "labeled", "label": {"name": "security-ack"}, "actor": {"login": "someone"}}]
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, events)
        code, _ = self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)
        self.assertEqual(code, 1)

    def test_new_high_alert_blocks_even_with_ack(self):
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["code-scanning/alerts?ref=refs/pull/7/merge"] = [
            {"number": 9, "rule": {"security_severity_level": "high"}},
            {"number": 3, "rule": {"security_severity_level": "critical"}}]
        routes["code-scanning/alerts?ref=refs/heads/develop"] = [{"number": 3}]  # pre-existing on develop
        code, _ = self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)
        self.assertEqual(code, 1)

    def test_push_of_sensitive_change_drops_ack(self):
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["compare/a...b"] = {"status": "ahead", "files": [{"filename": "api/pkg/httpsec/ssrf.go", "deletions": 1}]}
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 1)
        self.assertIn(("DELETE", "issues/7/labels/security-ack", None), fake.writes)

    def test_merging_the_base_branch_keeps_ack(self):
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["compare/a...b"] = {"status": "ahead", "files": [{"filename": "api/pkg/crypto/cipher.go", "deletions": 1}]}
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 0)
        self.assertNotIn(("DELETE", "issues/7/labels/security-ack", None), fake.writes)

    def test_force_push_drops_ack(self):
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["compare/a...b"] = {"status": "diverged", "files": []}
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, _ = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 1)

    # The ack covers the sensitive diff, recorded as a digest in the gate comment.

    def comment(self, files, login="github-actions[bot]"):
        fs = [sg.changed_file(f) for f in files]
        d = sg.sensitive_digest(fs, CONFIG, sg.review(fs)[0])
        body = f"{sg.COMMENT_MARKER}\nold\n<!-- security-gate:ack-digest={d} -->\n"
        return [{"id": 5, "body": body, "user": {"login": login}}]

    def test_ack_label_event_records_the_digest(self):
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        event = {"action": "labeled", "label": {"name": "security-ack"}, "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 0)
        posted = [b["body"] for m, p, b in fake.writes if m == "POST" and p == "issues/7/comments"]
        self.assertEqual(len(posted), 1)
        self.assertIn(self.comment(self.SENSITIVE)[0]["body"].splitlines()[-1], posted[0])

    def test_base_merge_touching_the_sensitive_file_keeps_ack(self):
        # develop changed other lines of the same file: the compare lists it, the PR's own lines are the same.
        moved = [dict(self.SENSITIVE[0], patch=patch("x := 1", start=80))]
        routes = self.routes(self.pr(labels=("security-ack",)), moved, self.ACK_BY_OWNER)
        routes["issues/7/comments"] = self.comment(self.SENSITIVE)
        routes["compare/a...b"] = {"status": "ahead", "files": [{"filename": "api/pkg/httpsec/ssrf.go", "deletions": 3}]}
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 0)
        self.assertFalse(any(m == "DELETE" for m, _, _ in fake.writes))

    def test_changed_sensitive_line_drops_ack(self):
        changed = [dict(self.SENSITIVE[0], patch=patch("x := 2"))]
        routes = self.routes(self.pr(labels=("security-ack",)), changed, self.ACK_BY_OWNER)
        routes["issues/7/comments"] = self.comment(self.SENSITIVE)
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 1)
        self.assertIn(("DELETE", "issues/7/labels/security-ack", None), fake.writes)
        patched = [b["body"] for m, p, b in fake.writes if m == "PATCH"]
        self.assertTrue(patched and "ack-digest" not in patched[0] and "was removed" in patched[0])

    def test_digest_in_a_comment_someone_else_wrote_is_ignored(self):
        # A planted marker comment cannot vouch for a push that touches the sensitive file.
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["issues/7/comments"] = self.comment(self.SENSITIVE, login="someone")
        routes["compare/a...b"] = {"status": "ahead", "files": [{"filename": "api/pkg/httpsec/ssrf.go", "deletions": 1}]}
        event = {"action": "synchronize", "before": "a", "after": "b", "pull_request": {"number": 7}}
        code, fake = self.run_gate("pull_request", event, routes)
        self.assertEqual(code, 1)
        self.assertIn(("DELETE", "issues/7/labels/security-ack", None), fake.writes)

    def test_merge_group_with_a_changed_digest_blocks_without_writing(self):
        event = {"merge_group": {"head_ref": "refs/heads/gh-readonly-queue/develop/pr-7-abc123"}}
        changed = [dict(self.SENSITIVE[0], patch=patch("x := 2"))]
        routes = self.routes(self.pr(labels=("security-ack",)), changed, self.ACK_BY_OWNER)
        routes["issues/7/comments"] = self.comment(self.SENSITIVE)
        code, fake = self.run_gate("merge_group", event, routes)
        self.assertEqual((code, fake.writes), (1, []))
        routes["pulls/7/files"] = self.SENSITIVE
        code, fake = self.run_gate("merge_group", event, routes)
        self.assertEqual((code, fake.writes), (0, []))

    def test_fork_pr_is_read_only(self):
        code, fake = self.run_gate("pull_request", {"pull_request": {"number": 7}},
                                   self.routes(self.pr(head_repo="fork/r"), self.SENSITIVE))
        self.assertEqual(code, 1)
        self.assertEqual(fake.writes, [])

    def test_merge_group_reads_labels_and_never_writes(self):
        event = {"merge_group": {"head_ref": "refs/heads/gh-readonly-queue/develop/pr-7-abc123"}}
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        code, fake = self.run_gate("merge_group", event, routes)
        self.assertEqual((code, fake.writes), (0, []))
        routes = self.routes(self.pr(), self.SENSITIVE)
        code, fake = self.run_gate("merge_group", event, routes)
        self.assertEqual((code, fake.writes), (1, []))

    def test_merge_group_ignores_stale_alerts_on_the_pr_merge_ref(self):
        """The PR merge ref keeps an old analysis; the group's own ref decides."""
        ref = "refs/heads/gh-readonly-queue/develop/pr-7-abc123"
        event = {"merge_group": {"head_ref": ref}}
        routes = self.routes(self.pr(labels=("security-ack",)), self.SENSITIVE, self.ACK_BY_OWNER)
        routes["code-scanning/alerts?ref=refs/pull/7/merge"] = [{"number": 9, "rule": {"security_severity_level": "high"}}]
        routes["code-scanning/alerts?ref=" + ref] = [{"number": 1, "rule": {"security_severity_level": "low"}}]
        routes["code-scanning/alerts?ref=refs/heads/develop"] = []
        self.assertEqual(self.run_gate("merge_group", event, routes)[0], 0)
        routes["code-scanning/alerts?ref=" + ref] = [{"number": 9, "rule": {"security_severity_level": "high"}}]
        self.assertEqual(self.run_gate("merge_group", event, routes)[0], 1)

    def test_release_pr_evaluates_only_what_it_adds_to_develop(self):
        pr = self.pr(base="main", head_ref="release/v1.2.3")
        routes = self.routes(pr, self.SENSITIVE)  # the full diff carries develop's sensitive change
        routes["compare/develop..." + "h" * 40] = {"files": [{"filename": "versions.yaml", "status": "modified",
                                                             "deletions": 1, "patch": patch("v: 1.2.3")}]}
        code, _ = self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)
        self.assertEqual(code, 0)
        routes["compare/develop..." + "h" * 40] = {"files": self.SENSITIVE}
        code, _ = self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)
        self.assertEqual(code, 1)

    def test_release_pr_without_integration_branch_uses_its_own_diff(self):
        pr = self.pr(base="main", head_ref="release/v1.2.3")
        with mock.patch.dict(os.environ, {"INTEGRATION_BRANCH": ""}):
            self.assertIsNone(sg.release_files(None, pr))

    def test_api_error_fails_closed(self):
        routes = self.routes(self.pr(), self.SENSITIVE)
        del routes["pulls/7/files"]
        with self.assertRaises(RuntimeError):
            self.run_gate("pull_request", {"pull_request": {"number": 7}}, routes)


if __name__ == "__main__":
    unittest.main()
