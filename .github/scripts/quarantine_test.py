#!/usr/bin/env python3
"""Tests for quarantine.py. Run: python3 .github/scripts/quarantine_test.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quarantine as q  # noqa: E402

GO = "go:github.com/openctemio/openctem/api/tests/integration.TestIngest_ConcurrentResightings"
PW = "pw:e2e/specs/19-scan-lifecycle.spec.ts::a single scan: create, edit, run"


def entry(test=GO, added="2026-10-25", fix_by="2026-11-01", **kw):
    e = {"test": test, "issue": "3031", "owner": "ingest", "added": added, "fix_by": fix_by, "reason": "race"}
    e.update(kw)
    return e


NAMES = {"TestIngest_ConcurrentResightings": {"github.com/openctemio/openctem/api/tests/integration"}}


class Parse(unittest.TestCase):
    def test_list(self):
        text = f"# c\n- test: {GO}\n  issue: 3031\n  owner: ingest\n  added: 2026-10-25\n  fix_by: 2026-11-01\n  reason: r # note\n"
        self.assertEqual(q.parse(text), [entry(reason="r")])

    def test_empty(self):
        self.assertEqual(q.parse("# nothing\n[]\n"), [])

    def test_quoted_value_keeps_colons(self):
        e = q.parse(f'- test: "{PW}"\n')[0]
        self.assertEqual(e["test"], PW)

    def test_bad_line(self):
        with self.assertRaises(ValueError):
            q.parse("test: x\n")

    def test_duplicate_key(self):
        with self.assertRaises(ValueError):
            q.parse("- test: a\n  test: b\n")


class Problems(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(q.problems([entry(), entry(test=PW)], NAMES), [])

    def test_missing_field(self):
        e = entry()
        del e["owner"]
        self.assertIn("missing owner", q.problems([e])[0])

    def test_sla(self):
        self.assertTrue(q.problems([entry(fix_by="2026-11-20")]))
        self.assertTrue(q.problems([entry(fix_by="2026-10-01")]))

    def test_security_tests_refused(self):
        for name in ("TestTenantIsolation_X", "TestCrossTenantRead", "TestAuthzMatrix", "TestScopeGate",
                     "TestDashboardCTEMWidgets_ScopeAndParity_DB", "TestRLSPolicy", "TestSecretRedaction"):
            t = f"go:github.com/openctemio/openctem/api/tests/integration.{name}"
            names = {name: {"github.com/openctemio/openctem/api/tests/integration"}}
            self.assertTrue(any("security test" in p for p in q.problems([entry(test=t)], names)), name)
        self.assertTrue(q.problems([entry(test="pw:e2e/specs/x.spec.ts::tenant switch keeps data apart")]))

    def test_unknown_or_ambiguous_go_name(self):
        self.assertTrue(q.problems([entry()], {}))
        two = {"TestIngest_ConcurrentResightings": {"github.com/openctemio/openctem/api/tests/integration",
                                                     "github.com/openctemio/openctem/api/internal/app/ingest"}}
        self.assertTrue(any("also exists" in p for p in q.problems([entry()], two)))

    def test_bad_test_id(self):
        self.assertTrue(q.problems([entry(test="TestX")]))
        self.assertTrue(q.problems([entry(test="pw:../x.spec.ts::t")]))

    def test_duplicate(self):
        self.assertTrue(any("twice" in p for p in q.problems([entry(), entry()], NAMES)))


class Active(unittest.TestCase):
    def setUp(self):
        self.old = os.environ.get("QUARANTINE_TODAY")

    def tearDown(self):
        if self.old is None:
            os.environ.pop("QUARANTINE_TODAY", None)
        else:
            os.environ["QUARANTINE_TODAY"] = self.old

    def test_expiry(self):
        os.environ["QUARANTINE_TODAY"] = "2026-11-01"
        self.assertEqual(len(q.active([entry()])), 1)
        os.environ["QUARANTINE_TODAY"] = "2026-11-02"
        self.assertEqual(q.active([entry()]), [])


if __name__ == "__main__":
    unittest.main()
