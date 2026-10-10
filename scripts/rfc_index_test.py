#!/usr/bin/env python3
"""Tests for rfc_index.py. Run: python3 scripts/rfc_index_test.py"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rfc_index as ri  # noqa: E402


class StatusTest(unittest.TestCase):
    def s(self, text):
        return ri.status_of(text.splitlines(), "RFC-999-x.md")

    def test_header_forms(self):
        self.assertEqual(self.s("- **Status**: Implemented"), "Implemented")
        self.assertEqual(self.s("**Status:** Proposed. More detail."), "Proposed.")
        self.assertEqual(self.s("| | |\n|---|---|\n| Status | Accepted (2026-10-10) |\n| Scope | api |"), "Accepted (2026-10-10)")

    def test_blockquote_continuation_stops_at_next_field(self):
        text = "> Status: **Accepted** (2026-10-02; decisions\n> in §12). P0 shipped.\n> Scope: api"
        self.assertEqual(self.s(text), "**Accepted** (2026-10-02; decisions in §12).")

    def test_dot_inside_code_or_parens_is_not_a_sentence_end(self):
        self.assertEqual(self.s("> Status: Implemented (v0.5. tag) in `a. b` now. Later."), "Implemented (v0.5. tag) in `a. b` now.")

    def test_pipe_is_escaped(self):
        self.assertEqual(ri.cell("a | b"), r"a \| b")

    def test_missing_status_fails(self):
        with self.assertRaises(ri.IndexError_):
            self.s("> Scope: api")


class RepoTest(unittest.TestCase):
    def test_readme_is_current(self):
        current = ri.README.read_text(encoding="utf-8")
        self.assertEqual(ri.render(current, ri.collect()), current, "run python3 scripts/rfc_index.py")


if __name__ == "__main__":
    unittest.main()
