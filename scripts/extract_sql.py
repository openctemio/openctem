#!/usr/bin/env python3
"""Extract preparable SQL literals from the Go sources.

Emits one `location<TAB>statement` line per candidate, where the statement has
newlines escaped as \\n so a single record stays on one line.

The bar for emitting a statement is deliberately high: it must be a complete,
self-contained SQL string. Anything assembled at runtime (fmt.Sprintf, string
concatenation, strings.Join) is dropped rather than guessed at, because a
half-reconstructed statement would fail to parse and produce a false alarm —
and a gate that cries wolf gets switched off. scripts/check-sql-schema.sh states
that residual gap in its output instead of pretending to full coverage.
"""
import os
import re
import sys

# A candidate must start with one of these verbs (after optional whitespace).
STARTS = re.compile(r"^\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WITH)\b", re.I)

# Signals that the literal is only a FRAGMENT or is completed at runtime.
DYNAMIC = (
    "%s", "%d", "%q", "%v",   # fmt verbs
    "` +", "`+",              # Go string concatenation onto the literal
)

# Directories that hold test fixtures or generated code rather than live queries.
SKIP_DIRS = {"vendor", "node_modules", ".git", "docs", "tests", ".claude"}


def candidates(path):
    """Yield (line_number, sql) for each backtick-quoted SQL literal in a file."""
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return

    for m in re.finditer(r"`([^`]*)`", src, re.S):
        raw = m.group(1)
        if not STARTS.match(raw):
            continue
        if any(tok in raw for tok in DYNAMIC):
            continue
        # A trailing fragment (no closing paren balance) usually means the query
        # is continued in code; requiring balance keeps us to whole statements.
        if raw.count("(") != raw.count(")"):
            continue
        # A SELECT with no FROM is a projection fragment that the caller
        # concatenates with a base query built elsewhere — preparing it alone
        # yields a bogus "column does not exist". Requiring FROM is what keeps
        # this gate free of the false alarms that get a check switched off.
        # Collapse whitespace first: a FROM that begins an indented line is
        # preceded by a newline or tab, not a space, and matching the raw text
        # silently dropped every such query from the gate (342 of them).
        head = raw.lstrip()[:6].upper()
        if head.startswith("SELECT") and " FROM " not in " ".join(raw.split()).upper():
            continue
        # schema_migrations is created by the migration tool at runtime, not by
        # any migrations/*.sql, so it is legitimately absent from this schema.
        if "schema_migrations" in raw:
            continue
        # Skip literals that are one operand of a string concatenation: the rest
        # of the statement lives in the other operand, so preparing this half
        # alone invents errors. This is how `SELECT ... FROM component_findings`
        # looked broken — component_findings is a CTE defined in the baseCTE
        # string prepended to it.
        before = src[max(0, m.start() - 40):m.start()]
        after = src[m.end():m.end() + 40]
        if before.rstrip().endswith("+") or after.lstrip().startswith("+"):
            continue
        # Opt-out for SQL that intentionally targets a table this schema does not
        # (and should not) have — e.g. a legacy table the code probes with
        # information_schema before touching. Mirrors the expand-contract-ok
        # marker used by the migration gate: an escape hatch that must be
        # justified in the comment, so it can be reviewed rather than hidden.
        if "sqlgate:optional" in src[max(0, m.start() - 400):m.start()]:
            continue
        line = src.count("\n", 0, m.start()) + 1
        yield line, " ".join(strip_line_comments(raw).split())


def strip_line_comments(sql):
    """Drop SQL `--` comments, which run to the end of their line.

    The statement is emitted on ONE line, so a comment left in place would
    swallow everything after it — including the terminating `;` — and the
    unterminated PREPARE then absorbed every following statement in the batch
    into a single syntax error, which the gate ignores. That silently cut
    verification from all statements down to the ones before the first
    commented query. Quotes are tracked so a `--` inside a string survives.
    """
    out = []
    i, n, in_str = 0, len(sql), False
    while i < n:
        c = sql[i]
        if in_str:
            out.append(c)
            if c == "'":
                in_str = False
            i += 1
        elif c == "'":
            in_str = True
            out.append(c)
            i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if not fn.endswith(".go") or fn.endswith("_test.go"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            for line, sql in candidates(full):
                # Tabs and newlines are the record/field separators downstream.
                safe = sql.replace("\\", "\\\\").replace("\t", " ")
                print(f"{rel}:{line}\t{safe}")


if __name__ == "__main__":
    main()
