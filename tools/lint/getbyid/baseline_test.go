package getbyid_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// Q1/WS-F: regression test for the F-310 linter baseline.
//
// Strategy: run the analyzer against the postgres repo package and
// assert the number of diagnostics matches the agreed ceiling. When
// someone adds a NEW unscoped GetByID on a tenant-scoped table, this
// test fails with a diff, forcing them to either:
//   - add a //getbyid:unsafe opt-out with justification (Category A/B), or
//   - add a GetByTenantAndID variant (Category C migration).
//
// The ceiling is intentionally conservative — it goes down over time as
// the Category C migration progresses, never up. A blocking CI rule
// wrapping this test is the "flip to blocking" half of the task.

// baselineCeiling is the agreed maximum number of diagnostics. Must
// never go UP without review. After every Category C migration PR the
// maintainer drops this number to match the new reality.
const baselineCeiling = 40

func TestGetByIDLinter_BaselineNotRegressed(t *testing.T) {
	if testing.Short() {
		t.Skip("baseline lint takes a couple of seconds")
	}
	cmd := exec.Command("go", "run", "./cmd",
		"../../../internal/infra/postgres/...",
	)
	// The analyzer exits non-zero when it reports diagnostics — that
	// is the whole point. We capture stderr to count them and fail
	// only if the count exceeds the ceiling.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(cmd.Environ(), "GOWORK=off")
	_ = cmd.Run()

	got := countDiagnostics(stderr.String())
	if got > baselineCeiling {
		t.Fatalf("F-310 linter reported %d diagnostics, ceiling %d — regression detected.\n\nOutput:\n%s",
			got, baselineCeiling, stderr.String())
	}
	// We don't fail on *fewer* diagnostics — that's progress. But we
	// log it so the reviewer knows the ceiling can drop.
	if got < baselineCeiling {
		t.Logf("baseline improved: %d diagnostics (ceiling %d). Consider lowering baselineCeiling.",
			got, baselineCeiling)
	}
}

func countDiagnostics(output string) int {
	// Analyzer output format: "<file>:<line>:<col>: <message>".
	// We count lines containing the diagnostic message marker to be
	// robust to other chatter in the output.
	n := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "has no tenantID parameter") {
			n++
		}
	}
	return n
}
