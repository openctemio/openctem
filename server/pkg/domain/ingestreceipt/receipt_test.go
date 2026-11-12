package ingestreceipt

import "testing"

// Unaccounted is zero only when every received finding has a count or an
// outcome; split adds to the received side, closed and untouched are not
// part of the sum.
func TestUnaccounted(t *testing.T) {
	untouched := 9
	c := Counts{Created: 2, StillDetected: 3, Reopened: 1, Suppressed: 1, Failed: 1, Skipped: 2, Closed: 7, Untouched: &untouched}
	out := map[string]int{OutcomeMerged: 4, OutcomeExposure: 1, OutcomeQuarantined: 0, OutcomeSplit: 2}
	if n := Unaccounted(13, c, out); n != 0 {
		t.Fatalf("reconciled receipt: %d unaccounted", n)
	}
	if n := Unaccounted(15, c, out); n != 2 {
		t.Fatalf("two findings in no column: %d", n)
	}
	if n := Unaccounted(12, c, out); n != -1 {
		t.Fatalf("over-counted: %d", n)
	}
}

func TestQuarantinedIsAnOutcome(t *testing.T) {
	if !IsOutcome(OutcomeQuarantined) {
		t.Fatal("quarantined is not an outcome code")
	}
}
