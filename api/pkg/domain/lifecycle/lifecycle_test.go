package lifecycle

import (
	"testing"
	"time"
)

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func TestNext_OneStepAtATime(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		cur  Stage
		idle int
		want Stage
	}{
		{StageActive, 10, StageActive},
		{StageActive, 59, StageActive},
		{StageActive, 60, StageReminded},
		{StageActive, 200, StageReminded}, // never skips the reminder
		{StageReminded, 89, StageReminded},
		{StageReminded, 90, StageReadOnly},
		{StageReminded, 200, StageReadOnly},
		{StageReadOnly, 112, StageReadOnly},
		{StageReadOnly, 113, StageFinalWarning},
		{StageFinalWarning, 119, StageFinalWarning},
		{StageFinalWarning, 120, StageDeletionDue},
		{StageDeletionDue, 400, StageDeletionDue},
		{StageDeletionDue, 3, StageActive}, // a sign-in resets from any stage
		{StageReadOnly, 0, StageActive},
		{"", 61, StageReminded},
	}
	for _, c := range cases {
		if got := th.Next(c.cur, days(c.idle)); got != c.want {
			t.Errorf("Next(%q, %dd) = %q, want %q", c.cur, c.idle, got, c.want)
		}
	}
}

func TestDecide_WaitsBetweenWarningsAndHonoursExemption(t *testing.T) {
	th := DefaultThresholds()
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	created := now.Add(-days(400))

	// Reminded two days ago after an outage; idle for 150 days: the
	// read-only step waits until a week after the reminder.
	w := Workspace{Stage: StageReminded, StageChangedAt: now.Add(-days(2)), CreatedAt: created, LastSignIn: now.Add(-days(150))}
	if got := th.Decide(w, now); got != StageReminded {
		t.Fatalf("got %q, want reminded (gap)", got)
	}
	w.StageChangedAt = now.Add(-days(8))
	if got := th.Decide(w, now); got != StageReadOnly {
		t.Fatalf("got %q, want read_only", got)
	}

	w.Exempt = true
	if got := th.Decide(w, now); got != StageActive {
		t.Fatalf("exempt: got %q", got)
	}

	// No sign-in ever: idle since creation.
	fresh := Workspace{Stage: StageActive, CreatedAt: now.Add(-days(10))}
	if got := th.Decide(fresh, now); got != StageActive {
		t.Fatalf("new organization: got %q", got)
	}
	old := Workspace{Stage: StageActive, CreatedAt: now.Add(-days(61))}
	if got := th.Decide(old, now); got != StageReminded {
		t.Fatalf("never signed in for 61 days: got %q", got)
	}

	// A sign-in returns to active at once, whatever the gap.
	back := Workspace{Stage: StageFinalWarning, StageChangedAt: now.Add(-days(1)), CreatedAt: created, LastSignIn: now.Add(-time.Hour)}
	if got := th.Decide(back, now); got != StageActive {
		t.Fatalf("signed in: got %q", got)
	}
	// An unknown stored stage is treated as active.
	odd := Workspace{Stage: Stage("bogus"), CreatedAt: created, LastSignIn: now.Add(-days(70))}
	if got := th.Decide(odd, now); got != StageReminded {
		t.Fatalf("unknown stage: got %q", got)
	}
}

func TestStageReadOnly(t *testing.T) {
	for s, want := range map[Stage]bool{
		StageActive: false, StageReminded: false, StageReadOnly: true, StageFinalWarning: true, StageDeletionDue: true,
	} {
		if s.ReadOnly() != want {
			t.Errorf("%s.ReadOnly() = %v", s, !want)
		}
	}
}
