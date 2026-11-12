package remediation

import (
	"testing"
	"time"
)

func TestDeriveState(t *testing.T) {
	hold, cancel := ManualStateOnHold, ManualStateCanceled
	cases := []struct {
		name     string
		manual   *ManualState
		archived bool
		c        TaskCounts
		want     TaskState
	}{
		{"archived wins", &cancel, true, TaskCounts{Total: 2, Open: 2}, TaskStateArchived},
		{"canceled", &cancel, false, TaskCounts{Total: 2, Open: 2}, TaskStateCanceled},
		{"on hold", &hold, false, TaskCounts{Total: 2, Closed: 2, Verified: 2}, TaskStateOnHold},
		{"no members", nil, false, TaskCounts{}, TaskStateOpen},
		{"all open", nil, false, TaskCounts{Total: 3, Open: 3}, TaskStateOpen},
		{"one in progress", nil, false, TaskCounts{Total: 3, Open: 2, InProgress: 1}, TaskStateInProgress},
		{"one claimed fixed", nil, false, TaskCounts{Total: 3, Open: 2, FixApplied: 1}, TaskStateInProgress},
		{"every open member claimed", nil, false, TaskCounts{Total: 3, FixApplied: 2, Closed: 1}, TaskStateVerifying},
		{"closed, one verified", nil, false, TaskCounts{Total: 3, Closed: 3, Verified: 1}, TaskStateDone},
		{"closed, none verified", nil, false, TaskCounts{Total: 3, Closed: 3}, TaskStateClosedUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveState(tc.manual, tc.archived, tc.c); got != tc.want {
				t.Fatalf("DeriveState = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEffectiveDeadlineOnlyTightens(t *testing.T) {
	base := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	member, earlier, later := base, base.Add(-48*time.Hour), base.Add(240*time.Hour)

	if dl, src := EffectiveDeadline(nil, nil, nil); dl != nil || src != nil {
		t.Fatalf("no input: got %v %v", dl, src)
	}
	dl, src := EffectiveDeadline(&member, &later, &later)
	if !dl.Equal(member) || *src != DeadlineSourceMember {
		t.Fatalf("a later manual or campaign deadline must not extend: %v %v", dl, *src)
	}
	dl, src = EffectiveDeadline(&member, &earlier, nil)
	if !dl.Equal(earlier) || *src != DeadlineSourceManual {
		t.Fatalf("an earlier manual deadline tightens: %v %v", dl, *src)
	}
	dl, src = EffectiveDeadline(&member, nil, &earlier)
	if !dl.Equal(earlier) || *src != DeadlineSourceCampaign {
		t.Fatalf("an earlier campaign deadline tightens: %v %v", dl, *src)
	}
	dl, src = EffectiveDeadline(nil, &later, nil)
	if !dl.Equal(later) || *src != DeadlineSourceManual {
		t.Fatalf("a manual deadline alone applies: %v %v", dl, *src)
	}
}

func TestTaskStateTerminal(t *testing.T) {
	for _, s := range AllTaskStates() {
		want := s == TaskStateDone || s == TaskStateClosedUnverified || s == TaskStateCanceled || s == TaskStateArchived
		if s.IsTerminal() != want {
			t.Errorf("%s terminal = %v, want %v", s, s.IsTerminal(), want)
		}
	}
}
