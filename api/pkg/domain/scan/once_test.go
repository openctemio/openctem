package scan

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newOnceScan(t *testing.T) *Scan {
	t.Helper()
	sc, err := NewScan(shared.NewID(), "once", shared.NewID(), ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = StatusActive
	return sc
}

func TestSetOnceSchedule_Validation(t *testing.T) {
	now := time.Now()
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	for _, tc := range []struct {
		name  string
		runAt *time.Time
		tz    string
		ok    bool
	}{
		{"in an hour", at(time.Hour), "Asia/Ho_Chi_Minh", true},
		{"default timezone", at(48 * time.Hour), "", true},
		{"missing", nil, "UTC", false},
		{"past", at(-time.Hour), "UTC", false},
		{"too soon", at(10 * time.Second), "UTC", false},
		{"too far", at(400 * 24 * time.Hour), "UTC", false},
		{"unknown timezone", at(time.Hour), "Mars/Base", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := newOnceScan(t)
			err := sc.SetOnceSchedule(tc.runAt, tc.tz, now)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want a validation error", err)
			}
		})
	}
}

// The one-off run is the scan's next run until it is claimed; after that the
// scan has no next run, and it is not run again.
func TestOnceSchedule_RunsOnce(t *testing.T) {
	sc := newOnceScan(t)
	runAt := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := sc.SetOnceSchedule(&runAt, "Europe/Paris", time.Now()); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleType != ScheduleOnce || sc.ScheduleTimezone != "Europe/Paris" {
		t.Fatalf("type %s tz %s", sc.ScheduleType, sc.ScheduleTimezone)
	}
	if sc.NextRunAt == nil || !sc.NextRunAt.Equal(runAt) {
		t.Fatalf("next_run_at = %v, want %v", sc.NextRunAt, runAt)
	}
	if occ := sc.UpcomingOccurrences(time.Now(), 5); len(occ) != 1 || !occ[0].Equal(runAt) {
		t.Fatalf("upcoming = %v, want just %v", occ, runAt)
	}
	// The scheduler claims the due occurrence: what follows is nothing.
	sc.NextRunAt = &runAt
	if next := sc.OccurrenceAfter(runAt); next != nil {
		t.Fatalf("after the run: next = %v, want none", next)
	}
	// Resuming after the time has passed does not revive it.
	sc.Status = StatusPaused
	sc.computeNextRunAt()
	sc.Status = StatusActive
	if next := sc.OccurrenceAfter(runAt.Add(time.Minute)); next != nil {
		t.Fatalf("resumed past the run: next = %v", next)
	}
}

func TestOnceSchedule_OtherSchedulesClearRunAt(t *testing.T) {
	sc := newOnceScan(t)
	runAt := time.Now().Add(time.Hour)
	if err := sc.SetOnceSchedule(&runAt, "UTC", time.Now()); err != nil {
		t.Fatal(err)
	}
	tod := time.Date(0, 1, 1, 2, 0, 0, 0, time.UTC)
	if err := sc.SetSchedule(ScheduleDaily, "", nil, &tod, "UTC"); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleRunAt != nil {
		t.Fatal("daily schedule kept the one-off run")
	}
	if err := sc.SetOnceSchedule(&runAt, "UTC", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sc.SetRRuleSchedule("FREQ=DAILY;BYHOUR=3", "UTC"); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleRunAt != nil {
		t.Fatal("rrule schedule kept the one-off run")
	}
}

// Clone used to drop the RRULE (an rrule clone had no rule and never ran).
func TestClone_KeepsRRuleAndRunAt(t *testing.T) {
	sc := newOnceScan(t)
	if err := sc.SetRRuleSchedule("FREQ=WEEKLY;BYDAY=MO;BYHOUR=2", "UTC"); err != nil {
		t.Fatal(err)
	}
	if c := sc.Clone("copy"); c.ScheduleRRule != sc.ScheduleRRule || c.NextRunAt == nil {
		t.Fatalf("rrule clone: rule %q next %v", c.ScheduleRRule, c.NextRunAt)
	}
	runAt := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := sc.SetOnceSchedule(&runAt, "UTC", time.Now()); err != nil {
		t.Fatal(err)
	}
	if c := sc.Clone("copy 2"); c.ScheduleRunAt == nil || !c.ScheduleRunAt.Equal(runAt) || c.NextRunAt == nil {
		t.Fatalf("once clone: run_at %v next %v", c.ScheduleRunAt, c.NextRunAt)
	}
}
