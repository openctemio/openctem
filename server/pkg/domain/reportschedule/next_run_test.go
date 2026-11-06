package reportschedule

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A schedule used to be created with next_run_at = NULL. The scheduler's
// ListDue selects NULLS FIRST, so every new schedule delivered a report on the
// next tick whatever its cron said, and editing the cron or timezone kept the
// old next run. next_run_at is now computed from cron + timezone on create and
// on every change to cron, timezone or enabled state.

// nextLocal returns the next hh:00 wall-clock time in loc strictly after t.
func nextLocal(t time.Time, loc *time.Location, hour int) time.Time {
	l := t.In(loc)
	c := time.Date(l.Year(), l.Month(), l.Day(), hour, 0, 0, 0, loc)
	if !c.After(l) {
		c = c.AddDate(0, 0, 1)
	}
	return c
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNewReportSchedule_SetsNextRunFromCron(t *testing.T) {
	before := time.Now()
	s, err := NewReportSchedule(shared.NewID(), "Daily", "executive_summary", "pdf", "0 9 * * *")
	if err != nil {
		t.Fatal(err)
	}
	if s.NextRunAt() == nil {
		t.Fatal("a new schedule has no next_run_at, so the scheduler sends it immediately")
	}
	want := nextLocal(before, time.UTC, 9)
	if !s.NextRunAt().Equal(want) {
		t.Fatalf("next run = %v, want %v (next 09:00 UTC)", s.NextRunAt(), want)
	}
}

func TestReportSchedule_UpdateRecomputesNextRunInTimezone(t *testing.T) {
	s, err := NewReportSchedule(shared.NewID(), "Daily", "executive_summary", "pdf", "0 9 * * *")
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if err := s.Update("", "executive_summary", "pdf", "0 9 * * *", "Asia/Ho_Chi_Minh"); err != nil {
		t.Fatal(err)
	}
	want := nextLocal(before, mustLoc(t, "Asia/Ho_Chi_Minh"), 9)
	if s.NextRunAt() == nil || !s.NextRunAt().Equal(want) {
		t.Fatalf("after setting Asia/Ho_Chi_Minh: next run = %v, want %v (09:00 +07)", s.NextRunAt(), want)
	}

	// Changing the cron moves the next run too.
	if err := s.Update("", "executive_summary", "pdf", "0 18 * * *", ""); err != nil {
		t.Fatal(err)
	}
	want = nextLocal(time.Now(), mustLoc(t, "Asia/Ho_Chi_Minh"), 18)
	if !s.NextRunAt().Equal(want) {
		t.Fatalf("after cron change: next run = %v, want %v (18:00 +07)", s.NextRunAt(), want)
	}
}

func TestReportSchedule_ActivateRecomputesStaleNextRun(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)
	now := time.Now()
	s := ReconstituteReportSchedule(shared.NewID(), shared.NewID(), "Daily", "executive_summary", "pdf",
		map[string]any{}, nil, "email", nil, "0 9 * * *", "Asia/Ho_Chi_Minh", false,
		nil, &past, "", 0, nil, now, now)

	s.Activate()
	if s.NextRunAt() == nil || !s.NextRunAt().After(now) {
		t.Fatalf("re-enabling kept a next run in the past (%v), so it would fire immediately", s.NextRunAt())
	}
	if want := nextLocal(now, mustLoc(t, "Asia/Ho_Chi_Minh"), 9); !s.NextRunAt().Equal(want) {
		t.Fatalf("next run = %v, want %v", s.NextRunAt(), want)
	}
}

func TestReportSchedule_NextFireAfter_TimezoneAndFallback(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	mk := func(tz string) *ReportSchedule {
		return ReconstituteReportSchedule(shared.NewID(), shared.NewID(), "Daily", "executive_summary", "pdf",
			map[string]any{}, nil, "email", nil, "0 9 * * *", tz, true, nil, nil, "", 0, nil, now, now)
	}
	cases := map[string]time.Time{
		"Asia/Ho_Chi_Minh": time.Date(2026, 10, 2, 2, 0, 0, 0, time.UTC),
		"America/New_York": time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC),
		"UTC":              time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		"":                 time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		"Not/AZone":        time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
	}
	for tz, want := range cases {
		got, err := mk(tz).NextFireAfter(now)
		if err != nil || !got.Equal(want) {
			t.Errorf("tz=%q: NextFireAfter = %v, %v; want %v", tz, got, err, want)
		}
	}
}
