package scan

// Schedules across daylight-saving changes: one run per period, at the
// requested wall time, or right after the gap when that time does not exist.

import (
	"testing"
	"time"
)

func dstScan(t *testing.T, typ ScheduleType, day *int, hh, mm int, tz string) *Scan {
	t.Helper()
	sc := newScheduledScan(t)
	at := time.Date(0, 1, 1, hh, mm, 0, 0, time.UTC)
	if err := sc.SetSchedule(typ, "", day, &at, tz); err != nil {
		t.Fatal(err)
	}
	return sc
}

func localStrings(t *testing.T, got []time.Time, tz string) []string {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(got))
	for i, g := range got {
		out[i] = g.In(loc).Format("2006-01-02 15:04 MST")
	}
	return out
}

func assertSeq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("occurrence %d: got %v, want %v", i, got, want)
		}
	}
}

func TestOccurrence_DailyAcrossSpringForward_OneRunPerDay(t *testing.T) {
	sc := dstScan(t, ScheduleDaily, nil, 2, 30, "America/New_York")
	// 2026-03-08: clocks go 02:00 EST -> 03:00 EDT in New York.
	got := sc.UpcomingOccurrences(mustTime(t, "2026-03-07T12:00:00Z"), 4)
	assertSeq(t, localStrings(t, got, "America/New_York"), []string{
		"2026-03-08 03:30 EDT", // 02:30 does not exist: right after the gap
		"2026-03-09 02:30 EDT",
		"2026-03-10 02:30 EDT",
		"2026-03-11 02:30 EDT",
	})
}

func TestOccurrence_DailyAcrossSpringForward_SchedulerStepping(t *testing.T) {
	// The scheduler computes the next run from the run it just fired plus
	// a margin; the day after the gap must still get exactly one run.
	sc := dstScan(t, ScheduleDaily, nil, 2, 30, "Europe/Berlin")
	cur := mustTime(t, "2026-03-28T12:00:00Z")
	var got []time.Time
	for range 3 {
		next := sc.OccurrenceAfter(cur)
		if next == nil {
			t.Fatal("no next run")
		}
		got = append(got, *next)
		cur = next.Add(15 * time.Minute)
	}
	assertSeq(t, localStrings(t, got, "Europe/Berlin"), []string{
		"2026-03-29 03:30 CEST",
		"2026-03-30 02:30 CEST",
		"2026-03-31 02:30 CEST",
	})
}

func TestOccurrence_WeeklyOnSpringForwardSunday_OneRunPerWeek(t *testing.T) {
	sunday := int(time.Sunday)
	sc := dstScan(t, ScheduleWeekly, &sunday, 2, 30, "America/New_York")
	got := sc.UpcomingOccurrences(mustTime(t, "2026-03-01T12:00:00Z"), 3)
	assertSeq(t, localStrings(t, got, "America/New_York"), []string{
		"2026-03-08 03:30 EDT",
		"2026-03-15 02:30 EDT",
		"2026-03-22 02:30 EDT",
	})
}

func TestOccurrence_DailyAcrossFallBack_OneRunPerDay(t *testing.T) {
	sc := dstScan(t, ScheduleDaily, nil, 1, 30, "America/New_York")
	// 2026-11-01: clocks go 02:00 EDT -> 01:00 EST; 01:30 happens twice.
	got := sc.UpcomingOccurrences(mustTime(t, "2026-10-31T12:00:00Z"), 3)
	assertSeq(t, localStrings(t, got, "America/New_York"), []string{
		"2026-11-01 01:30 EDT",
		"2026-11-02 01:30 EST",
		"2026-11-03 01:30 EST",
	})
}

func TestOccurrence_CronAcrossFallBack_FiresOnce(t *testing.T) {
	sc := newScheduledScan(t)
	if err := sc.SetSchedule(ScheduleCrontab, "30 1 * * *", nil, nil, "America/New_York"); err != nil {
		t.Fatal(err)
	}
	got := sc.UpcomingOccurrences(mustTime(t, "2026-10-31T12:00:00Z"), 3)
	assertSeq(t, localStrings(t, got, "America/New_York"), []string{
		"2026-11-01 01:30 EDT",
		"2026-11-02 01:30 EST",
		"2026-11-03 01:30 EST",
	})
}

func TestOccurrence_MonthlyOnSpringForwardDay(t *testing.T) {
	day := 8
	sc := dstScan(t, ScheduleMonthly, &day, 2, 30, "America/New_York")
	got := sc.UpcomingOccurrences(mustTime(t, "2026-02-20T12:00:00Z"), 2)
	assertSeq(t, localStrings(t, got, "America/New_York"), []string{
		"2026-03-08 03:30 EDT",
		"2026-04-08 02:30 EDT",
	})
}
