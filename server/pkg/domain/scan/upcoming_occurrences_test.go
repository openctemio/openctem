package scan

// The schedule preview: the next occurrences are exactly what the scheduler
// would fire (OccurrenceAfter, repeated), in the scan's timezone.

import (
	"testing"
	"time"
)

func mustTime(t *testing.T, v string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestUpcomingOccurrences_RRuleInTimezone(t *testing.T) {
	sc := newScheduledScan(t)
	if err := sc.SetRRuleSchedule("FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=2;BYMINUTE=30", "Asia/Ho_Chi_Minh"); err != nil {
		t.Fatal(err)
	}
	// Wednesday 2026-10-07 12:00 UTC (19:00 in Ho Chi Minh, UTC+7).
	got := sc.UpcomingOccurrences(mustTime(t, "2026-10-07T12:00:00Z"), 4)
	want := []string{
		"2026-10-08T02:30:00+07:00", // Thursday
		"2026-10-12T02:30:00+07:00", // Monday
		"2026-10-15T02:30:00+07:00",
		"2026-10-19T02:30:00+07:00",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d occurrences, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if !got[i].Equal(mustTime(t, w)) {
			t.Errorf("occurrence %d: got %s, want %s", i, got[i], w)
		}
		if got[i].Location() != time.UTC {
			t.Errorf("occurrence %d not in UTC: %s", i, got[i].Location())
		}
	}
}

func TestUpcomingOccurrences_MatchesOccurrenceAfter(t *testing.T) {
	sc := newScheduledScan(t)
	day := 15
	at := time.Date(0, 1, 1, 3, 0, 0, 0, time.UTC)
	if err := sc.SetSchedule(ScheduleMonthly, "", &day, &at, "Europe/Paris"); err != nil {
		t.Fatal(err)
	}
	from := mustTime(t, "2026-01-20T00:00:00Z")
	got := sc.UpcomingOccurrences(from, 3)
	cur := from
	for i := range 3 {
		next := sc.OccurrenceAfter(cur)
		if next == nil || !got[i].Equal(*next) {
			t.Fatalf("occurrence %d: preview %v, scheduler %v", i, got[i], next)
		}
		cur = *next
	}
}

func TestUpcomingOccurrences_Bounds(t *testing.T) {
	sc := newScheduledScan(t)
	at := time.Date(0, 1, 1, 1, 0, 0, 0, time.UTC)
	if err := sc.SetSchedule(ScheduleDaily, "", nil, &at, "UTC"); err != nil {
		t.Fatal(err)
	}
	from := mustTime(t, "2026-10-04T00:00:00Z")
	if n := len(sc.UpcomingOccurrences(from, 1000)); n != MaxUpcomingOccurrences {
		t.Errorf("asked for 1000, got %d (cap %d)", n, MaxUpcomingOccurrences)
	}
	if n := len(sc.UpcomingOccurrences(from, 0)); n != 0 {
		t.Errorf("asked for 0, got %d", n)
	}
	if n := len(sc.UpcomingOccurrences(from, -3)); n != 0 {
		t.Errorf("asked for -3, got %d", n)
	}

	manual := newScheduledScan(t)
	if err := manual.SetSchedule(ScheduleManual, "", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	if n := len(manual.UpcomingOccurrences(from, 5)); n != 0 {
		t.Errorf("a manual scan previewed %d occurrences", n)
	}
}

func TestUpcomingOccurrences_RuleThatEnds(t *testing.T) {
	sc := newScheduledScan(t)
	if err := sc.SetRRuleSchedule("FREQ=DAILY;BYHOUR=2;UNTIL=20991231T000000Z", "UTC"); err != nil {
		t.Fatal(err)
	}
	// UNTIL is 31 Dec 00:00: only 29 and 30 Dec at 02:00 remain.
	got := sc.UpcomingOccurrences(mustTime(t, "2099-12-28T12:00:00Z"), 10)
	if len(got) != 2 {
		t.Fatalf("got %d occurrences before UNTIL, want 2: %v", len(got), got)
	}
}
