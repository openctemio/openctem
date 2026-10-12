package scan

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSetRRuleSchedule_Validation(t *testing.T) {
	for _, tc := range []struct {
		rule string
		ok   bool
	}{
		{"FREQ=DAILY;BYHOUR=2;BYMINUTE=0", true},
		{"FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=2;BYMINUTE=30", true},
		{"FREQ=MONTHLY;BYMONTHDAY=-1;BYHOUR=3", true}, // last day of the month
		{"FREQ=MINUTELY;INTERVAL=15", true},
		{"freq=hourly", true}, // case does not matter
		{"FREQ=MINUTELY;INTERVAL=5", false},
		{"FREQ=MINUTELY", false},
		{"FREQ=HOURLY;BYMINUTE=0,10", false}, // two runs 10 minutes apart
		{"FREQ=SECONDLY;INTERVAL=3600", false},
		{"FREQ=DAILY;BYSECOND=30", false},
		{"FREQ=DAILY;COUNT=3", false},
		{"DTSTART:20260101T000000Z\nRRULE:FREQ=DAILY", false},
		{"RRULE:FREQ=DAILY", false},
		{"FREQ=DAILY;UNTIL=20200101T000000Z", false}, // no future occurrence
		{"FREQ=NEVER", false},
		{"", false},
	} {
		sc := newScheduledScan(t)
		err := sc.SetRRuleSchedule(tc.rule, "UTC")
		if tc.ok && err != nil {
			t.Errorf("%q refused: %v", tc.rule, err)
		}
		if !tc.ok && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (err %v), want a validation error", tc.rule, err)
		}
	}
	long := "FREQ=DAILY;BYHOUR=2"
	for len(long) <= MaxRRuleLength {
		long += ";BYMINUTE=0"
	}
	if err := newScheduledScan(t).SetRRuleSchedule(long, "UTC"); err == nil {
		t.Error("an oversized rule was accepted")
	}
	if err := newScheduledScan(t).SetRRuleSchedule("FREQ=DAILY", "Mars/Olympus"); err == nil {
		t.Error("an unknown timezone was accepted")
	}
}

func TestSetRRuleSchedule_StoresAndComputesNextRun(t *testing.T) {
	sc := newScheduledScan(t)
	sc.ScheduleCron = "0 * * * *"
	if err := sc.SetRRuleSchedule(" freq=daily;byhour=2 ", "Europe/Paris"); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleType != ScheduleRRule || sc.ScheduleRRule != "FREQ=DAILY;BYHOUR=2" || sc.ScheduleCron != "" {
		t.Fatalf("stored %q %q cron=%q", sc.ScheduleType, sc.ScheduleRRule, sc.ScheduleCron)
	}
	if sc.NextRunAt == nil {
		t.Fatal("no next run")
	}
	paris, _ := time.LoadLocation("Europe/Paris")
	if got := sc.NextRunAt.In(paris); got.Hour() != 2 || got.Minute() != 0 || got.Second() != 0 {
		t.Fatalf("next run %v, want 02:00:00 Paris time", got)
	}
	// Switching back to a legacy type clears the rule.
	at := time.Date(0, 1, 1, 3, 0, 0, 0, time.UTC)
	if err := sc.SetSchedule(ScheduleDaily, "", nil, &at, "UTC"); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleRRule != "" {
		t.Fatalf("rule kept after switching to daily: %q", sc.ScheduleRRule)
	}
}

// Occurrences are computed in the scan timezone, across DST and month ends.
func TestRRuleOccurrences_TimezoneDSTAndMonthEnd(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	sc := newScheduledScan(t)
	if err := sc.SetRRuleSchedule("FREQ=DAILY;BYHOUR=9;BYMINUTE=30", "America/New_York"); err != nil {
		t.Fatal(err)
	}
	// Across the 2026-03-08 spring-forward: still 09:30 local each day.
	for _, day := range []int{7, 8, 9} {
		base := time.Date(2026, 3, day, 0, 0, 0, 0, ny)
		got := sc.OccurrenceAfter(base)
		if got == nil {
			t.Fatalf("no occurrence after %v", base)
		}
		if l := got.In(ny); l.Day() != day || l.Hour() != 9 || l.Minute() != 30 {
			t.Fatalf("after %v: %v, want 09:30 local on the same day", base, l)
		}
	}

	if err := sc.SetRRuleSchedule("FREQ=MONTHLY;BYMONTHDAY=-1;BYHOUR=23", "UTC"); err != nil {
		t.Fatal(err)
	}
	got := sc.OccurrenceAfter(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if got == nil || !got.Equal(time.Date(2026, 2, 28, 23, 0, 0, 0, time.UTC)) {
		t.Fatalf("last day of February 2026 = %v, want 2026-02-28 23:00", got)
	}
}

// A rule that crowds runs only in one month is still caught.
func TestSetRRuleSchedule_MinimumIntervalOverAYear(t *testing.T) {
	m := (time.Now().Month()+5)%12 + 1 // a month a few months away
	rule := "FREQ=YEARLY;BYMONTH=" + strconv.Itoa(int(m)) + ";BYMONTHDAY=10;BYHOUR=2;BYMINUTE=0,5"
	if err := newScheduledScan(t).SetRRuleSchedule(rule, "UTC"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("%q accepted (err %v): two runs 5 minutes apart", rule, err)
	}
}
