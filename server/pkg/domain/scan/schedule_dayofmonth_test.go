package scan

import (
	"testing"
	"time"
)

func TestDateOnClampedDay(t *testing.T) {
	utc := time.UTC
	cases := []struct {
		name      string
		year      int
		month     time.Month
		day       int
		wantYear  int
		wantMonth time.Month
		wantDay   int
	}{
		{"feb 31 non-leap clamps to 28", 2026, time.February, 31, 2026, time.February, 28},
		{"feb 31 leap clamps to 29", 2024, time.February, 31, 2024, time.February, 29},
		{"apr 31 clamps to 30", 2026, time.April, 31, 2026, time.April, 30},
		{"jan 31 stays 31", 2026, time.January, 31, 2026, time.January, 31},
		{"day below 1 becomes 1", 2026, time.March, 0, 2026, time.March, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := dateOnClampedDay(c.year, c.month, c.day, 9, 30, utc)
			if got.Year() != c.wantYear || got.Month() != c.wantMonth || got.Day() != c.wantDay {
				t.Fatalf("got %s, want %d-%02d-%02d", got.Format("2006-01-02"), c.wantYear, c.wantMonth, c.wantDay)
			}
			if got.Hour() != 9 || got.Minute() != 30 {
				t.Fatalf("time-of-day not preserved: %s", got.Format("15:04"))
			}
		})
	}
}

func TestNextAtDayOfMonth_ShortMonthDoesNotDrift(t *testing.T) {
	utc := time.UTC
	day := 31
	tod := time.Date(0, 1, 1, 9, 0, 0, 0, utc) // 09:00

	// Mid-February, asking for the 31st: must land on Feb 28 (this year),
	// NOT roll forward into March (the old time.Date overflow bug).
	now := time.Date(2026, time.February, 15, 8, 0, 0, 0, utc)
	got := nextAtDayOfMonth(now, &day, &tod)
	if got.Month() != time.February || got.Day() != 28 {
		t.Fatalf("got %s, want 2026-02-28", got.Format("2006-01-02"))
	}

	// On Jan 31 after the scheduled time: roll to next month and clamp the
	// 31st to Feb's last day (28), not normalize to early March.
	now2 := time.Date(2026, time.January, 31, 12, 0, 0, 0, utc)
	got2 := nextAtDayOfMonth(now2, &day, &tod)
	if got2.Month() != time.February || got2.Day() != 28 {
		t.Fatalf("got %s, want 2026-02-28", got2.Format("2006-01-02"))
	}
	if !got2.After(now2) {
		t.Fatalf("next run %s must be after now %s", got2, now2)
	}
}
