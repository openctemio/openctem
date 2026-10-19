package controller

import (
	"testing"
	"time"
)

// A KEV source that answers 304 for days must not stop the findings from
// being reconciled with the catalog: findings created since a catalog
// change still need the KEV flag and escalation (RFC-117 hourly refresh).
func TestSweepDue(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		changed bool
		last    time.Time
		want    bool
	}{
		{"changed catalog", true, now.Add(-time.Minute), true},
		{"first run, unchanged", false, time.Time{}, true},
		{"unchanged within a day", false, now.Add(-time.Hour), false},
		{"unchanged for a day", false, now.Add(-findingSweepEvery), true},
	}
	for _, c := range cases {
		if got := sweepDue(c.changed, c.last, now); got != c.want {
			t.Errorf("%s: sweepDue = %v, want %v", c.name, got, c.want)
		}
	}
}
