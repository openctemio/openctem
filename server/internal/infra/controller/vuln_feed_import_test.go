package controller

import (
	"testing"
	"time"
)

func TestFeedNeedsWarning(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		stale bool
		last  time.Time
		want  bool
	}{
		{"fresh success, fresh bundle", false, now.Add(-time.Hour), false},
		{"bundle older than the window", true, now.Add(-time.Hour), true},
		{"no success for longer than the warn window (failing import)", false, now.Add(-7 * time.Hour), true},
		{"no success for three days", false, now.Add(-72 * time.Hour), true},
		{"just inside the window", false, now.Add(-FeedFailingWarnAfter), false},
		{"never succeeded, not stale yet", false, time.Time{}, false},
	}
	for _, c := range cases {
		if got := feedNeedsWarning(c.stale, c.last, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
