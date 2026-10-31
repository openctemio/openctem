package certificate

import (
	"strings"
	"testing"
	"time"
)

func TestStatusAt_Boundaries(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	for _, c := range []struct {
		name string
		in   *time.Time
		want Status
	}{
		{"missing date is unknown, never ok", nil, StatusUnknown},
		{"long expired", at(-400 * 24 * time.Hour), StatusExpired},
		{"expired a second ago", at(-time.Second), StatusExpired},
		{"expires exactly now is expired", at(0), StatusExpired},
		{"one second left is soon", at(time.Second), StatusExpiringSoon},
		{"29 days left is soon", at(29 * 24 * time.Hour), StatusExpiringSoon},
		{"just under 30 days is soon", at(ExpiringSoonWindow - time.Second), StatusExpiringSoon},
		{"exactly 30 days is ok", at(ExpiringSoonWindow), StatusOK},
		{"a year left is ok", at(365 * 24 * time.Hour), StatusOK},
	} {
		if got := StatusAt(c.in, now); got != c.want {
			t.Errorf("%s: StatusAt = %q, want %q", c.name, got, c.want)
		}
	}
}

// The SQL status expression must mirror StatusAt: the same window, the same
// boundary, unknown for an unreadable date.
func TestStatusSQL_MirrorsStatusAt(t *testing.T) {
	for _, want := range []string{"<= now()", "< now() + interval '30 days'", "'unknown'", "'expired'", "'expiring_soon'", "'ok'"} {
		if !strings.Contains(StatusSQL, want) {
			t.Errorf("StatusSQL lacks %q: %s", want, StatusSQL)
		}
	}
	if ExpiringSoonWindow != 30*24*time.Hour {
		t.Errorf("window changed to %v: update StatusSQL", ExpiringSoonWindow)
	}
}
