package easmchange

import (
	"errors"
	"testing"
	"time"
)

func TestDigestSlot(t *testing.T) {
	// 2026-10-12 is a Monday.
	cases := []struct {
		now      string
		weekday  time.Weekday
		wantSlot string
	}{
		{"2026-10-12T08:00:00Z", time.Monday, "2026-10-12T08:00:00Z"},
		{"2026-10-12T07:59:59Z", time.Monday, "2026-10-05T08:00:00Z"},
		{"2026-10-14T12:00:00Z", time.Monday, "2026-10-12T08:00:00Z"},
		{"2026-10-18T23:00:00Z", time.Sunday, "2026-10-18T08:00:00Z"},
		{"2026-10-17T09:00:00Z", time.Sunday, "2026-10-11T08:00:00Z"},
	}
	for _, c := range cases {
		now, _ := time.Parse(time.RFC3339, c.now)
		slot, from := DigestSlot(now, c.weekday)
		if got := slot.Format(time.RFC3339); got != c.wantSlot {
			t.Errorf("DigestSlot(%s, %s) = %s, want %s", c.now, c.weekday, got, c.wantSlot)
		}
		if slot.Sub(from) != 7*24*time.Hour {
			t.Errorf("window = %s, want 7 days", slot.Sub(from))
		}
	}
}

func TestWeekday(t *testing.T) {
	if Weekday(0) != time.Monday || Weekday(8) != time.Monday || Weekday(-1) != time.Monday {
		t.Fatal("out of range settings must fall back to Monday")
	}
	if Weekday(7) != time.Sunday || Weekday(3) != time.Wednesday {
		t.Fatal("ISO weekday mapping broken")
	}
}

func TestQueryNormalize(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	q := Query{}
	if err := q.Normalize(now); err != nil {
		t.Fatal(err)
	}
	if !q.To.Equal(now) || q.To.Sub(q.From) != DefaultWindow || q.Limit != 50 {
		t.Fatalf("defaults wrong: %+v", q)
	}
	bad := []Query{
		{From: now, To: now},
		{From: now.Add(-32 * 24 * time.Hour), To: now},
	}
	for _, b := range bad {
		if err := b.Normalize(now); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("Normalize(%v..%v) = %v, want ErrInvalidQuery", b.From, b.To, err)
		}
	}
	q = Query{Limit: 10000}
	_ = q.Normalize(now)
	if q.Limit != 50 {
		t.Fatalf("oversized limit kept: %d", q.Limit)
	}
}

func TestParseKinds(t *testing.T) {
	if _, err := ParseKinds([]string{"host_added", "dns_dangling"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKinds([]string{"host_added", "nope"}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("unknown kind accepted: %v", err)
	}
	if len(AllKinds()) != 13 {
		t.Fatal("a kind was added without updating AllKinds")
	}
}
