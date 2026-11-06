package scanwindow

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func loc(name string) *time.Location {
	l, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return l
}

func weekly(id string, kind Kind, tz string, days []int, start, end string) Source {
	s, _ := ParseMinute(start)
	e, _ := ParseMinute(end)
	return Source{ID: id, Name: id, Kind: kind, Origin: OriginPolicy, MinTier: TierActive, Overridable: true,
		Slots: []LocalSlot{{Days: days, Start: s, End: e, Loc: loc(tz)}}}
}

func once(id string, kind Kind, from, to string) Source {
	return Source{ID: id, Name: id, Kind: kind, Origin: OriginPolicy, MinTier: TierActive, Overridable: true,
		OneOffs: []OneOff{{StartsAt: utc(from), EndsAt: utc(to)}}}
}

func ptr(t time.Time) *time.Time { return &t }

func eqTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

var weekdays = []int{1, 2, 3, 4, 5}

func TestDecide(t *testing.T) {
	bizBerlin := weekly("biz", KindAllow, "Europe/Berlin", weekdays, "09:00", "17:00")
	cases := []struct {
		name      string
		sources   []Source
		tier      int
		now       string
		open      bool
		governed  bool
		nextOpen  *time.Time
		never     bool
		closesAt  *time.Time
		blocking  []string
		blockedTo []*time.Time
	}{
		{
			name: "no sources: open, not governed", now: "2026-10-07T08:00:00Z", tier: 1,
			open: true,
		},
		{
			name: "inside business hours (Berlin, CEST)", sources: []Source{bizBerlin}, tier: 1,
			now: "2026-10-07T08:00:00Z", open: true, governed: true, closesAt: ptr(utc("2026-10-07T15:00:00Z")),
		},
		{
			name: "Friday evening waits for Monday 09:00 Berlin", sources: []Source{bizBerlin}, tier: 1,
			now: "2026-10-09T16:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-12T07:00:00Z")),
			blocking: []string{"biz"}, blockedTo: []*time.Time{ptr(utc("2026-10-12T07:00:00Z"))},
		},
		{
			name: "same wall clock in Tokyo is a different instant", tier: 1,
			sources: []Source{weekly("tokyo", KindAllow, "Asia/Tokyo", weekdays, "09:00", "17:00")},
			now:     "2026-10-07T08:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-08T00:00:00Z")),
			blocking: []string{"tokyo"}, blockedTo: []*time.Time{ptr(utc("2026-10-08T00:00:00Z"))},
		},
		{
			name: "passive work is not governed by an active-tier policy", sources: []Source{bizBerlin}, tier: 0,
			now: "2026-10-09T16:00:00Z", open: true,
		},
		{
			name: "intrusive-only policy does not govern active work", tier: 1,
			sources: []Source{func() Source { s := bizBerlin; s.MinTier = TierIntrusive; return s }()},
			now:     "2026-10-09T16:00:00Z", open: true,
		},
		{
			name: "overnight blackout Saturday 22:00 to Sunday 06:00 holds on Sunday morning", tier: 1,
			sources: []Source{weekly("night", KindBlackout, "UTC", []int{6}, "22:00", "06:00")},
			now:     "2026-10-11T03:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-11T06:00:00Z")),
			blocking: []string{"night"}, blockedTo: []*time.Time{ptr(utc("2026-10-11T06:00:00Z"))},
		},
		{
			name: "overnight blackout does not hold Sunday evening", tier: 1,
			sources: []Source{weekly("night", KindBlackout, "UTC", []int{6}, "22:00", "06:00")},
			now:     "2026-10-11T23:00:00Z", open: true, governed: true, closesAt: ptr(utc("2026-10-17T22:00:00Z")),
		},
		{
			name: "two allow policies intersect", tier: 1,
			sources: []Source{
				weekly("a", KindAllow, "UTC", weekdays, "09:00", "17:00"),
				weekly("b", KindAllow, "UTC", []int{1, 3}, "13:00", "20:00"),
			},
			now: "2026-10-06T10:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-07T13:00:00Z")),
			blocking: []string{"b"}, blockedTo: []*time.Time{ptr(utc("2026-10-07T13:00:00Z"))},
		},
		{
			name: "intersection closes at the earlier end", tier: 1,
			sources: []Source{
				weekly("a", KindAllow, "UTC", weekdays, "09:00", "17:00"),
				weekly("b", KindAllow, "UTC", []int{1, 3}, "13:00", "20:00"),
			},
			now: "2026-10-07T14:00:00Z", open: true, governed: true, closesAt: ptr(utc("2026-10-07T17:00:00Z")),
		},
		{
			name: "blackout wins over allow", tier: 1,
			sources: []Source{
				weekly("biz", KindAllow, "UTC", weekdays, "09:00", "17:00"),
				once("freeze", KindBlackout, "2026-10-07T12:00:00Z", "2026-10-07T14:00:00Z"),
			},
			now: "2026-10-07T12:30:00Z", governed: true, nextOpen: ptr(utc("2026-10-07T14:00:00Z")),
			blocking: []string{"freeze"}, blockedTo: []*time.Time{ptr(utc("2026-10-07T14:00:00Z"))},
		},
		{
			name: "allow window that opens after the blackout ends", tier: 1,
			sources: []Source{
				weekly("biz", KindAllow, "UTC", weekdays, "09:00", "17:00"),
				once("freeze", KindBlackout, "2026-10-09T12:00:00Z", "2026-10-12T10:00:00Z"),
			},
			now: "2026-10-09T13:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-12T10:00:00Z")),
			blocking: []string{"freeze"}, blockedTo: []*time.Time{ptr(utc("2026-10-12T10:00:00Z"))},
		},
		{
			name: "empty intersection never opens", tier: 1,
			sources: []Source{
				weekly("mon", KindAllow, "UTC", []int{1}, "09:00", "17:00"),
				weekly("sat", KindAllow, "UTC", []int{6}, "09:00", "17:00"),
			},
			now: "2026-10-07T10:00:00Z", governed: true, never: true,
			blocking:  []string{"mon", "sat"},
			blockedTo: []*time.Time{ptr(utc("2026-10-12T09:00:00Z")), ptr(utc("2026-10-10T09:00:00Z"))},
		},
		{
			name: "one-off allow inside a longer blackout never opens", tier: 1,
			sources: []Source{
				once("pentest", KindAllow, "2026-10-08T10:00:00Z", "2026-10-08T12:00:00Z"),
				once("freeze", KindBlackout, "2026-10-07T00:00:00Z", "2026-10-10T00:00:00Z"),
			},
			now: "2026-10-07T10:00:00Z", governed: true, never: true,
			blocking:  []string{"pentest", "freeze"},
			blockedTo: []*time.Time{ptr(utc("2026-10-08T10:00:00Z")), ptr(utc("2026-10-10T00:00:00Z"))},
		},
		{
			name: "past one-off allow never opens", tier: 1,
			sources: []Source{once("done", KindAllow, "2026-10-01T10:00:00Z", "2026-10-01T12:00:00Z")},
			now:     "2026-10-07T10:00:00Z", governed: true, never: true,
			blocking: []string{"done"}, blockedTo: []*time.Time{nil},
		},
		{
			name: "equal start and end is 24 hours", tier: 1,
			sources: []Source{weekly("day", KindBlackout, "UTC", []int{3}, "08:00", "08:00")},
			now:     "2026-10-08T07:59:00Z", governed: true, nextOpen: ptr(utc("2026-10-08T08:00:00Z")),
			blocking: []string{"day"}, blockedTo: []*time.Time{ptr(utc("2026-10-08T08:00:00Z"))},
		},
		{
			name: "broken allow source never opens (fail closed)", tier: 1,
			sources: []Source{{ID: "x", Kind: KindAllow, MinTier: 1, Broken: true}},
			now:     "2026-10-07T10:00:00Z", governed: true, never: true,
			blocking: []string{"x"}, blockedTo: []*time.Time{nil},
		},
		{
			name: "broken blackout source is always active (fail closed)", tier: 1,
			sources: []Source{{ID: "x", Kind: KindBlackout, MinTier: 1, Broken: true}},
			now:     "2026-10-07T10:00:00Z", governed: true, never: true,
			blocking: []string{"x"}, blockedTo: []*time.Time{nil},
		},
		{
			name: "duplicate source ids count once", tier: 1,
			sources: []Source{bizBerlin, bizBerlin},
			now:     "2026-10-09T16:00:00Z", governed: true, nextOpen: ptr(utc("2026-10-12T07:00:00Z")),
			blocking: []string{"biz"}, blockedTo: []*time.Time{ptr(utc("2026-10-12T07:00:00Z"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.sources, tc.tier, utc(tc.now))
			if d.Open != tc.open || d.Governed != tc.governed || d.Never != tc.never {
				t.Fatalf("open/governed/never = %v/%v/%v, want %v/%v/%v (%+v)",
					d.Open, d.Governed, d.Never, tc.open, tc.governed, tc.never, d)
			}
			if !eqTime(d.NextOpen, tc.nextOpen) {
				t.Errorf("next open = %v, want %v", d.NextOpen, tc.nextOpen)
			}
			if !eqTime(d.ClosesAt, tc.closesAt) {
				t.Errorf("closes at = %v, want %v", d.ClosesAt, tc.closesAt)
			}
			if len(d.Blocking) != len(tc.blocking) {
				t.Fatalf("blocking = %+v, want %v", d.Blocking, tc.blocking)
			}
			for i, b := range d.Blocking {
				if b.SourceID != tc.blocking[i] {
					t.Errorf("blocking[%d] = %s, want %s", i, b.SourceID, tc.blocking[i])
				}
				if !eqTime(b.Until, tc.blockedTo[i]) {
					t.Errorf("blocking[%d] until = %v, want %v", i, b.Until, tc.blockedTo[i])
				}
			}
		})
	}
}

// Europe/Berlin: clocks go forward 2026-03-29 02:00 -> 03:00 and back
// 2026-10-25 03:00 -> 02:00.
func TestDecide_DaylightSaving(t *testing.T) {
	t.Run("a slot starting in the skipped hour starts one hour later", func(t *testing.T) {
		s := weekly("gap", KindAllow, "Europe/Berlin", []int{7}, "02:30", "04:00")
		// 02:30 does not exist; time.Date reads it as 03:30 CEST (01:30Z).
		d := Decide([]Source{s}, 1, utc("2026-03-29T01:15:00Z")) // 03:15 CEST
		if d.Open || !eqTime(d.NextOpen, ptr(utc("2026-03-29T01:30:00Z"))) {
			t.Fatalf("decision = %+v, want closed until 01:30Z", d)
		}
		d = Decide([]Source{s}, 1, utc("2026-03-29T01:45:00Z"))
		if !d.Open || !eqTime(d.ClosesAt, ptr(utc("2026-03-29T02:00:00Z"))) {
			t.Fatalf("decision = %+v, want open until 04:00 CEST (02:00Z)", d)
		}
	})
	t.Run("a slot over the skipped hour is an hour shorter", func(t *testing.T) {
		s := weekly("short", KindBlackout, "Europe/Berlin", []int{7}, "01:00", "04:00")
		d := Decide([]Source{s}, 1, utc("2026-03-29T00:30:00Z")) // 01:30 CET
		if d.Open || !eqTime(d.NextOpen, ptr(utc("2026-03-29T02:00:00Z"))) {
			t.Fatalf("decision = %+v, want blackout until 04:00 CEST (02:00Z), two real hours", d)
		}
	})
	t.Run("a slot over the repeated hour is an hour longer", func(t *testing.T) {
		s := weekly("long", KindBlackout, "Europe/Berlin", []int{7}, "01:00", "04:00")
		// 01:00 CEST = 23:00Z on the 24th; 04:00 CET = 03:00Z: four real hours.
		d := Decide([]Source{s}, 1, utc("2026-10-24T23:30:00Z"))
		if d.Open || !eqTime(d.NextOpen, ptr(utc("2026-10-25T03:00:00Z"))) {
			t.Fatalf("decision = %+v, want blackout until 03:00Z", d)
		}
	})
	t.Run("business hours follow the offset change", func(t *testing.T) {
		s := weekly("biz", KindAllow, "Europe/Berlin", weekdays, "09:00", "17:00")
		// Friday 2026-10-23 after hours (CEST); Monday 2026-10-26 09:00 is CET (08:00Z).
		d := Decide([]Source{s}, 1, utc("2026-10-23T16:00:00Z"))
		if !eqTime(d.NextOpen, ptr(utc("2026-10-26T08:00:00Z"))) {
			t.Fatalf("next open = %v, want 2026-10-26T08:00Z", d.NextOpen)
		}
	})
}

func TestDecide_CapsAndGrace(t *testing.T) {
	a := weekly("a", KindAllow, "UTC", weekdays, "00:00", "00:00")
	a.RateLimitRPS, a.MaxConcurrent, a.GraceMinutes = 50, 3, 30
	b := weekly("b", KindAllow, "UTC", weekdays, "00:00", "00:00")
	b.RateLimitRPS, b.GraceMinutes = 20, 5
	d := Decide([]Source{a, b}, 1, utc("2026-10-07T10:00:00Z"))
	if !d.Open || d.RateLimitRPS != 20 || len(d.Caps) != 1 || d.Caps[0].MaxConcurrent != 3 {
		t.Fatalf("decision = %+v, want open, rate 20, one cap of 3", d)
	}
	// Saturday: both block; the smaller grace applies.
	d = Decide([]Source{a, b}, 1, utc("2026-10-10T10:00:00Z"))
	if d.Open || d.GraceMinutes != 5 {
		t.Fatalf("decision = %+v, want closed with grace 5", d)
	}
}

func TestOpenings(t *testing.T) {
	s := weekly("biz", KindAllow, "UTC", weekdays, "09:00", "17:00")
	got := Openings([]Source{s}, 1, utc("2026-10-09T10:00:00Z"), 3)
	want := []Window{
		{Start: utc("2026-10-09T10:00:00Z"), End: utc("2026-10-09T17:00:00Z")},
		{Start: utc("2026-10-12T09:00:00Z"), End: utc("2026-10-12T17:00:00Z")},
		{Start: utc("2026-10-13T09:00:00Z"), End: utc("2026-10-13T17:00:00Z")},
	}
	if len(got) != len(want) {
		t.Fatalf("openings = %+v", got)
	}
	for i := range want {
		if !got[i].Start.Equal(want[i].Start) || !got[i].End.Equal(want[i].End) {
			t.Errorf("opening %d = %v, want %v", i, got[i], want[i])
		}
	}
	if o := Openings([]Source{once("x", KindAllow, "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")}, 1,
		utc("2026-10-09T10:00:00Z"), 3); len(o) != 0 {
		t.Errorf("past one-off openings = %v, want none", o)
	}
}

func TestPolicySource(t *testing.T) {
	now := utc("2026-10-07T10:00:00Z")
	p, err := NewPolicy(shared.NewID(), Spec{Name: "biz", Kind: KindAllow, MinTier: 1, Timezone: "Asia/Ho_Chi_Minh",
		Slots: []Slot{{Days: weekdays, Start: "08:00", End: "17:30"}}, Enabled: true}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	s := PolicySource(p)
	if s.Broken || !s.Overridable || s.Origin != OriginPolicy || len(s.Slots) != 1 || s.Slots[0].End != 17*60+30 {
		t.Fatalf("source = %+v", s)
	}
	// 10:00Z is 17:00 in Ho Chi Minh City: open until 17:30 local.
	d := Decide([]Source{s}, 1, now)
	if !d.Open || !eqTime(d.ClosesAt, ptr(utc("2026-10-07T10:30:00Z"))) {
		t.Fatalf("decision = %+v", d)
	}
	p.Timezone = "Nowhere/Land" // a stored zone that no longer loads
	if s := PolicySource(p); !s.Broken {
		t.Fatal("a zone that does not load must make the source fail closed")
	}
}

func TestOverrides(t *testing.T) {
	now := utc("2026-10-07T10:00:00Z")
	tenant := shared.NewID()
	pid := shared.NewID()
	pol := weekly(pid.String(), KindAllow, "UTC", []int{6}, "09:00", "17:00")
	other := weekly(shared.NewID().String(), KindBlackout, "UTC", weekdays, "00:00", "00:00")
	prog := weekly("program:1", KindAllow, "UTC", []int{6}, "09:00", "17:00")
	prog.Origin, prog.Overridable = OriginProgram, false

	one, err := NewOverride(tenant, &pid, "incident 4711 needs a rescan", time.Hour, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	got := WithoutSuspended([]Source{pol, other, prog}, []*Override{one}, now)
	if len(got) != 2 || got[0].ID != other.ID || got[1].ID != prog.ID {
		t.Fatalf("one-policy override left %+v", got)
	}
	all, _ := NewOverride(tenant, nil, "incident 4711 needs a rescan", time.Hour, nil, now)
	got = WithoutSuspended([]Source{pol, other, prog}, []*Override{all}, now)
	if len(got) != 1 || got[0].ID != prog.ID {
		t.Fatalf("an override must never suspend a program source; left %+v", got)
	}
	if got := WithoutSuspended([]Source{pol}, []*Override{all}, now.Add(2*time.Hour)); len(got) != 1 {
		t.Fatal("an expired override must not suspend")
	}
	revoked := *all
	revoked.RevokedAt = &now
	if got := WithoutSuspended([]Source{pol}, []*Override{&revoked}, now); len(got) != 1 {
		t.Fatal("a revoked override must not suspend")
	}
	for name, mk := range map[string]func() error{
		"short reason": func() error { _, err := NewOverride(tenant, nil, "too short", time.Hour, nil, now); return err },
		"long reason": func() error {
			_, err := NewOverride(tenant, nil, string(make([]rune, 501)), time.Hour, nil, now)
			return err
		},
		"too short": func() error {
			_, err := NewOverride(tenant, nil, "a valid reason here", 10*time.Minute, nil, now)
			return err
		},
		"too long": func() error {
			_, err := NewOverride(tenant, nil, "a valid reason here", 25*time.Hour, nil, now)
			return err
		},
	} {
		if mk() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
