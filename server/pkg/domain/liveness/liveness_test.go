package liveness

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func observe(e Evidence, k Kind, observer string, at time.Time) Evidence {
	return e.Observe(Observation{Kind: k, Observer: observer}, at)
}

func settle(t *testing.T, e Evidence, g Guards, now time.Time) Evidence {
	t.Helper()
	e, _ = e.Settle(g, DefaultThresholds(), now)
	return e
}

func TestNoEvidenceIsUnknown(t *testing.T) {
	if s, _ := Decide(Evidence{}, Guards{Known: true, DanglingChecked: true}, DefaultThresholds()); s != StateUnknown {
		t.Fatalf("state %s, want unknown", s)
	}
}

// One no-answer, or three within a day, is a brief outage: never unreachable.
func TestUnreachableNeedsAttemptsAndWindow(t *testing.T) {
	e := observe(Evidence{}, KindAnswered, "sensor:a", t0)
	e = observe(e, KindNoAnswer, "sensor:a", t0.Add(time.Hour))
	e = observe(e, KindNoAnswer, "sensor:a", t0.Add(2*time.Hour))
	e = observe(e, KindNoAnswer, "sensor:a", t0.Add(3*time.Hour))
	if s, _ := Decide(e, Guards{}, DefaultThresholds()); s != StateAlive {
		t.Fatalf("3 misses in 2 h: %s, want alive", s)
	}
	e = observe(e, KindNoAnswer, "sensor:a", t0.Add(80*time.Hour))
	e = settle(t, e, Guards{}, t0.Add(80*time.Hour))
	if e.State != StateUnreachable || e.Reason != ReasonNoAnswer {
		t.Fatalf("4 misses over 79 h: %s/%s, want unreachable/no_answer", e.State, e.Reason)
	}
	if !e.Since.Equal(t0.Add(time.Hour)) {
		t.Fatalf("since %v, want the first miss", e.Since)
	}
	// Any answer, from any observer, ends it at once.
	e = observe(e, KindAnswered, "zone:b", t0.Add(81*time.Hour))
	if e = settle(t, e, Guards{}, t0.Add(81*time.Hour)); e.State != StateAlive {
		t.Fatalf("after an answer: %s, want alive", e.State)
	}
}

func TestUnresolvableAndResolverFailed(t *testing.T) {
	e := observe(Evidence{}, KindResolverFailed, "sensor:a", t0)
	e = observe(e, KindResolverFailed, "sensor:a", t0.Add(24*time.Hour))
	e = settle(t, e, Guards{}, t0.Add(24*time.Hour))
	if e.State != StateUnresolvable || e.Reason != ReasonResolverFailed {
		t.Fatalf("%s/%s, want unresolvable/resolver_failed", e.State, e.Reason)
	}
	// SERVFAIL never counts towards gone, however long.
	for i := 2; i < 30; i++ {
		e = observe(e, KindResolverFailed, "sensor:b", t0.Add(time.Duration(i)*24*time.Hour))
	}
	g := Guards{Known: true, DanglingChecked: true}
	if s, _ := Decide(e, g, DefaultThresholds()); s == StateGone {
		t.Fatal("a failed lookup made the asset gone")
	}
}

func nxSeries(observers []string, days ...int) Evidence {
	e := observe(Evidence{}, KindAnswered, "sensor:a", t0.Add(-24*time.Hour))
	for i, d := range days {
		e = observe(e, KindNXDomain, observers[i%len(observers)], t0.Add(time.Duration(d)*24*time.Hour))
	}
	return e
}

func TestGoneNeedsTwoObserversOrLongWindow(t *testing.T) {
	ok := Guards{Known: true, DanglingChecked: true}
	th := DefaultThresholds()
	cases := []struct {
		name      string
		e         Evidence
		wantState State
	}{
		{"one observer, 4 days", nxSeries([]string{"sensor:a"}, 0, 1, 4), StateUnresolvable},
		{"one observer, 11 days", nxSeries([]string{"sensor:a"}, 0, 1, 4, 11), StateGone},
		{"two observers, 4 days", nxSeries([]string{"sensor:a", "zone:b"}, 0, 1, 4), StateGone},
		{"two observers, 1 day", nxSeries([]string{"sensor:a", "zone:b"}, 0, 0, 1), StateUnresolvable},
		{"unknown observers count as one", nxSeries([]string{"", ""}, 0, 1, 4), StateUnresolvable},
		{"two observations only", nxSeries([]string{"sensor:a", "zone:b"}, 0, 9), StateUnresolvable},
	}
	for _, c := range cases {
		if s, _ := Decide(c.e, ok, th); s != c.wantState {
			t.Errorf("%s: %s, want %s", c.name, s, c.wantState)
		}
	}
}

// A dangling name is an organization asset with a takeover risk: never gone.
func TestDanglingNeverGone(t *testing.T) {
	e := nxSeries([]string{"sensor:a", "zone:b"}, 0, 1, 4, 11, 18)
	s, r := Decide(e, Guards{Known: true, Dangling: true, DanglingChecked: true}, DefaultThresholds())
	if s != StateUnresolvable || r != ReasonDangling {
		t.Fatalf("%s/%s, want unresolvable/dangling", s, r)
	}
	// The settle path (no guards) keeps the dangling reason.
	e.State, e.Reason = s, r
	if s, r := Decide(e, Guards{}, DefaultThresholds()); s != StateUnresolvable || r != ReasonDangling {
		t.Fatalf("settle path: %s/%s, want unresolvable/dangling", s, r)
	}
}

func TestGoneGuards(t *testing.T) {
	e := nxSeries([]string{"sensor:a", "zone:b"}, 0, 1, 4)
	th := DefaultThresholds()
	if s, _ := Decide(e, Guards{Known: true}, th); s == StateGone {
		t.Fatal("gone without a dangling check since the streak began")
	}
	if s, _ := Decide(e, Guards{Known: true, DanglingChecked: true, Pinned: true}, th); s == StateGone {
		t.Fatal("gone although a person pinned the asset")
	}
	if s, _ := Decide(e, Guards{}, th); s == StateGone {
		t.Fatal("the settle path (no guards) entered gone")
	}
	if s, r := Decide(Evidence{}, Guards{Known: true, HostGone: true}, th); s != StateGone || r != ReasonHostGone {
		t.Fatalf("host gone: %s/%s", s, r)
	}
}

func TestGoneKeptUntilSeenAgain(t *testing.T) {
	e := nxSeries([]string{"sensor:a", "zone:b"}, 0, 1, 4)
	e = settle(t, e, Guards{Known: true, DanglingChecked: true}, t0.Add(4*24*time.Hour))
	if e.State != StateGone {
		t.Fatalf("%s, want gone", e.State)
	}
	// Another NXDOMAIN on the settle path keeps it.
	e = observe(e, KindNXDomain, "sensor:a", t0.Add(11*24*time.Hour))
	if e = settle(t, e, Guards{}, t0.Add(11*24*time.Hour)); e.State != StateGone {
		t.Fatalf("%s, want gone kept", e.State)
	}
	// The name resolves again: no longer gone.
	e = observe(e, KindResolved, "sensor:a", t0.Add(12*24*time.Hour))
	if e = settle(t, e, Guards{}, t0.Add(12*24*time.Hour)); e.State != StateAlive {
		t.Fatalf("%s, want alive", e.State)
	}
}

func TestResolverFailedDoesNotBreakNXStreak(t *testing.T) {
	e := nxSeries([]string{"sensor:a", "zone:b"}, 0, 1)
	e = observe(e, KindResolverFailed, "sensor:a", t0.Add(2*24*time.Hour))
	e = observe(e, KindNXDomain, "zone:b", t0.Add(4*24*time.Hour))
	if e.NXCount != 3 || !e.NXConfirmed(DefaultThresholds()) {
		t.Fatalf("nx count %d, confirmed %v", e.NXCount, e.NXConfirmed(DefaultThresholds()))
	}
}

func TestFloors(t *testing.T) {
	th := Thresholds{UnreachableAttempts: 1, GoneAttempts: 1, GoneWindow: time.Minute, GoneSingleObserverWindow: time.Minute}.Floored()
	if th.UnreachableAttempts != MinUnreachableAttempts || th.UnreachableWindow != MinUnreachableWindow ||
		th.GoneAttempts != MinGoneAttempts || th.GoneWindow != MinGoneWindow || th.GoneSingleObserverWindow != MinGoneSingleObserverWindow {
		t.Fatalf("floors not applied: %+v", th)
	}
	// A single NXDOMAIN under thresholds of zero is never gone.
	e := observe(Evidence{}, KindNXDomain, "sensor:a", t0)
	if s, _ := Decide(e, Guards{Known: true, DanglingChecked: true}, Thresholds{}); s == StateGone {
		t.Fatal("one NXDOMAIN made the asset gone")
	}
}

func TestObserversBounded(t *testing.T) {
	e := Evidence{}
	for i := 0; i < 20; i++ {
		e = observe(e, KindNoAnswer, "sensor:"+string(rune('a'+i)), t0)
	}
	if len(e.ReachObservers) != MaxObservers {
		t.Fatalf("observers %d, want %d", len(e.ReachObservers), MaxObservers)
	}
}
