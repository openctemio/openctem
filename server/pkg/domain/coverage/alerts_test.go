package coverage

import (
	"testing"
	"time"
)

// apply stores the planned states the way the repository upserts them.
func apply(states []AlertState, store []AlertState) []AlertState {
	byKey := map[AlertKey]int{}
	for i, s := range states {
		byKey[s.AlertKey] = i
	}
	for _, s := range store {
		if i, ok := byKey[s.AlertKey]; ok {
			states[i] = s
			continue
		}
		byKey[s.AlertKey] = len(states)
		states = append(states, s)
	}
	return states
}

func TestPlanAlerts_OnChangeOnly(t *testing.T) {
	t0 := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	gap := func(n int) []AlertCondition {
		return []AlertCondition{{Capability: "resolve.dns", Kind: AlertGap, Count: n}}
	}
	var states []AlertState
	sent := 0
	pass := func(at time.Time, conds []AlertCondition) {
		t.Helper()
		send, store := PlanAlerts(states, conds, at)
		sent += len(send)
		states = apply(states, store)
	}

	// The same condition over 3 days, every 15 minutes: one alert.
	for at := t0; at.Before(t0.Add(72 * time.Hour)); at = at.Add(15 * time.Minute) {
		pass(at, gap(10))
	}
	if sent != 1 {
		t.Fatalf("same condition for 3 days sent %d alerts, want 1", sent)
	}
	// Small changes: nothing. Doubling: one more; halving: silent.
	pass(t0.Add(73*time.Hour), gap(15))
	pass(t0.Add(74*time.Hour), gap(19))
	if sent != 1 {
		t.Fatalf("small changes sent %d, want 1", sent)
	}
	pass(t0.Add(75*time.Hour), gap(20))
	if sent != 2 {
		t.Fatalf("doubled count: sent %d, want 2", sent)
	}
	pass(t0.Add(76*time.Hour), gap(10))
	pass(t0.Add(77*time.Hour), gap(1))
	if sent != 2 {
		t.Fatalf("an improvement was sent: sent %d, want 2", sent)
	}
	// Doubled again within a day of the last send: held until a day passed.
	pass(t0.Add(78*time.Hour), gap(40))
	if sent != 2 {
		t.Fatalf("worse within a day of the last send: sent %d, want 2", sent)
	}
	pass(t0.Add(75*time.Hour+AlertRenotifyAfter), gap(40))
	if sent != 3 {
		t.Fatalf("worse after a day: sent %d, want 3", sent)
	}
	// Cleared, back within the quiet time: silent. Cleared, back after it: sent.
	at := t0.Add(100 * time.Hour)
	pass(at, nil)
	pass(at.Add(AlertQuietAfterClear-time.Hour), gap(10))
	if sent != 3 {
		t.Fatalf("back within the quiet time: sent %d, want 3", sent)
	}
	at = at.Add(AlertQuietAfterClear)
	pass(at, nil)
	pass(at.Add(AlertQuietAfterClear), gap(10))
	if sent != 4 {
		t.Fatalf("back after the quiet time: sent %d, want 4", sent)
	}
}

// The "keeps failing" counts live sent on 2026-10-26..28: nine alerts in 38
// hours, each a small count doubling or halving. Now: the first only.
func TestPlanAlerts_SmallCountsThatFlapSendOnce(t *testing.T) {
	t0 := time.Date(2026, 10, 26, 14, 54, 0, 0, time.UTC)
	var states []AlertState
	sent := 0
	for i, n := range []int{4, 8, 4, 2, 6, 2, 6, 1, 5, 2, 6, 3, 7} {
		conds := []AlertCondition{{Capability: "vuln.templates", Kind: AlertFailing, Count: n}}
		send, store := PlanAlerts(states, conds, t0.Add(time.Duration(i)*3*time.Hour))
		sent += len(send)
		states = apply(states, store)
	}
	if sent != 1 {
		t.Fatalf("flapping small count sent %d alerts, want 1", sent)
	}
	// One open alert per key, holding the latest count.
	if len(states) != 1 || !states[0].Active || states[0].SentCount != 4 || states[0].LastCount != 7 {
		t.Fatalf("states = %+v", states)
	}
}

// A large gap that doubles is news; a gap that only shrinks is not.
func TestPlanAlerts_WorseningOnly(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 10, 21, 0, 0, time.UTC)
	var states []AlertState
	var sends []int
	for i, n := range []int{133, 282, 126, 158} {
		conds := []AlertCondition{{Capability: "resolve.dns", Kind: AlertGap, Count: n}}
		send, store := PlanAlerts(states, conds, t0.Add(time.Duration(i)*26*time.Hour))
		for _, c := range send {
			sends = append(sends, c.Count)
		}
		states = apply(states, store)
	}
	if len(sends) != 2 || sends[0] != 133 || sends[1] != 282 {
		t.Fatalf("sent %v, want [133 282]", sends)
	}
	// Gone: the open alert is resolved.
	_, store := PlanAlerts(states, nil, t0.Add(200*time.Hour))
	states = apply(states, store)
	if states[0].Active || states[0].ClearedAt == nil {
		t.Fatalf("gap closed but alert still open: %+v", states[0])
	}
}

func TestPlanAlerts_ReadinessReasonChangeIsANewAlert(t *testing.T) {
	t0 := time.Now()
	c1 := []AlertCondition{{Capability: "probe.http", Kind: AlertReadiness, Reason: ReadyToolMissing, Count: 5}}
	send, store := PlanAlerts(nil, c1, t0)
	if len(send) != 1 {
		t.Fatalf("first readiness alert: %v", send)
	}
	states := apply(nil, store)
	c2 := []AlertCondition{{Capability: "probe.http", Kind: AlertReadiness, Reason: ReadySensorOffline, Count: 5}}
	send, _ = PlanAlerts(states, c2, t0.Add(time.Hour))
	if len(send) != 1 || send[0].Reason != ReadySensorOffline {
		t.Fatalf("reason change: %v", send)
	}
}

func TestPlanAlerts_DigestAtMostDaily(t *testing.T) {
	t0 := time.Now()
	two := func(a, b string) []AlertCondition {
		return []AlertCondition{{Capability: a, Kind: AlertReadiness, Reason: ReadyNoScope, Count: 3},
			{Capability: b, Kind: AlertReadiness, Reason: ReadyNoScope, Count: 3}}
	}
	send, store := PlanAlerts(nil, two("resolve.dns", "lookup.rdap"), t0)
	if len(send) != 2 {
		t.Fatalf("first digest = %v", send)
	}
	states := apply(nil, store)
	// Two more changes the same day: held, not lost.
	conds := append(two("resolve.dns", "lookup.rdap"), two("scan.ports", "probe.http")...)
	send, store = PlanAlerts(states, conds, t0.Add(time.Hour))
	if len(send) != 0 {
		t.Fatalf("second digest within a day sent %v", send)
	}
	states = apply(states, store)
	send, _ = PlanAlerts(states, conds, t0.Add(DigestEvery+time.Minute))
	if len(send) != 2 || send[0].Capability != "scan.ports" {
		t.Fatalf("held changes after a day = %v", send)
	}
}

func TestConditions(t *testing.T) {
	got := Conditions([]CapabilityHealth{
		{Capability: "dns.dangling", Failing: 1},
		{Capability: "scan.ports", Failing: 2, Gaps: 4},
		{Capability: "probe.http", Paused: 7, PausedReason: ReadyToolMissing},
		{Capability: "lookup.asn", Paused: 3, PausedReason: "unreachable"},
	})
	want := map[AlertKey]int{
		{"scan.ports", AlertGap, ""}:                     4,
		{"scan.ports", AlertFailing, ""}:                 2,
		{"probe.http", AlertReadiness, ReadyToolMissing}: 7,
	}
	if len(got) != len(want) {
		t.Fatalf("conditions = %+v", got)
	}
	for _, c := range got {
		if want[c.Key()] != c.Count {
			t.Errorf("unexpected %+v", c)
		}
	}
}

func TestActionFor_EveryReadinessReason(t *testing.T) {
	for _, r := range ReadinessReasons() {
		a := ActionFor(AlertCondition{Kind: AlertReadiness, Reason: r})
		if a.Text == "" || a.URL == "" || a.URL[0] != '/' {
			t.Errorf("%s: action %+v", r, a)
		}
		if ReadinessText(r) == r {
			t.Errorf("%s has no text", r)
		}
	}
}
