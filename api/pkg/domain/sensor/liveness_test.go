package sensor

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func at(d time.Duration) *time.Time {
	t := testNow.Add(d)
	return &t
}

// The ladder's boundaries for the three intervals the platform advises
// (busy 5s, idle 30s, loaded 45s), the SDK default (60s) and the cap.
// Times are relative to the last heartbeat, which set due = seen + interval.
func TestLadder_Boundaries(t *testing.T) {
	cases := []struct {
		interval time.Duration
		// online until lateAt, late until staleAt, stale until offlineAt
		lateAt, staleAt, offlineAt time.Duration
	}{
		// grace 10s; late +2×5+10; offline floor 90s.
		{5 * time.Second, 15 * time.Second, 25 * time.Second, 95 * time.Second},
		// grace 10s; 30+60+10; 30+90.
		{30 * time.Second, 40 * time.Second, 100 * time.Second, 120 * time.Second},
		// grace 10s (0.2×45 = 9s); 45+90+10; 45+135.
		{45 * time.Second, 55 * time.Second, 145 * time.Second, 180 * time.Second},
		// grace 12s; 60+120+12; 60+180.
		{60 * time.Second, 72 * time.Second, 192 * time.Second, 240 * time.Second},
		// grace 60s; 300+600+60; 300+900.
		{5 * time.Minute, 6 * time.Minute, 16 * time.Minute, 20 * time.Minute},
	}
	for _, c := range cases {
		seen := testNow
		due := seen.Add(c.interval)
		d := HeartbeatDeadline{LastSeenAt: &seen, DueAt: &due, Interval: c.interval}
		steps := []struct {
			after time.Duration
			want  SensorHealth
		}{
			{0, SensorHealthOnline},
			{c.lateAt, SensorHealthOnline},
			{c.lateAt + time.Nanosecond, SensorHealthLate},
			{c.staleAt, SensorHealthLate},
			{c.staleAt + time.Nanosecond, SensorHealthStale},
			{c.offlineAt, SensorHealthStale},
			{c.offlineAt + time.Nanosecond, SensorHealthOffline},
		}
		for _, s := range steps {
			if got := Ladder(seen.Add(s.after), d).State; got != s.want {
				t.Errorf("interval %s, %s after the heartbeat: %q, want %q", c.interval, s.after, got, s.want)
			}
		}
		if got := OfflineDistance(c.interval); got != c.offlineAt {
			t.Errorf("OfflineDistance(%s) = %s, want %s", c.interval, got, c.offlineAt)
		}
	}
}

func TestLadder_Deadline(t *testing.T) {
	t.Run("no stored deadline: last seen + 60s", func(t *testing.T) {
		pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: at(-time.Minute)})
		if pos.Interval != DefaultHeartbeatInterval || !pos.Due.Equal(testNow) || pos.State != SensorHealthOnline {
			t.Errorf("pos = %+v", pos)
		}
	})
	t.Run("never seen is offline", func(t *testing.T) {
		if pos := Ladder(testNow, HeartbeatDeadline{}); pos.State != SensorHealthOffline || !pos.Due.IsZero() {
			t.Errorf("pos = %+v", pos)
		}
	})
	t.Run("a later request than the heartbeat extends the deadline", func(t *testing.T) {
		// Heartbeat 200s ago (due 170s ago, 30s interval: offline at 80s
		// ago), but a poll 10s ago proves it alive.
		pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: at(-10 * time.Second), DueAt: at(-170 * time.Second), Interval: 30 * time.Second})
		if pos.State != SensorHealthOnline || !pos.Due.Equal(testNow.Add(20*time.Second)) {
			t.Errorf("pos = %+v", pos)
		}
	})
	t.Run("a stored deadline later than last seen + interval wins", func(t *testing.T) {
		pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: at(-50 * time.Second), DueAt: at(10 * time.Second), Interval: 5 * time.Second})
		if !pos.Due.Equal(testNow.Add(10 * time.Second)) {
			t.Errorf("due = %s", pos.Due)
		}
	})
	t.Run("an out-of-range interval is clamped", func(t *testing.T) {
		if pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: at(0), Interval: time.Hour}); pos.Interval != MaxHeartbeatInterval {
			t.Errorf("interval = %s", pos.Interval)
		}
		if pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: at(0), Interval: time.Millisecond}); pos.Interval != MinHeartbeatInterval {
			t.Errorf("interval = %s", pos.Interval)
		}
	})
}

func TestLadder_StepsAreOrdered(t *testing.T) {
	for i := 1; i <= 300; i++ {
		iv := time.Duration(i) * time.Second
		seen := testNow
		pos := Ladder(testNow, HeartbeatDeadline{LastSeenAt: &seen, Interval: iv})
		if !pos.Due.Before(pos.LateAt) || !pos.LateAt.Before(pos.StaleAt) || !pos.StaleAt.Before(pos.OfflineAt) {
			t.Fatalf("interval %s: due %s late %s stale %s offline %s", iv, pos.Due, pos.LateAt, pos.StaleAt, pos.OfflineAt)
		}
		// An advice of at most half the offline distance never convicts a
		// sensor that follows it (RFC-035 D2).
		if 2*iv > OfflineDistance(iv) {
			t.Fatalf("interval %s exceeds half its offline distance %s", iv, OfflineDistance(iv))
		}
	}
}

func TestFollowedHeartbeatInterval(t *testing.T) {
	ctl := func(s float64) *ControlReport { return &ControlReport{IntervalSeconds: s} }
	cases := []struct {
		name    string
		control *ControlReport
		advised int
		aware   bool
		want    time.Duration
	}{
		{"ignores hints, no report: SDK default", nil, 30, false, 60 * time.Second},
		{"aware: the advice", nil, 30, true, 30 * time.Second},
		{"aware without advice: default", nil, 0, true, 60 * time.Second},
		{"reported interval", ctl(20), 0, false, 20 * time.Second},
		{"reported interval beats a shorter advice", ctl(60), 5, true, 60 * time.Second},
		{"fresh longer advice beats the report", ctl(5), 45, true, 45 * time.Second},
		{"advice to a sensor that ignores hints is not used", ctl(30), 45, false, 30 * time.Second},
		{"fractional report", ctl(2.5), 0, false, 2500 * time.Millisecond},
		{"report above the cap", ctl(3600), 0, false, MaxHeartbeatInterval},
		{"report below the floor", ctl(0.01), 0, false, MinHeartbeatInterval},
		{"zero report: default", ctl(0), 0, false, DefaultHeartbeatInterval},
	}
	for _, c := range cases {
		if got := FollowedHeartbeatInterval(c.control, c.advised, c.aware); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestParseControlReport(t *testing.T) {
	got := ParseControlReport(json.RawMessage(`{"interval_s":30,"gap_s":30.0041,"lag_ms":1,"build_ms":3,"rtt_ms":9,"failures":0,"extra":"x"}`))
	want := ControlReport{IntervalSeconds: 30, GapSeconds: 30.004, LagMillis: 1, BuildMillis: 3, RTTMillis: 9}
	if got == nil || *got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	for _, raw := range []string{``, `null`, `[]`, `"x"`, `{}`, `{"unknown":1}`, `{"interval_s":"30"}`, `{bad`} {
		if c := ParseControlReport(json.RawMessage(raw)); c != nil {
			t.Errorf("%q: got %+v, want nil", raw, c)
		}
	}

	// A member of the wrong type is ignored, the rest kept.
	if c := ParseControlReport(json.RawMessage(`{"interval_s":"30","lag_ms":7}`)); c == nil || c.IntervalSeconds != 0 || c.LagMillis != 7 {
		t.Errorf("lenient: %+v", c)
	}

	// Hostile values are clamped.
	c := ParseControlReport(json.RawMessage(`{"interval_s":-5,"gap_s":1e300,"lag_ms":1e300,"build_ms":-1,"rtt_ms":99999999999,"failures":1e12}`))
	if c == nil || c.IntervalSeconds != 0 || c.GapSeconds != MaxReportedControlSeconds || c.LagMillis != MaxReportedControlMillis ||
		c.BuildMillis != 0 || c.RTTMillis != MaxReportedControlMillis || c.Failures != MaxReportedControlFailures {
		t.Errorf("clamped: %+v", c)
	}
}

func TestControlReport_Clamp_NaN(t *testing.T) {
	c := ControlReport{IntervalSeconds: math.NaN(), GapSeconds: math.Inf(1)}.Clamp()
	if c.IntervalSeconds != 0 || c.GapSeconds != 0 {
		t.Errorf("clamp = %+v", c)
	}
}

func TestSensorHealth_Dispatchable(t *testing.T) {
	for h, want := range map[SensorHealth]bool{
		SensorHealthOnline: true, SensorHealthLate: true, SensorHealthStale: false,
		SensorHealthOffline: false, SensorHealthUnknown: false, SensorHealthError: false,
	} {
		if got := h.IsDispatchable(); got != want {
			t.Errorf("%s dispatchable = %v", h, got)
		}
	}
}
