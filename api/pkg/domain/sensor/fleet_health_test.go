package sensor

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func testPolicy() HealthPolicy {
	return HealthPolicy{
		OnlineWindow:     90 * time.Second,
		OfflineAfter:     5 * time.Minute,
		KeyExpiryWarning: 7 * 24 * time.Hour,
		LatestVersion:    "v0.4.2",
		MinVersion:       "v0.4.0",
	}.Normalized()
}

func ago(d time.Duration) *time.Time {
	t := testNow.Add(-d)
	return &t
}

func daemon(lastSeen *time.Time) *Sensor {
	return &Sensor{
		Type:          SensorTypeWorker,
		ExecutionMode: ExecutionModeDaemon,
		Status:        SensorStatusActive,
		Health:        SensorHealthOnline,
		Tools:         []string{"nuclei"},
		Version:       "v0.4.2",
		LastSeenAt:    lastSeen,
	}
}

func codes(rs []HealthReason) []HealthReasonCode {
	out := make([]HealthReasonCode, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Code)
	}
	return out
}

func hasCode(rs []HealthReason, c HealthReasonCode) bool {
	for _, r := range rs {
		if r.Code == c {
			return true
		}
	}
	return false
}

func TestAssessHealth_StateLadder(t *testing.T) {
	p := testPolicy()
	cases := []struct {
		name   string
		sensor func() *Sensor
		want   State
	}{
		// No stored deadline: due = last seen + 60s, grace 12s, late after
		// 72s, stale after 192s, offline step after 240s; unconvicted it
		// stays stale until the 5 min heartbeat timeout.
		{"online: heartbeat 10s ago", func() *Sensor { return daemon(ago(10 * time.Second)) }, StateOnline},
		{"online at the grace edge", func() *Sensor { return daemon(ago(72 * time.Second)) }, StateOnline},
		{"late: just past the grace", func() *Sensor { return daemon(ago(73 * time.Second)) }, StateLate},
		{"late at the stale edge", func() *Sensor { return daemon(ago(192 * time.Second)) }, StateLate},
		{"stale: just past the late step", func() *Sensor { return daemon(ago(193 * time.Second)) }, StateStale},
		{"stale past the offline step while not convicted", func() *Sensor { return daemon(ago(4 * time.Minute)) }, StateStale},
		{"stale at the heartbeat timeout while not convicted", func() *Sensor { return daemon(ago(5 * time.Minute)) }, StateStale},
		{"offline past the heartbeat timeout", func() *Sensor { return daemon(ago(5*time.Minute + time.Second)) }, StateOffline},
		{"offline: convicted past the offline step", func() *Sensor {
			s := daemon(ago(241 * time.Second))
			s.Health = SensorHealthOffline
			return s
		}, StateOffline},
		{"busy sensor (5s deadline) is stale after 25s", func() *Sensor {
			s := daemon(ago(26 * time.Second))
			s.HeartbeatInterval, s.HeartbeatDueAt = 5*time.Second, ago(21*time.Second)
			return s
		}, StateStale},
		{"loaded sensor (45s deadline) is online at 50s", func() *Sensor {
			s := daemon(ago(50 * time.Second))
			s.HeartbeatInterval, s.HeartbeatDueAt = 45*time.Second, ago(5*time.Second)
			return s
		}, StateOnline},
		{"late sensor with problems stays late", func() *Sensor {
			s := daemon(ago(100 * time.Second))
			s.Outbox = &OutboxStats{DeadLetterCount: 2}
			return s
		}, StateLate},
		{"offline: checker marked it, time not yet past", func() *Sensor {
			s := daemon(ago(2 * time.Minute))
			s.Health = SensorHealthOffline
			return s
		}, StateOffline},
		{"never connected", func() *Sensor { return daemon(nil) }, StateNeverConnected},
		{"disabled wins over heartbeat", func() *Sensor {
			s := daemon(ago(5 * time.Second))
			s.Status = SensorStatusDisabled
			return s
		}, StateDisabled},
		{"revoked wins over everything", func() *Sensor {
			s := daemon(nil)
			s.Status = SensorStatusRevoked
			return s
		}, StateRevoked},
		{"CI runner between runs is idle, not offline", func() *Sensor {
			s := daemon(ago(3 * time.Hour))
			s.Type, s.ExecutionMode = SensorTypeWorker, ExecutionModeStandalone
			return s
		}, StateIdle},
		{"CI runner during a run is online", func() *Sensor {
			s := daemon(ago(20 * time.Second))
			s.Type, s.ExecutionMode = SensorTypeWorker, ExecutionModeStandalone
			return s
		}, StateOnline},
		{"CI runner that never ran", func() *Sensor {
			s := daemon(nil)
			s.Type, s.ExecutionMode = SensorTypeWorker, ExecutionModeStandalone
			return s
		}, StateNeverConnected},
		{"heartbeating with an outbox backlog is degraded", func() *Sensor {
			s := daemon(ago(5 * time.Second))
			s.Outbox = &OutboxStats{PendingCount: 148, OldestAgeSeconds: 8040}
			return s
		}, StateDegraded},
		{"stale stays stale even with problems", func() *Sensor {
			s := daemon(ago(200 * time.Second))
			s.Outbox = &OutboxStats{DeadLetterCount: 2}
			return s
		}, StateStale},
		{"heartbeat in the future (clock skew) counts as online", func() *Sensor {
			future := testNow.Add(30 * time.Second)
			return daemon(&future)
		}, StateOnline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.sensor().AssessHealth(testNow, p).State; got != c.want {
				t.Errorf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAssessHealth_DegradedReasons(t *testing.T) {
	p := testPolicy()

	t.Run("healthy sensor has no reasons and an empty, non-nil list", func(t *testing.T) {
		a := daemon(ago(5*time.Second)).AssessHealth(testNow, p)
		if a.Reasons == nil || len(a.Reasons) != 0 {
			t.Fatalf("reasons = %#v, want empty non-nil", a.Reasons)
		}
		if a.State != StateOnline {
			t.Fatalf("state = %q", a.State)
		}
	})

	t.Run("outbox: backlog, dead letters, evictions", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Outbox = &OutboxStats{PendingCount: 3, OldestAgeSeconds: 4000, DeadLetterCount: 1, EvictedCount: 2}
		a := s.AssessHealth(testNow, p)
		for _, c := range []HealthReasonCode{ReasonOutboxBacklog, ReasonOutboxDeadLetters, ReasonOutboxEvicted} {
			if !hasCode(a.Reasons, c) {
				t.Errorf("missing %s in %v", c, codes(a.Reasons))
			}
		}
		if a.State != StateDegraded {
			t.Errorf("state = %q", a.State)
		}
	})

	t.Run("a small fresh outbox is fine", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Outbox = &OutboxStats{PendingCount: 2, OldestAgeSeconds: 30}
		if a := s.AssessHealth(testNow, p); len(a.Reasons) != 0 || a.State != StateOnline {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("key expiring within 7 days", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		exp := testNow.Add(6 * 24 * time.Hour)
		s.InlineKeyExpiresAt = &exp
		a := s.AssessHealth(testNow, p)
		if !hasCode(a.Reasons, ReasonKeyExpiring) || a.State != StateDegraded {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("key expiring in 30 days is fine", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		exp := testNow.Add(30 * 24 * time.Hour)
		s.InlineKeyExpiresAt = &exp
		if a := s.AssessHealth(testNow, p); len(a.Reasons) != 0 {
			t.Errorf("reasons=%v", codes(a.Reasons))
		}
	})

	t.Run("expired key is reported even when offline", func(t *testing.T) {
		s := daemon(ago(time.Hour))
		exp := testNow.Add(-time.Minute)
		s.InlineKeyExpiresAt = &exp
		a := s.AssessHealth(testNow, p)
		if a.State != StateOffline || !hasCode(a.Reasons, ReasonKeyExpired) {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
		if hasCode(a.Reasons, ReasonKeyExpiring) {
			t.Error("an expired key is not also 'expiring'")
		}
	})

	t.Run("version below the minimum", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Version = "0.3.0"
		a := s.AssessHealth(testNow, p)
		if a.VersionStatus != VersionUnsupported || !hasCode(a.Reasons, ReasonVersionUnsupported) || a.State != StateDegraded {
			t.Errorf("version=%q state=%q reasons=%v", a.VersionStatus, a.State, codes(a.Reasons))
		}
		if a.Version != "v0.3.0" {
			t.Errorf("normalized version = %q", a.Version)
		}
	})

	t.Run("an available update is not a health problem", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Version = "v0.4.1"
		a := s.AssessHealth(testNow, p)
		if a.VersionStatus != VersionUpdateAvailable || len(a.Reasons) != 0 || a.State != StateOnline {
			t.Errorf("version=%q state=%q reasons=%v", a.VersionStatus, a.State, codes(a.Reasons))
		}
	})

	t.Run("a scanning daemon without tools", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Tools = nil
		if a := s.AssessHealth(testNow, p); !hasCode(a.Reasons, ReasonNoTools) || a.State != StateDegraded {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("a collector needs no scan tools", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Type, s.Tools = SensorTypeCollector, nil
		if a := s.AssessHealth(testNow, p); len(a.Reasons) != 0 {
			t.Errorf("reasons=%v", codes(a.Reasons))
		}
	})

	t.Run("sensor-reported error", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Health = SensorHealthError
		s.StatusMessage = "trivy db download failed"
		a := s.AssessHealth(testNow, p)
		if !hasCode(a.Reasons, ReasonErrorReported) || a.State != StateDegraded {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("a late heartbeat is a reason", func(t *testing.T) {
		a := daemon(ago(100*time.Second)).AssessHealth(testNow, p)
		if a.State != StateLate || !hasCode(a.Reasons, ReasonHeartbeatLate) {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("control: a late gap and a slow loop degrade an online sensor", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Control = &ControlReport{IntervalSeconds: 30, GapSeconds: 46, LagMillis: 5001}
		a := s.AssessHealth(testNow, p)
		if a.State != StateDegraded || !hasCode(a.Reasons, ReasonHeartbeatLate) || !hasCode(a.Reasons, ReasonControlSlow) {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("control: on time and fast is fine", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Control = &ControlReport{IntervalSeconds: 30, GapSeconds: 45, LagMillis: 5000, BuildMillis: 5000}
		if a := s.AssessHealth(testNow, p); a.State != StateOnline || len(a.Reasons) != 0 {
			t.Errorf("state=%q reasons=%v", a.State, codes(a.Reasons))
		}
	})

	t.Run("a late sensor with a late gap lists heartbeat_late once", func(t *testing.T) {
		s := daemon(ago(100 * time.Second))
		s.Control = &ControlReport{IntervalSeconds: 30, GapSeconds: 90}
		n := 0
		for _, r := range s.AssessHealth(testNow, p).Reasons {
			if r.Code == ReasonHeartbeatLate {
				n++
			}
		}
		if n != 1 {
			t.Errorf("heartbeat_late listed %d times", n)
		}
	})

	t.Run("every reason has a severity and a message", func(t *testing.T) {
		s := daemon(ago(5 * time.Second))
		s.Tools, s.Version, s.Health = nil, "0.1.0", SensorHealthError
		exp := testNow.Add(time.Hour)
		s.InlineKeyExpiresAt = &exp
		s.Outbox = &OutboxStats{PendingCount: 1, OldestAgeSeconds: 9999, DeadLetterCount: 1, EvictedCount: 1}
		for _, r := range s.AssessHealth(testNow, p).Reasons {
			if r.Message == "" || (r.Severity != SeverityWarning && r.Severity != SeverityCritical) {
				t.Errorf("reason %+v", r)
			}
		}
	})
}

func TestAssessHealth_Uptime(t *testing.T) {
	p := testPolicy()
	s := daemon(ago(10 * time.Second))
	started := testNow.Add(-(6*24*time.Hour + 3*time.Hour))
	s.StartedAt = &started
	a := s.AssessHealth(testNow, p)
	if a.UptimeSeconds == nil {
		t.Fatal("uptime missing for a heartbeating sensor")
	}
	// Up to the last heartbeat, not to now: what the sensor reported.
	want := int64((6*24*time.Hour + 3*time.Hour - 10*time.Second).Seconds())
	if *a.UptimeSeconds != want {
		t.Errorf("uptime = %d, want %d", *a.UptimeSeconds, want)
	}

	off := daemon(ago(time.Hour))
	off.StartedAt = &started
	if a := off.AssessHealth(testNow, p); a.UptimeSeconds != nil {
		t.Errorf("an offline sensor has no uptime, got %d", *a.UptimeSeconds)
	}

	none := daemon(ago(time.Second))
	if a := none.AssessHealth(testNow, p); a.UptimeSeconds != nil {
		t.Error("uptime invented for a sensor that never reported one")
	}
}

func TestHealthPolicy_Normalized(t *testing.T) {
	p := HealthPolicy{}.Normalized()
	if p.OnlineWindow != DefaultOnlineWindow || p.OfflineAfter != DefaultOfflineAfter || p.KeyExpiryWarning != DefaultKeyExpiryWarning {
		t.Errorf("defaults = %+v", p)
	}
	// The online window never exceeds the offline timeout.
	p = HealthPolicy{OnlineWindow: 10 * time.Minute, OfflineAfter: time.Minute}.Normalized()
	if p.OnlineWindow != time.Minute {
		t.Errorf("online window = %s, want clamped to 1m", p.OnlineWindow)
	}
	// Versions are kept in normalized form; garbage is dropped.
	p = HealthPolicy{LatestVersion: "0.4.2", MinVersion: "not-a-version"}.Normalized()
	if p.LatestVersion != "v0.4.2" || p.MinVersion != "" {
		t.Errorf("versions = %q / %q", p.LatestVersion, p.MinVersion)
	}
}

func TestOnlineWindowFor(t *testing.T) {
	// The interval plus the ladder's grace; never past the timeout.
	if got := OnlineWindowFor(30*time.Second, 5*time.Minute); got != 40*time.Second {
		t.Errorf("30s idle -> %s", got)
	}
	if got := OnlineWindowFor(60*time.Second, 5*time.Minute); got != 72*time.Second {
		t.Errorf("60s idle -> %s", got)
	}
	if got := OnlineWindowFor(5*time.Minute, 5*time.Minute); got != 5*time.Minute {
		t.Errorf("5m idle -> %s", got)
	}
}
