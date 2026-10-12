package sensor

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRecoveredEvent_JudgedOnTheHeartbeatDeadline(t *testing.T) {
	tenant := shared.NewID()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	for _, c := range []struct {
		name string
		due  *time.Time
		want SensorHealth // "" = no event
	}{
		{"no deadline", nil, ""},
		{"on time", at(5 * time.Second), ""},
		{"within grace", at(-10 * time.Second), ""},
		{"late", at(-50 * time.Second), SensorHealthLate},
		{"stale", at(-90 * time.Second), SensorHealthStale},
		{"offline", at(-10 * time.Minute), SensorHealthOffline},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A poll a second ago does not hide a late heartbeat.
			s := &Sensor{ID: shared.NewID(), TenantID: &tenant, HeartbeatDueAt: c.due, HeartbeatInterval: 30 * time.Second,
				LastSeenAt: at(-time.Second), Health: SensorHealthOnline}
			e, ok := RecoveredEvent(s, now)
			if c.want == "" {
				if ok {
					t.Fatalf("unexpected event %+v", e)
				}
				return
			}
			if !ok || e.Type != EventHeartbeatRecovered || e.Details["was"] != string(c.want) || e.Type.Category() != CategoryStatus {
				t.Fatalf("event %+v ok %v, want was=%s", e, ok, c.want)
			}
			if gap := e.Details["gap_seconds"].(int64); gap != int64(now.Sub(c.due.Add(-30*time.Second))/time.Second) {
				t.Fatalf("gap_seconds %d", gap)
			}
		})
	}
	// Platform sensors (no tenant) have no timeline.
	if _, ok := RecoveredEvent(&Sensor{HeartbeatDueAt: at(-time.Hour), HeartbeatInterval: time.Minute}, now); ok {
		t.Fatal("event for a platform sensor")
	}
}

func TestHeartbeatHistory_BucketsAndClamping(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 44, 59, 0, time.FixedZone("x", 3600))
	if got := HeartbeatBucketStart(at); !got.Equal(time.Date(2026, 10, 2, 11, 30, 0, 0, time.UTC)) {
		t.Fatalf("bucket start %s", got)
	}
	s := HeartbeatSample{Gap: 72 * time.Hour, Interval: -time.Second, LagMillis: -5, Failures: 1 << 40}.Clamped()
	if s.Gap != MaxRecordedHeartbeatGap || s.Interval != 0 || s.LagMillis != 0 || s.Failures != 1_000_000 {
		t.Fatalf("clamped %+v", s)
	}
}
