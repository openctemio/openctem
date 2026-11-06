package sensor

import (
	"net"
	"testing"
	"time"
)

// The state digest ignores what changes on every heartbeat (metrics, load,
// outbox, control, interval) and moves with what Postgres must hear about.
func TestHeartbeatStateDigest(t *testing.T) {
	base := HeartbeatUpdate{
		Version: "1.0.0", Hostname: "h", IPAddress: net.ParseIP("192.0.2.1"), Protocol: 2,
		CPUPercent: 10, Interval: 30 * time.Second,
		Load: &LoadReport{Capacity: &ReportedCapacity{SlotsTotal: 4, SlotsFree: 2}},
	}
	d := HeartbeatStateDigest(base)

	volatile := base
	volatile.CPUPercent, volatile.MemoryPercent, volatile.LoadScore = 90, 80, 0.7
	volatile.Interval = 45 * time.Second
	volatile.Load = &LoadReport{Capacity: &ReportedCapacity{SlotsTotal: 4, SlotsFree: 1}, Queue: &ReportedQueue{Running: 3}}
	volatile.Outbox = &OutboxStats{}
	volatile.Control = &ControlReport{IntervalSeconds: 45}
	if HeartbeatStateDigest(volatile) != d {
		t.Fatal("volatile heartbeat fields changed the state digest")
	}

	for name, mut := range map[string]func(*HeartbeatUpdate){
		"version":  func(h *HeartbeatUpdate) { h.Version = "1.1.0" },
		"ip":       func(h *HeartbeatUpdate) { h.IPAddress = net.ParseIP("192.0.2.2") },
		"protocol": func(h *HeartbeatUpdate) { h.Protocol = 3 },
		"slots full": func(h *HeartbeatUpdate) {
			h.Load = &LoadReport{Capacity: &ReportedCapacity{SlotsTotal: 4, SlotsFree: 0}}
		},
		"slots": func(h *HeartbeatUpdate) {
			h.Load = &LoadReport{Capacity: &ReportedCapacity{SlotsTotal: 8, SlotsFree: 2}}
		},
		"config":  func(h *HeartbeatUpdate) { h.ConfigReportDigest = "abc" },
		"restart": func(h *HeartbeatUpdate) { h.UptimeSeconds = 5 },
		"report":  func(h *HeartbeatUpdate) { h.Report = &CapabilityReport{OS: "linux"} },
	} {
		c := base
		mut(&c)
		if HeartbeatStateDigest(c) == d {
			t.Errorf("%s change left the state digest unchanged", name)
		}
	}
}

// The merged deadline takes the later of the store's and Postgres's.
func TestLivenessSnapshotDeadline(t *testing.T) {
	t0 := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	old, oldDue := t0.Add(-10*time.Minute), t0.Add(-9*time.Minute)
	stored := HeartbeatDeadline{LastSeenAt: &old, DueAt: &oldDue, Interval: time.Minute}
	snap := LivenessSnapshot{SeenAt: t0, DueAt: t0.Add(30 * time.Second), Interval: 30 * time.Second}
	got := snap.Deadline(stored)
	if !got.LastSeenAt.Equal(t0) || !got.DueAt.Equal(t0.Add(30*time.Second)) || got.Interval != 30*time.Second {
		t.Fatalf("store newer: %+v", got)
	}
	if Ladder(t0.Add(20*time.Second), got).State != SensorHealthOnline {
		t.Fatal("merged deadline not online")
	}
	// Postgres newer (a fallback write): it stands.
	fresh, freshDue := t0.Add(time.Minute), t0.Add(90*time.Second)
	got = LivenessSnapshot{SeenAt: t0, DueAt: t0}.Deadline(HeartbeatDeadline{LastSeenAt: &fresh, DueAt: &freshDue, Interval: 30 * time.Second})
	if !got.LastSeenAt.Equal(fresh) || !got.DueAt.Equal(freshDue) {
		t.Fatalf("postgres newer: %+v", got)
	}
	// No entry: the stored deadline unchanged.
	if got := (LivenessSnapshot{}).Deadline(stored); got.LastSeenAt != stored.LastSeenAt {
		t.Fatal("empty snapshot changed the deadline")
	}
}

func TestParseLivenessMode(t *testing.T) {
	for in, want := range map[string]LivenessMode{"": LivenessShadow, "redis": LivenessRedis, " Postgres ": LivenessPostgres, "shadow": LivenessShadow} {
		if got, err := ParseLivenessMode(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseLivenessMode("memory"); err == nil {
		t.Error("unknown mode accepted")
	}
}
