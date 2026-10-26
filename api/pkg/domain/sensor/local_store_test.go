package sensor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseLocalStoreReport(t *testing.T) {
	r := ParseLocalStoreReport(json.RawMessage(`{
		"level": "high", "stop_claiming": true,
		"reason": "9 % of the volume free,\nbelow 10 %\u202e; injected",
		"bytes_by_class": {"outbox": 1024, "workspace": -5, "secrets": 99, "log": "big"},
		"total_bytes": 1e30, "quota_bytes": 2048, "disk_level": "low",
		"sweeps": 3, "last_sweep_at": "2026-10-25T08:00:00Z", "last_sweep_removed": 2,
		"boot": 7, "boot_reset": true, "tampered": 1
	}`))
	if r == nil {
		t.Fatal("nil report")
	}
	if r.Level != LocalStoreLevelHigh || !r.StopClaiming || r.DiskLevel != LocalDiskLow {
		t.Fatalf("levels %+v", r)
	}
	// One line, no bidi override, no newline.
	if r.Reason != "9 % of the volume free, below 10 % ; injected" {
		t.Fatalf("reason %q", r.Reason)
	}
	// Known classes only, negatives to 0, non-numbers dropped.
	if len(r.BytesByClass) != 2 || r.BytesByClass["outbox"] != 1024 || r.BytesByClass["workspace"] != 0 {
		t.Fatalf("classes %+v", r.BytesByClass)
	}
	if _, ok := r.BytesByClass["secrets"]; ok {
		t.Fatal("unknown class kept")
	}
	if r.TotalBytes != MaxLocalStoreBytes || r.QuotaBytes != 2048 {
		t.Fatalf("bytes %d / %d", r.TotalBytes, r.QuotaBytes)
	}
	if r.Sweeps != 3 || r.LastSweepAt == nil || r.LastSweepRemoved != 2 || !r.BootReset || r.Tampered != 1 {
		t.Fatalf("sweeps %+v", r)
	}
	if r.UsedFraction() != 1 {
		t.Fatalf("used %v", r.UsedFraction())
	}
}

func TestParseLocalStoreReport_Lenient(t *testing.T) {
	for _, raw := range []string{``, `null`, `[]`, `"x"`, `{}`, `{"reason": "only a reason"}`, `{"level": 3}`} {
		if r := ParseLocalStoreReport(json.RawMessage(raw)); r != nil {
			t.Errorf("%s: %+v, want nil", raw, r)
		}
	}
	// A value outside its set is dropped, the report is kept.
	r := ParseLocalStoreReport(json.RawMessage(`{"level": "melting", "stop_claiming": false, "disk_level": "full"}`))
	if r == nil || r.Level != "" || r.DiskLevel != "" || r.StopClaiming {
		t.Fatalf("%+v", r)
	}
	// A very long reason is cut.
	r = ParseLocalStoreReport(json.RawMessage(`{"stop_claiming": true, "reason": "` + strings.Repeat("a", 1000) + `"}`))
	if r == nil || len([]rune(r.Reason)) != MaxLocalStoreReasonRunes {
		t.Fatalf("reason length %d", len([]rune(r.Reason)))
	}
}

func TestCurrentLocalStore_Freshness(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	reported := now.Add(-time.Minute)
	a := &Sensor{LastSeenAt: &now, HeartbeatInterval: 30 * time.Second,
		LocalStore: &LocalStoreReport{StopClaiming: true, ReportedAt: &reported}}
	if !a.StoppedClaiming() {
		t.Fatal("a report from the last minute is current")
	}
	old := now.Add(-2 * time.Hour)
	a.LocalStore.ReportedAt = &old
	if a.CurrentLocalStore() != nil || a.StoppedClaiming() {
		t.Fatal("a report left behind two hours ago is not current")
	}
	a.LocalStore.ReportedAt = nil
	if a.StoppedClaiming() {
		t.Fatal("a report without a time is not current")
	}
	a.LocalStore = nil
	if a.StoppedClaiming() {
		t.Fatal("no report")
	}
}

func TestAssessHealth_StoppedClaiming(t *testing.T) {
	now := time.Now().UTC()
	due := now.Add(time.Minute)
	a := &Sensor{Status: SensorStatusActive, Health: SensorHealthOnline, LastSeenAt: &now,
		HeartbeatDueAt: &due, HeartbeatInterval: 30 * time.Second, Type: SensorTypeWorker,
		ExecutionMode: ExecutionModeDaemon, Capabilities: []string{"nuclei"},
		LocalStore: &LocalStoreReport{StopClaiming: true, Level: LocalStoreLevelHigh, DiskLevel: LocalDiskLow,
			Reason: "9 % of the volume free, below 10 %", ReportedAt: &now}}
	h := a.AssessHealth(now, DefaultHealthPolicy())
	var got *HealthReason
	for i := range h.Reasons {
		if h.Reasons[i].Code == ReasonStoppedClaiming {
			got = &h.Reasons[i]
		}
	}
	if got == nil {
		t.Fatalf("no stopped_claiming reason: %+v", h.Reasons)
	}
	if got.Severity != SeverityCritical || !strings.Contains(got.Message, "disk") ||
		!strings.Contains(got.Message, "9 % of the volume free") || h.State != StateDegraded {
		t.Fatalf("reason %+v state %s", got, h.State)
	}

	a.LocalStore.StopClaiming = false
	for _, r := range a.AssessHealth(now, DefaultHealthPolicy()).Reasons {
		if r.Code == ReasonStoppedClaiming {
			t.Fatal("a sensor that claims has no stopped_claiming reason")
		}
	}
}

func TestHeartbeatStateDigest_StoreGate(t *testing.T) {
	base := HeartbeatUpdate{Version: "v1", LocalStore: &LocalStoreReport{Level: LocalStoreLevelOK, TotalBytes: 10}}
	bytesOnly := base
	bytesOnly.LocalStore = &LocalStoreReport{Level: LocalStoreLevelOK, TotalBytes: 99999}
	if HeartbeatStateDigest(base) != HeartbeatStateDigest(bytesOnly) {
		t.Fatal("byte counts alone must not force a Postgres write")
	}
	stopped := base
	stopped.LocalStore = &LocalStoreReport{Level: LocalStoreLevelHigh, StopClaiming: true, TotalBytes: 10}
	if HeartbeatStateDigest(base) == HeartbeatStateDigest(stopped) {
		t.Fatal("stop_claiming must be written at once")
	}
}
