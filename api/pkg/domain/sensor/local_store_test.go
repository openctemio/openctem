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

// The content member of a local store report is read leniently: digests that
// are not sha256 digests are dropped, counts are clamped, and the held list
// is bounded.
func TestParseLocalStoreReport_Content(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	held := []any{good, "sha256:zz", "../../etc/passwd", 7, "SHA256:" + strings.Repeat("A", 64)}
	for i := 0; i < MaxReportedPackDigests+10; i++ {
		held = append(held, "sha256:"+strings.Repeat("b", 63)+string(rune('0'+i%10)))
	}
	raw, _ := json.Marshal(map[string]any{
		"level": "ok", "total_bytes": 10,
		"content": map[string]any{
			"held": held, "held_count": 9e18, "held_set_sha256": strings.Repeat("c", 64), "bytes": 5, "hits": 3, "misses": 1,
			"bytes_downloaded": 100, "bytes_saved": 400, "verify_failures": 2, "desired_version": `"abc-123"`,
		},
	})
	r := ParseLocalStoreReport(raw)
	if r == nil || r.Content == nil {
		t.Fatalf("report = %+v", r)
	}
	c := r.Content
	if len(c.Held) != MaxReportedPackDigests || c.Held[0] != good {
		t.Errorf("held = %d entries, first %q", len(c.Held), c.Held[0])
	}
	for _, d := range c.Held {
		if !packDigestRE.MatchString(d) {
			t.Errorf("kept a malformed digest %q", d)
		}
	}
	if c.HeldCount != MaxLocalStoreCount || c.HeldSetSHA256 != strings.Repeat("c", 64) || c.Hits != 3 || c.BytesSaved != 400 || c.VerifyFailures != 2 || c.DesiredVersion != `"abc-123"` {
		t.Errorf("content = %+v", c)
	}
	// Garbage members are ignored, not an error.
	raw, _ = json.Marshal(map[string]any{"level": "ok", "content": map[string]any{
		"held_set_sha256": "nope", "desired_version": "has spaces and <b>", "hits": "many", "held": "not a list",
	}})
	r = ParseLocalStoreReport(raw)
	if r == nil || r.Content == nil || r.Content.HeldSetSHA256 != "" || r.Content.DesiredVersion != "" || r.Content.Hits != 0 || len(r.Content.Held) != 0 {
		t.Errorf("garbage content = %+v", r)
	}
	// A content member that is not an object is dropped.
	raw, _ = json.Marshal(map[string]any{"level": "ok", "content": "x"})
	if r = ParseLocalStoreReport(raw); r == nil || r.Content != nil {
		t.Errorf("non-object content = %+v", r)
	}
}

// The stored report keeps the content member through JSON (it is written to
// reported_local_store and read back).
func TestLocalStoreReport_ContentSurvivesStorage(t *testing.T) {
	raw := []byte(`{"level":"ok","total_bytes":1,"content":{"held":["sha256:` + strings.Repeat("a", 64) + `"],"held_count":1,"bytes":9,"desired_version":"\"v1\""}}`)
	r := ParseLocalStoreReport(raw)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back LocalStoreReport
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Content == nil || back.Content.HeldCount != 1 || len(back.Content.Held) != 1 || back.Content.DesiredVersion != `"v1"` || back.Content.Bytes != 9 {
		t.Fatalf("stored content = %+v", back.Content)
	}
}
