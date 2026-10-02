package sensor

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func diffSensor() *Sensor {
	tid := shared.NewID()
	started := time.Now().Add(-time.Hour)
	seen := time.Now().Add(-time.Minute)
	return &Sensor{
		ID: shared.NewID(), TenantID: &tid, Version: "0.4.1", MaxConcurrentJobs: 5,
		StartedAt: &started, LastSeenAt: &seen, Health: SensorHealthOnline,
		Protocol: &ProtocolInfo{Version: 1},
		Build:    BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.8.0"},
		Reported: CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Version: "3.1.0", Installed: true}}},
	}
}

func typesOf(events []Event) map[EventType]Event {
	out := map[EventType]Event{}
	for _, e := range events {
		out[e.Type] = e
	}
	return out
}

func TestDiffHeartbeat_Steady(t *testing.T) {
	prev := diffSensor()
	start := *prev.StartedAt
	start = start.Add(2 * time.Second) // jitter of NOW() - uptime
	got := DiffHeartbeat(prev, HeartbeatObservation{
		At: time.Now(), Version: "v0.4.1", Protocol: 1, StartedAt: &start, Build: prev.Build,
		Report: &CapabilityReport{Tools: prev.Reported.Tools},
	})
	if len(got) != 0 {
		t.Fatalf("steady heartbeat produced %+v", got)
	}
}

func TestDiffHeartbeat_EveryChange(t *testing.T) {
	prev := diffSensor()
	now := time.Now()
	start := now.Add(-2 * time.Minute) // restarted before its last heartbeat was stored
	got := typesOf(DiffHeartbeat(prev, HeartbeatObservation{
		At: now, Version: "0.4.0", Protocol: 2, StartedAt: &start,
		Build: BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.9.0"},
		Report: &CapabilityReport{MaxConcurrentJobs: 2, Tools: []ReportedTool{
			{Name: "nuclei", Version: "3.2.0", Installed: true},
			{Name: "trivy", Version: "0.60.0", Installed: true},
		}},
	}))
	for _, typ := range []EventType{EventRestarted, EventVersionChanged, EventSDKVersionChanged, EventProtocolChanged,
		EventToolsChanged, EventCapacityChanged} {
		if _, ok := got[typ]; !ok {
			t.Errorf("missing %s in %+v", typ, got)
		}
	}
	if d := got[EventVersionChanged].Details; d["direction"] != "downgrade" {
		t.Errorf("version direction %+v", d)
	}
	if got[EventRestarted].Details["downtime_seconds"] != nil {
		t.Errorf("restart before the last heartbeat has no downtime: %+v", got[EventRestarted].Details)
	}
}

func TestDiffHeartbeat_FirstReportIsNotAChange(t *testing.T) {
	prev := diffSensor()
	prev.Version, prev.Protocol, prev.StartedAt, prev.Build, prev.Reported = "", nil, nil, BuildInfo{}, CapabilityReport{}
	start := time.Now().Add(-time.Second)
	got := DiffHeartbeat(prev, HeartbeatObservation{
		At: time.Now(), Version: "0.5.0", Protocol: 2, StartedAt: &start,
		Build:  BuildInfo{SDKVersion: "v0.9.0"},
		Report: &CapabilityReport{Tools: []ReportedTool{{Name: "nuclei", Installed: true}}},
	})
	if len(got) != 0 {
		t.Fatalf("first report produced %+v", got)
	}
}

func TestDiffHeartbeat_PlatformSensorRecordsNothing(t *testing.T) {
	prev := diffSensor()
	prev.TenantID = nil
	if got := DiffHeartbeat(prev, HeartbeatObservation{At: time.Now(), Version: "v9.9.9"}); got != nil {
		t.Fatalf("platform sensor: %+v", got)
	}
	if _, ok := OfflineEvent(prev, time.Now()); ok {
		t.Fatal("platform sensor offline event")
	}
}

func TestDiffHeartbeat_Content(t *testing.T) {
	prev := diffSensor()
	prev.Reported.Tools = []ReportedTool{{Name: "trivy", Installed: true, Content: []ReportedContent{{Name: "trivy-db", Version: "a"}}}}
	got := typesOf(DiffHeartbeat(prev, HeartbeatObservation{At: time.Now(), Report: &CapabilityReport{Tools: []ReportedTool{
		{Name: "trivy", Installed: true, Content: []ReportedContent{{Name: "trivy-db", Version: "b", Error: "registry unreachable"}}},
	}}}))
	if _, ok := got[EventContentUpdated]; !ok {
		t.Error("content_updated missing")
	}
	if _, ok := got[EventContentRefreshFailed]; !ok {
		t.Error("content_refresh_failed missing")
	}
}

func TestOnlineEvent(t *testing.T) {
	s := diffSensor()
	s.Health = SensorHealthOffline
	e, ok := OnlineEvent(s, s.LastSeenAt.Add(3*time.Minute))
	if !ok || e.Details["offline_seconds"] != int64(180) {
		t.Fatalf("online %+v", e)
	}
	s.LastSeenAt = nil
	if e, _ = OnlineEvent(s, time.Now()); e.Summary != "Connected for the first time" {
		t.Fatalf("first connect %+v", e)
	}
}

func TestActivityCursorRoundTrip(t *testing.T) {
	c := ActivityCursor{At: time.Date(2026, 10, 2, 1, 2, 3, 456789000, time.UTC), Key: "e:abc"}
	got, err := ParseActivityCursor(c.Encode())
	if err != nil || !got.At.Equal(c.At) || got.Key != c.Key {
		t.Fatalf("round trip %+v %v", got, err)
	}
	for _, bad := range []string{"!!", "bm9waXBl", string(make([]byte, 300))} {
		if _, err := ParseActivityCursor(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
