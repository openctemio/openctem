package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// The sensor page reads local_policy: always present, "unknown" for a sensor
// that never reported, "paused" while the kill switch is engaged.
func TestLocalPolicyResponse(t *testing.T) {
	never := localPolicyResponse(&sensor.Sensor{})
	raw, _ := json.Marshal(never)
	if never.State != "unknown" || string(raw) != `{"state":"unknown","kill_switch":false}` {
		t.Fatalf("never reported: %s", raw)
	}
	at := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	got := localPolicyResponse(&sensor.Sensor{LocalPolicyReportedAt: &at, LocalPolicy: &sensor.LocalPolicyReport{
		State: sensor.LocalPolicyEnforced, Source: "file", Digest: digest, KillSwitch: true,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: 2, Tools: []string{"nuclei"}},
	}})
	if got.State != "paused" || got.Digest != digest || !got.KillSwitch || got.Summary.TargetsAllow != 2 ||
		got.ReportedAt == nil || *got.ReportedAt != "2026-10-03T10:00:00Z" {
		t.Fatalf("%+v", got)
	}
	if s := localPolicyResponse(&sensor.Sensor{LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent}}); s.State != "absent" {
		t.Fatalf("absent: %+v", s)
	}
}
