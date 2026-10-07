package routes

// RFC-033 Phase 2 (§6.12, owner decisions O1-O3) through the v2 handlers:
// the policy echo, GET /manifest, slim heartbeats with the content block,
// the kill switch, and the manifest_changed event.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func phase2Manifest(nucleiVersion string, semgrepCaps []string) map[string]any {
	return map[string]any{
		"schema":       1,
		"sensor":       map[string]any{"name": "openctemio-sensor", "version": "v0.7.0"},
		"platform":     map[string]any{"os": "linux", "arch": "amd64"},
		"concurrency":  map[string]any{"ceiling": 3, "model": "dynamic"},
		"capabilities": []string{"validate"},
		"tools": []any{
			map[string]any{"name": "nuclei", "kind": "scanner", "version": nucleiVersion, "installed": true,
				"capabilities": []string{"dast"},
				"content":      []any{map[string]any{"name": "nuclei-templates", "version": "v10.4.9", "managed": true}}},
			map[string]any{"name": "semgrep", "kind": "scanner", "version": "1.179.0", "installed": true, "capabilities": semgrepCaps},
		},
	}
}

func (h *ctlHarness) getManifestState(s ctlSensor) (*http.Response, protov2.ManifestStateResponse, []byte) {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodGet, protov2.PathPrefix+protov2.ManifestPath, nil)
	var out protov2.ManifestStateResponse
	_ = json.Unmarshal(raw, &out)
	return resp, out, raw
}

// O2: the answer and GET carry the effective policy (every installed tool
// the manifest reports; the administrator's concurrency limit narrows), and
// GET follows a change of the administrator's settings.
func TestSensorManifestPhase2_PolicyEcho(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "policy", nil, nil, 5)

	resp, _, raw := h.getManifestState(s)
	h.want(resp, raw, http.StatusNotFound, protov2.ProblemManifestNotFound.URI())

	ack := h.putManifest(s, phase2Manifest("v3.11.1", []string{"sast"}))
	if !slices.Equal(ack.Policy.AllowedTools, []string{"nuclei", "semgrep"}) {
		t.Fatalf("policy tools %v, want the reported tools [nuclei semgrep]", ack.Policy.AllowedTools)
	}
	if ack.Policy.MaxJobs != 3 || !ack.Heartbeat.OmitInventory {
		t.Fatalf("policy max_jobs %d (ceiling 3 < admin 5), omit %v", ack.Policy.MaxJobs, ack.Heartbeat.OmitInventory)
	}

	resp, st, raw := h.getManifestState(s)
	h.want(resp, raw, http.StatusOK, "")
	if st.ManifestDigest != ack.ManifestDigest || !slices.Equal(st.Policy.AllowedTools, []string{"nuclei", "semgrep"}) {
		t.Fatalf("GET %s", raw)
	}

	// The administrator lowers the concurrency limit: GET follows.
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET max_concurrent_jobs = 2 WHERE id = $1`, s.id); err != nil {
		t.Fatal(err)
	}
	_, st, raw = h.getManifestState(s)
	if st.Policy.MaxJobs != 2 {
		t.Fatalf("GET after lowering the limit: %s", raw)
	}
}

// O3: a slim heartbeat keeps the manifest's projection (tools, kind,
// capabilities, ceiling) and merges its content freshness.
func TestSensorManifestPhase2_SlimHeartbeat(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "slim", nil, nil, 5)
	ack := h.putManifest(s, phase2Manifest("v3.11.1", []string{"sast"}))

	checked := time.Now().UTC().Truncate(time.Second)
	actions := h.heartbeatActions(s, map[string]any{
		"status": "running", "manifest_digest": ack.ManifestDigest,
		"capacity": map[string]any{"slots_total": 4, "slots_free": 4, "active_jobs": 0},
		"content": []any{map[string]any{"tool": "nuclei", "name": "nuclei-templates", "version": "v10.4.9", "managed": true,
			"checked_at": checked.Format(time.RFC3339), "error": "checksum mismatch"}},
	})
	if slices.Contains(actions, protov2.ActionSendManifest) {
		t.Fatalf("a slim heartbeat with the acknowledged digest was asked for the manifest: %v", actions)
	}
	got := h.load(s)
	if len(got.Reported.Tools) != 2 || got.Reported.Tools[0].Kind != "scanner" ||
		!slices.Equal(got.Reported.Tools[1].Capabilities, []string{"sast"}) {
		t.Fatalf("the slim heartbeat changed the tools: %+v", got.Reported.Tools)
	}
	if got.Reported.MaxConcurrentJobs != 3 || got.EffectiveMaxConcurrentJobs() != 3 {
		t.Fatalf("the slim heartbeat changed the ceiling: %d / %d", got.Reported.MaxConcurrentJobs, got.EffectiveMaxConcurrentJobs())
	}
	c := got.Reported.Tools[0].Content
	if len(c) != 1 || c[0].Error != "checksum mismatch" || c[0].CheckedAt == nil || !c[0].CheckedAt.Equal(checked) {
		t.Fatalf("content not merged: %+v", c)
	}
	if !got.HasCapability("validate") || !got.HasCapability("dast") {
		t.Fatalf("flat capabilities lost: %v", got.EffectiveCapabilities())
	}
}

// The kill switch: answers say omit_inventory false, and a slim heartbeat
// is asked for the manifest so the sensor goes back to full heartbeats.
func TestSensorManifestPhase2_KillSwitch(t *testing.T) {
	h := newCtlHarness(t)
	h.sensors.SetSlimHeartbeat(false)
	s := h.newLimitedSensor(h.tenantID, "kill", nil, nil, 5)
	ack := h.putManifest(s, phase2Manifest("v3.11.1", []string{"sast"}))
	if ack.Heartbeat.OmitInventory {
		t.Fatal("omit_inventory true with slim heartbeats switched off")
	}
	slim := map[string]any{"status": "running", "manifest_digest": ack.ManifestDigest}
	if a := h.heartbeatActions(s, slim); !slices.Contains(a, protov2.ActionSendManifest) {
		t.Fatalf("slim heartbeat under the kill switch not asked for the manifest: %v", a)
	}
	full := map[string]any{"status": "running", "manifest_digest": ack.ManifestDigest,
		"tools": []any{map[string]any{"name": "nuclei", "installed": true}}}
	if a := h.heartbeatActions(s, full); slices.Contains(a, protov2.ActionSendManifest) {
		t.Fatalf("full heartbeat asked for the manifest: %v", a)
	}
}

// O1: a changed manifest is one manifest_changed event with the diff and
// both digests, and no duplicate tools_changed.
func TestSensorManifestPhase2_ManifestChangedEvent(t *testing.T) {
	h := newCtlHarness(t)
	h.sensors.SetEventRepository(postgres.NewSensorEventRepository(&postgres.DB{DB: h.db}), sensor.DefaultEventLimits())
	s := h.newLimitedSensor(h.tenantID, "events", nil, nil, 5)
	first := h.putManifest(s, phase2Manifest("v3.11.1", []string{"sast"}))
	second := h.putManifest(s, phase2Manifest("v3.12.0", []string{"sast", "iac"}))

	rows, err := h.db.QueryContext(context.Background(),
		`SELECT type, summary, details FROM sensor_events WHERE sensor_id = $1 ORDER BY at`, s.id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var types []string
	var summary string
	var details []byte
	for rows.Next() {
		var typ, sum string
		var det []byte
		if err := rows.Scan(&typ, &sum, &det); err != nil {
			t.Fatal(err)
		}
		types = append(types, typ)
		if typ == string(sensor.EventManifestChanged) {
			summary, details = sum, det
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(types, []string{"manifest_changed"}) {
		t.Fatalf("events %v, want one manifest_changed", types)
	}
	if !strings.Contains(summary, "nuclei v3.11.1 → v3.12.0") {
		t.Fatalf("summary %q", summary)
	}
	var d struct {
		Diff           sensor.ManifestDiff `json:"diff"`
		ManifestDigest string              `json:"manifest_digest"`
		Previous       string              `json:"previous_manifest_digest"`
	}
	if err := json.Unmarshal(details, &d); err != nil {
		t.Fatal(err)
	}
	if d.ManifestDigest != second.ManifestDigest || d.Previous != first.ManifestDigest ||
		len(d.Diff.Capabilities) != 1 || !slices.Equal(d.Diff.Capabilities[0].Added, []string{"iac"}) {
		t.Fatalf("details %s", details)
	}
}

// A registering sensor's heartbeat that disagrees with the stored manifest
// (before it registers the new one) records no tools_changed: the
// manifest_changed of the registration says it once.
func TestSensorManifestPhase2_NoHeartbeatToolEventsForRegisteringSensors(t *testing.T) {
	h := newCtlHarness(t)
	h.sensors.SetEventRepository(postgres.NewSensorEventRepository(&postgres.DB{DB: h.db}), sensor.DefaultEventLimits())
	s := h.newLimitedSensor(h.tenantID, "no-dup", nil, nil, 5)
	ack := h.putManifest(s, phase2Manifest("v3.11.1", []string{"sast"}))
	h.heartbeatV2(s, map[string]any{"status": "running", "manifest_digest": ack.ManifestDigest,
		"tools": []any{map[string]any{"name": "nuclei", "version": "v3.12.0", "installed": true}}})
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sensor_events WHERE sensor_id = $1 AND type IN ('tools_changed', 'capacity_changed')`, s.id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d heartbeat tool events (%v), want 0", n, err)
	}
}
