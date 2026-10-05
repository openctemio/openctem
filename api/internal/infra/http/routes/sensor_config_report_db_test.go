package routes

// The sensor config report end to end (research/26): PUT
// /api/v2/sensor/config-report through the v2 route and handler, the stored
// row (sanitized, never a setting value), digest dedup, the heartbeat's
// config_report digest and send_config_report, and the management read
// GET /api/v1/sensors/{id}/config-report with tenant isolation.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

const configCanary = "CANARY-SECRET-7f3a"

func configReportBody(observedAt string) map[string]any {
	return map[string]any{
		"schema": 1, "observed_at": observedAt, "trigger": "start",
		"runtime": map[string]any{"kind": "docker"}, "config_health": "ok",
		"checks": []any{
			map[string]any{"id": "identity.state_persistent", "status": "warn", "severity": "warning", "code": "not_persistent",
				"params":  map[string]any{"path": map[string]any{"path": "/var/lib/openctem/state"}},
				"keys":    []string{"SENSOR_STATE_DIR"},
				"summary": "<script>alert(1)</script>\u202estate is not on a volume"},
			map[string]any{"id": "tool.nuclei.binary", "status": "pass", "code": "ok",
				"params": map[string]any{"tool": map[string]any{"name": "nuclei"}}},
			map[string]any{"id": "content.templates_signed", "status": "warn", "code": "newer", "summary": "from a newer sensor"},
		},
		"settings": []any{
			map[string]any{"name": "API_KEY", "set": true, "source": "env", "secret": true, "valid": true, "value": configCanary},
			map[string]any{"name": "SENSOR_CA_CERT_FILE", "set": false, "source": "unset", "secret": false, "valid": true},
		},
	}
}

func (h *ctlHarness) putConfigReport(s ctlSensor, body any) protov2.ConfigReportResponse {
	h.t.Helper()
	resp, raw := h.call(s.key, http.MethodPut, protov2.PathPrefix+protov2.ConfigReportPath, body)
	h.want(resp, raw, 200, "")
	return decodeAs[protov2.ConfigReportResponse](h.t, raw)
}

func (h *ctlHarness) configRow(s ctlSensor) (report, digest, health string, receivedAt time.Time) {
	h.t.Helper()
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT report::text, digest, health, received_at FROM sensor_config_reports WHERE sensor_id = $1`, s.id).
		Scan(&report, &digest, &health, &receivedAt); err != nil {
		h.t.Fatalf("config report row: %v", err)
	}
	return
}

func (h *ctlHarness) configPointers(s ctlSensor) (digest, health, heartbeat sql.NullString) {
	h.t.Helper()
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT config_report_digest, config_health, config_heartbeat_digest FROM sensors WHERE id = $1`, s.id).
		Scan(&digest, &health, &heartbeat); err != nil {
		h.t.Fatal(err)
	}
	return
}

func TestSensorConfigReport_StoreDedupAndHeartbeat_DB(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "config-report")

	resp, raw := h.call(s.key, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil)
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), `"`+protov2.FeatureConfigReport+`"`) {
		t.Fatalf("hello does not list config_report: %s", raw)
	}

	first := h.putConfigReport(s, configReportBody("2026-10-05T10:00:00Z"))
	if !first.Changed || !strings.HasPrefix(first.ConfigReportDigest, "sha256:") || len(first.ConfigReportDigest) != 71 {
		t.Fatalf("first answer %+v", first)
	}
	reasons := map[string]string{}
	for _, i := range first.Ignored {
		reasons[i.Path] = i.Reason
		if strings.Contains(i.Value, configCanary) {
			t.Fatalf("ignored echoes the canary: %+v", i)
		}
	}
	if reasons["settings[0].value"] != "unknown-member" {
		t.Fatalf("ignored %+v", first.Ignored)
	}

	report, digest, health, received := h.configRow(s)
	if strings.Contains(report, configCanary) || strings.Contains(report, `"value"`) {
		t.Fatalf("stored report keeps a setting value: %s", report)
	}
	if strings.Contains(report, "\u202e") || !strings.Contains(report, "alert(1)") {
		t.Fatalf("stored summary not reduced to plain text: %s", report)
	}
	// The platform's rollup (attention), not the sensor's claim (ok).
	if digest != first.ConfigReportDigest || health != "attention" {
		t.Fatalf("row digest %s health %s", digest, health)
	}
	if d, hl, hb := h.configPointers(s); d.String != digest || hl.String != "attention" || hb.String != digest {
		t.Fatalf("pointers %v %v %v", d, hl, hb)
	}

	// Same checks, run again later: same digest, only received_at moves.
	time.Sleep(10 * time.Millisecond)
	again := h.putConfigReport(s, configReportBody("2026-10-05T11:00:00Z"))
	if again.Changed || again.ConfigReportDigest != first.ConfigReportDigest {
		t.Fatalf("repeat answer %+v", again)
	}
	report2, _, _, received2 := h.configRow(s)
	if report2 != report || !received2.After(received) {
		t.Fatalf("dedup rewrote the report or kept received_at (%v -> %v)", received, received2)
	}

	// The heartbeat: the stored digest asks for nothing; another one asks
	// for the report; none stores none (the stored report is then stale).
	other := "sha256:" + strings.Repeat("e", 64)
	hb := func(cr any) []string {
		body := map[string]any{"status": "running"}
		if cr != nil {
			body["config_report"] = cr
		}
		return h.heartbeatActions(s, body)
	}
	if a := hb(map[string]any{"digest": digest, "health": "attention", "warn": 1}); slices.Contains(a, protov2.ActionSendConfigReport) {
		t.Fatalf("current digest asked for the report: %v", a)
	}
	if a := hb(map[string]any{"digest": other}); !slices.Contains(a, protov2.ActionSendConfigReport) {
		t.Fatalf("unknown digest did not ask for the report: %v", a)
	}
	if _, _, hbd := h.configPointers(s); hbd.String != other {
		t.Fatalf("heartbeat digest %v, want %s", hbd, other)
	}
	if a := hb(nil); slices.Contains(a, protov2.ActionSendConfigReport) {
		t.Fatalf("a heartbeat without config_report asked for it: %v", a)
	}
	if _, _, hbd := h.configPointers(s); hbd.Valid {
		t.Fatalf("heartbeat without config_report kept %v", hbd)
	}
	if a := hb(map[string]any{"digest": 42}); slices.Contains(a, protov2.ActionSendConfigReport) {
		t.Fatalf("a malformed summary asked for the report: %v", a)
	}
	if !h.load(s).ConfigReportStale() {
		t.Fatal("report not stale after heartbeats without its digest")
	}
	hb(map[string]any{"digest": digest})
	if got := h.load(s); got.ConfigReportStale() || got.ConfigHealth != "attention" {
		t.Fatalf("fresh again: stale=%v health=%q", got.ConfigReportStale(), got.ConfigHealth)
	}
}

func TestSensorConfigReport_RefusedBodies_DB(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "config-report-refused")
	path := protov2.PathPrefix + protov2.ConfigReportPath

	big := configReportBody("2026-10-05T10:00:00Z")
	big["padding"] = strings.Repeat("a", 65*1024)
	resp, raw := h.call(s.key, http.MethodPut, path, big)
	h.want(resp, raw, http.StatusRequestEntityTooLarge, ingestProblem("content-too-large"))
	if p := decodeAs[protov2.Problem](t, raw); p.Limit == nil || *p.Limit != protov2.MaxConfigReportBytes {
		t.Fatalf("413 limit %+v", p)
	}

	deep := []byte(`{"schema":1,"checks":[{"id":"a.b","status":"pass","params":{"x":{"names":[["too deep"]]}}}]}`)
	resp, raw = h.call(s.key, http.MethodPut, path, deep)
	h.want(resp, raw, http.StatusBadRequest, ingestProblem("invalid-request"))

	resp, raw = h.call(s.key, http.MethodPut, path, []byte(`{"schema":1,`))
	h.want(resp, raw, http.StatusBadRequest, ingestProblem("invalid-request"))

	resp, raw = h.call(s.key, http.MethodPut, path, map[string]any{"schema": 2, "checks": []any{}})
	h.want(resp, raw, http.StatusUnprocessableEntity, sensorProblem("config-report-invalid"))

	resp, raw = h.call(s.key, http.MethodPut, path, map[string]any{"schema": 1})
	h.want(resp, raw, http.StatusUnprocessableEntity, sensorProblem("config-report-invalid"))

	resp, raw = h.call(s.key, http.MethodPut, path, []byte(`{"schema":1,"checks":[]}`), "Content-Type", "text/plain")
	h.want(resp, raw, http.StatusUnsupportedMediaType, ingestProblem("unsupported-media-type"))

	// 500 checks: the first 200 are kept and the rest listed, one item.
	checks := make([]any, 500)
	for i := range checks {
		checks[i] = map[string]any{"id": "config.env_unknown", "status": "warn", "code": "unknown",
			"params": map[string]any{"name": map[string]any{"name": "SENSOR_X" + strings.Repeat("Y", i%40) + string(rune('A'+i%26))}}}
	}
	many := configReportBody("2026-10-05T10:00:00Z")
	many["checks"] = checks
	out := h.putConfigReport(s, many)
	limited := false
	for _, i := range out.Ignored {
		if i.Path == "checks[200:]" && i.Reason == "limit" && i.Value == "300" {
			limited = true
		}
	}
	if !limited {
		t.Fatalf("ignored %+v", out.Ignored)
	}

	// Nothing was stored by the refused bodies; no other row exists.
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM sensor_config_reports WHERE tenant_id = $1`, h.tenantID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d %v", n, err)
	}

	// Without a key: 401.
	resp, raw = h.call("", http.MethodPut, path, bytes.NewReader([]byte(`{}`)))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no key: %d %s", resp.StatusCode, raw)
	}
}

func TestSensorConfigReport_ManagementReadAndIsolation_DB(t *testing.T) {
	h := newCtlHarness(t)
	m := newActivityRouteHarness(t)

	s := h.newSensor(h.tenantID, "config-report-read")
	h.putConfigReport(s, configReportBody("2026-10-05T10:00:00Z"))
	viewer := m.member(h.tenantID, "viewer")

	var got handler.SensorConfigReportResponse
	body := m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s.id+"/config-report", "", http.StatusOK)
	if strings.Contains(body, configCanary) {
		t.Fatalf("read leaks a setting value: %s", body)
	}
	mustJSON(t, body, &got)
	if sb, _ := json.Marshal(got.Settings); strings.Contains(string(sb), "value") {
		t.Fatalf("settings carry a value member: %s", sb)
	}
	if got.State != "reported" || got.Stale || got.Health != "attention" || got.RuntimeKind != "docker" ||
		got.ObservedAt == nil || *got.ObservedAt != "2026-10-05T10:00:00Z" || got.ReceivedAt == nil {
		t.Fatalf("view %+v", got)
	}
	if got.Counts.Warn != 2 || got.Counts.Pass != 1 || len(got.Checks) != 3 || len(got.Settings) != 2 {
		t.Fatalf("counts %+v checks %d settings %+v", got.Counts, len(got.Checks), got.Settings)
	}
	// warn before pass; within warn, the identity group before content.
	if got.Checks[0].ID != "identity.state_persistent" || got.Checks[1].ID != "content.templates_signed" || got.Checks[2].Status != "pass" {
		t.Fatalf("order %s %s %s", got.Checks[0].ID, got.Checks[1].ID, got.Checks[2].ID)
	}
	state, unknown := got.Checks[0], got.Checks[1]
	if unknown.Known || unknown.Title != unknown.ID || unknown.Why != "" || len(unknown.Fix) != 0 || unknown.Summary != "from a newer sensor" {
		t.Fatalf("unknown check %+v", unknown)
	}
	if !state.Known || state.Group != "identity" || !strings.Contains(state.Why, "/var/lib/openctem/state") ||
		!strings.Contains(state.Fix["compose"], `"state:/var/lib/openctem/state"`) || state.Fix["helm"] == "" ||
		!strings.HasPrefix(state.DocsURL, "https://docs.openctem.io/") {
		t.Fatalf("state check %+v", state)
	}
	if len(state.Observed) != 1 || state.Observed[0].Label != "path" || state.Observed[0].Value != "/var/lib/openctem/state" {
		t.Fatalf("observed %+v", state.Observed)
	}
	if !strings.HasPrefix(state.Summary, "<script>") || strings.Contains(state.Summary, "\u202e") {
		t.Fatalf("summary %q", state.Summary)
	}

	// The sensor list and detail carry config_health.
	if b := m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s.id, "", http.StatusOK); !strings.Contains(b, `"config_health":"attention"`) {
		t.Fatalf("detail without config_health: %s", b)
	}

	// BOLA: another organization's administrator, an unknown id.
	outsider := m.member(m.tenant(), "admin")
	m.expect(outsider, http.MethodGet, "/api/v1/sensors/"+s.id+"/config-report", "", http.StatusNotFound)
	m.expect(viewer, http.MethodGet, "/api/v1/sensors/01a10b14-0000-7000-8000-000000000000/config-report", "", http.StatusNotFound)
	m.expect(viewer, http.MethodGet, "/api/v1/sensors/not-a-uuid/config-report", "", http.StatusBadRequest)

	// An older sensor that heartbeats without a report: a derived checklist.
	old := h.newSensor(h.tenantID, "config-report-derived")
	h.heartbeatActions(old, map[string]any{"status": "running", "tools": []any{
		map[string]any{"name": "semgrep", "installed": false}, map[string]any{"name": "nuclei", "installed": true}}})
	var derived handler.SensorConfigReportResponse
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+old.id+"/config-report", "", http.StatusOK), &derived)
	if derived.State != "derived" || derived.DerivedNote == "" || derived.Health != "impaired" || len(derived.Checks) == 0 ||
		derived.Checks[0].ID != "tool.semgrep.binary" || derived.Checks[0].Status != "fail" {
		t.Fatalf("derived %+v", derived)
	}
	if b := m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+old.id, "", http.StatusOK); !strings.Contains(b, `"config_health":null`) {
		t.Fatalf("derived sensor detail: config_health should be null: %s", b)
	}

	// Never connected: nothing.
	idle := h.newSensor(h.tenantID, "config-report-none")
	var none handler.SensorConfigReportResponse
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+idle.id+"/config-report", "", http.StatusOK), &none)
	if none.State != "none" || none.Health != "unknown" || len(none.Checks) != 0 || none.Checks == nil {
		t.Fatalf("none %+v", none)
	}
}
