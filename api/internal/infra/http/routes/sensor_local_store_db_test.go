package routes

// The local store report end to end: hello lists "local_store", a heartbeat's
// report is stored sanitized, and the management detail and list show it
// (with the stopped_claiming health reason) to the sensor's own
// organization only.

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestSensorLocalStore_HeartbeatToDetail_DB(t *testing.T) {
	h := newCtlHarness(t)
	m := newActivityRouteHarness(t)

	s := h.newSensor(h.tenantID, "local-store")
	resp, raw := h.call(s.key, http.MethodGet, protov2.PathPrefix+protov2.HelloPath, nil)
	h.want(resp, raw, 200, "")
	if !strings.Contains(string(raw), `"`+protov2.FeatureLocalStore+`"`) {
		t.Fatalf("hello does not list local_store: %s", raw)
	}

	// Hostile values: a reason with a line break and a bidi override, an
	// unknown class, a negative size, a level outside the set.
	h.heartbeatActions(s, map[string]any{"status": "running", "local_store": map[string]any{
		"level": "high", "stop_claiming": true, "disk_level": "low",
		"reason":         "9 % of the volume free\n\u202ebelow 10 %",
		"bytes_by_class": map[string]any{"outbox": 2048, "workspace": -1, "private_keys": 1},
		"total_bytes":    2048, "quota_bytes": 1 << 30, "sweeps": 4,
	}})

	viewer := m.member(h.tenantID, "viewer")
	var d handler.SensorResponse
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s.id, "", http.StatusOK), &d)
	ls := d.LocalStore
	if ls == nil {
		t.Fatal("detail has no local_store")
	}
	if !ls.StopClaiming || ls.Level != "high" || ls.DiskLevel != "low" || ls.TotalBytes != 2048 || ls.ReportedAt == nil {
		t.Fatalf("local_store %+v", ls)
	}
	if strings.ContainsAny(ls.Reason, "\n\u202e") || !strings.HasPrefix(ls.Reason, "9 % of the volume free") {
		t.Fatalf("reason not sanitized: %q", ls.Reason)
	}
	if _, ok := ls.BytesByClass["private_keys"]; ok || ls.BytesByClass["workspace"] != 0 {
		t.Fatalf("classes %+v", ls.BytesByClass)
	}
	if d.AuthKind != "bearer" {
		t.Fatalf("auth_kind %q", d.AuthKind)
	}
	hasReason := func(r handler.SensorResponse) bool {
		return slices.ContainsFunc(r.HealthReasons, func(x handler.SensorHealthReasonResponse) bool {
			return x.Code == "stopped_claiming"
		})
	}
	if !hasReason(d) || d.State != "degraded" {
		t.Fatalf("state %s reasons %+v", d.State, d.HealthReasons)
	}

	// A heartbeat without the member keeps the report.
	h.heartbeatActions(s, map[string]any{"status": "running"})
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors/"+s.id, "", http.StatusOK), &d)
	if d.LocalStore == nil || !d.LocalStore.StopClaiming {
		t.Fatalf("report lost on a heartbeat without one: %+v", d.LocalStore)
	}

	// Recovered: the reason goes away.
	h.heartbeatActions(s, map[string]any{"status": "running", "local_store": map[string]any{
		"level": "ok", "stop_claiming": false, "disk_level": "ok", "total_bytes": 10}})
	var list struct {
		Items []handler.SensorResponse `json:"items"`
	}
	mustJSON(t, m.expect(viewer, http.MethodGet, "/api/v1/sensors?per_page=100", "", http.StatusOK), &list)
	i := slices.IndexFunc(list.Items, func(r handler.SensorResponse) bool { return r.ID == s.id })
	if i < 0 || list.Items[i].LocalStore == nil || list.Items[i].LocalStore.StopClaiming || hasReason(list.Items[i]) {
		t.Fatalf("list after recovery: %+v", list.Items[i].LocalStore)
	}

	// Another organization sees nothing of it.
	outsider := m.member(m.tenant(), "admin")
	m.expect(outsider, http.MethodGet, "/api/v1/sensors/"+s.id, "", http.StatusNotFound)
	if b := m.expect(outsider, http.MethodGet, "/api/v1/sensors?per_page=100", "", http.StatusOK); strings.Contains(b, s.id) {
		t.Fatal("another organization lists the sensor")
	}
}
