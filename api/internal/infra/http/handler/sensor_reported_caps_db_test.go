package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// TestSensorReportedCaps_Response: a heartbeat carrying a capability report
// is answered normally, and GET /sensors/{id} shows the administrator's settings, the
// report, the effective values and the mismatch hints. The harness sensor
// is declared with tools [semgrep], capabilities [sast].
func TestSensorReportedCaps_Response(t *testing.T) {
	h := newSensorHarness(t)
	sh := NewSensorHandler(
		sensor.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop()),
		validator.New(), logger.NewNop())
	get := func() map[string]json.RawMessage {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+h.sensorID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", h.sensorID)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, h.tenantID)
		rec := httptest.NewRecorder()
		sh.Get(rec, req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx)))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET sensor: %d %s", rec.Code, rec.Body.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// Before any report: reported is null, no tools (only a report names
	// them), the declared capabilities, no hints.
	before := get()
	if string(before["reported"]) != "null" || string(before["effective"]) != `{"tools":[],"capabilities":["sast"],"max_concurrent_jobs":5}` {
		t.Fatalf("before: reported=%s effective=%s", before["reported"], before["effective"])
	}
	if _, ok := before["capability_mismatch"]; ok {
		t.Fatalf("mismatch without a report: %s", before["capability_mismatch"])
	}

	h.heartbeat(map[string]any{
		"status": "running",
		"tools": []map[string]any{
			{"name": "semgrep", "version": "1.90.0", "installed": false},
			{"name": "nuclei", "version": "3.3.0", "installed": true},
		},
		"capabilities": []string{"nuclei", "sast"}, "max_concurrent_jobs": 2, "os": "linux", "arch": "arm64",
	})

	after := get()
	var rep SensorReportedResponse
	if err := json.Unmarshal(after["reported"], &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Tools) != 2 || rep.Tools[1].Name != "nuclei" || rep.Tools[1].Version != "3.3.0" || !rep.Tools[1].Installed ||
		rep.MaxConcurrentJobs == nil || *rep.MaxConcurrentJobs != 2 || rep.OS != "linux" || rep.Arch != "arm64" || rep.ReportedAt == nil {
		t.Fatalf("reported = %s", after["reported"])
	}
	// nuclei is the one installed tool; semgrep is reported not installed.
	// sast is both declared and reported.
	if got := string(after["effective"]); got != `{"tools":["nuclei"],"capabilities":["sast"],"max_concurrent_jobs":2}` {
		t.Fatalf("effective = %s", got)
	}
	if _, ok := after["capability_mismatch"]; ok {
		t.Fatalf("capability_mismatch = %s, want none", after["capability_mismatch"])
	}
	// The administrator's settings are unchanged, and there is no declared
	// tool list in the response any more.
	if _, ok := after["tools"]; ok || string(after["max_concurrent_jobs"]) != "5" {
		t.Fatalf("declared values: tools=%s max=%s", after["tools"], after["max_concurrent_jobs"])
	}
}
