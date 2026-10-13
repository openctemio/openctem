package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakePlacement struct {
	tenant, run, task shared.ID
	p                 *commandapp.Placement
}

func (f *fakePlacement) ExplainRunTaskPlacement(_ context.Context, tenantID, runID, commandID shared.ID) (*commandapp.Placement, error) {
	if tenantID != f.tenant || runID != f.run || commandID != f.task {
		return nil, shared.ErrNotFound
	}
	return f.p, nil
}

func placementRequest(tenant shared.ID, run, task string, perms ...string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-runs/"+run+"/tasks/"+task+"/placement", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", run)
	rc.URLParams.Add("task_id", task)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
	ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, append([]string{"scans:read"}, perms...))
	return req.WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
}

func newPlacementHandler(t *testing.T) (*ScanWorkflowHandler, *fakePlacement) {
	t.Helper()
	sensorID := shared.NewID()
	f := &fakePlacement{tenant: shared.NewID(), run: shared.NewID(), task: shared.NewID(), p: &commandapp.Placement{
		Status:   commanddom.CommandStatusPending,
		Eligible: 0,
		Sensors: []commandapp.SensorPlacement{{SensorID: sensorID, Name: "dmz-sensor-1",
			Reasons: []string{commanddom.PlacementToolMissing}}},
		Blocking: []commandapp.ReasonCount{{Code: commanddom.PlacementToolMissing, Count: 1}},
	}}
	h := NewScanWorkflowHandler(nil, nil, logger.NewNop())
	h.SetPlacement(f)
	h.SetRunReader(fakeRuns{tenant: f.tenant, run: f.run})
	return h, f
}

func decodePlacement(t *testing.T, w *httptest.ResponseRecorder) RunTaskPlacementResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got RunTaskPlacementResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// The counts and codes go to any reader of the run; the sensors' names
// and verdicts only to a caller who can read sensors.
func TestGetRunTaskPlacement_SensorsOnlyWithSensorsRead(t *testing.T) {
	h, f := newPlacementHandler(t)

	w := httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String()))
	got := decodePlacement(t, w)
	if !got.Queued || got.Evaluated != 1 || len(got.Blocking) != 1 || got.Blocking[0].Code != commanddom.PlacementToolMissing {
		t.Fatalf("response %+v", got)
	}
	if len(got.Sensors) != 0 || strings.Contains(w.Body.String(), "dmz-sensor-1") {
		t.Fatalf("a caller without sensors:read got sensor details: %s", w.Body)
	}

	w = httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String(), "sensors:read"))
	got = decodePlacement(t, w)
	if len(got.Sensors) != 1 || got.Sensors[0].Name != "dmz-sensor-1" || got.Sensors[0].Reasons[0] != commanddom.PlacementToolMissing {
		t.Fatalf("sensors:read caller: %+v", got.Sensors)
	}
}

// Platform scanning is never broken down into sensors, and a task that no
// longer waits carries nothing but queued=false.
func TestGetRunTaskPlacement_PlatformAndSettled(t *testing.T) {
	h, f := newPlacementHandler(t)
	f.p.Platform = true
	w := httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String(), "sensors:read"))
	got := decodePlacement(t, w)
	if !got.Platform || len(got.Sensors) != 0 || got.Evaluated != 0 || len(got.Blocking) != 0 {
		t.Fatalf("platform task: %+v", got)
	}

	f.p.Platform, f.p.Status = false, commanddom.CommandStatusRunning
	w = httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String(), "sensors:read"))
	got = decodePlacement(t, w)
	if got.Queued || len(got.Sensors) != 0 || len(got.Blocking) != 0 {
		t.Fatalf("running task: %+v", got)
	}
}

func TestGetRunTaskPlacement_NotFoundAcrossTenantsAndRuns(t *testing.T) {
	h, f := newPlacementHandler(t)
	for name, req := range map[string]*http.Request{
		"other tenant": placementRequest(shared.NewID(), f.run.String(), f.task.String(), "sensors:read"),
		"other run":    placementRequest(f.tenant, shared.NewID().String(), f.task.String(), "sensors:read"),
		"other task":   placementRequest(f.tenant, f.run.String(), shared.NewID().String(), "sensors:read"),
	} {
		w := httptest.NewRecorder()
		h.GetRunTaskPlacement(w, req)
		if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "dmz-sensor-1") {
			t.Errorf("%s: status %d body %s", name, w.Code, w.Body)
		}
	}
	w := httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), "nope"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed task id: status %d", w.Code)
	}
}
