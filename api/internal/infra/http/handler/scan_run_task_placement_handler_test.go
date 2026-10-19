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
	hw                *commandapp.HostWait
}

func (f *fakePlacement) RunTaskHostWait(_ context.Context, tenantID, runID, commandID shared.ID) (*commandapp.HostWait, error) {
	if tenantID != f.tenant || runID != f.run || commandID != f.task {
		return nil, shared.ErrNotFound
	}
	return f.hw, nil
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

// A task waiting for its hosts says how many and which tasks hold them: a
// holder's task, run and step only when the caller can read that run; the
// tool always; never host names.
func TestGetRunTaskPlacement_HostWait(t *testing.T) {
	h, f := newPlacementHandler(t)
	sameRun, otherRun := shared.NewID(), shared.NewID()
	f.p.JobReasons = []string{commanddom.PlacementHostBusy}
	f.p.HostWait = &commandapp.HostWait{Held: 10, Total: 10, Holders: []commanddom.HostHolder{
		{CommandID: sameRun, RunID: f.run.String(), StepKey: "http", Tool: "httpx", Keys: []string{"secret-host.example.com"}},
		{CommandID: otherRun, RunID: shared.NewID().String(), StepKey: "ports", Tool: "naabu"},
	}}
	w := httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String()))
	got := decodePlacement(t, w)
	hw := got.HostWait
	if hw == nil || hw.HostsHeld != 10 || hw.HostsTotal != 10 || len(hw.Holders) != 2 {
		t.Fatalf("host wait %+v", hw)
	}
	if hw.Holders[0] != (RunTaskHostHolder{TaskID: sameRun.String(), RunID: f.run.String(), StepKey: "http", Tool: "httpx"}) {
		t.Fatalf("visible holder %+v", hw.Holders[0])
	}
	if hw.Holders[1] != (RunTaskHostHolder{Tool: "naabu"}) {
		t.Fatalf("a holder in a run the caller cannot read was named: %+v", hw.Holders[1])
	}
	if strings.Contains(w.Body.String(), "secret-host") {
		t.Fatalf("host names in the response: %s", w.Body)
	}
}

// The run's task list says, on each task waiting for its hosts, how many
// hosts are held, by which task (named only when the caller can read its
// run), and how many targets can start; never a host name, and nothing
// for a task that is not the run's or does not wait.
func TestRunTaskList_HostWait(t *testing.T) {
	h, f := newPlacementHandler(t)
	holder := shared.NewID()
	f.hw = &commandapp.HostWait{Held: 1, Total: 20, Targets: 23, CanStart: 21, Holders: []commanddom.HostHolder{
		{CommandID: holder, RunID: f.run.String(), StepKey: "templates", Tool: "nuclei", Keys: []string{"203.0.113.3"}},
	}}
	tasks := []RunTaskResponse{
		{ID: f.task.String(), WaitingOnHosts: true},
		{ID: shared.NewID().String(), WaitingOnHosts: true}, // not found for this run
		{ID: shared.NewID().String()},
	}
	ctx := placementRequest(f.tenant, f.run.String(), f.task.String()).Context()
	h.withHostWaits(ctx, f.tenant.String(), f.run.String(), tasks)
	hw := tasks[0].HostWait
	if hw == nil || hw.HostsHeld != 1 || hw.HostsTotal != 20 || hw.Targets != 23 || hw.CanStart != 21 || len(hw.Holders) != 1 ||
		hw.Holders[0] != (RunTaskHostHolder{TaskID: holder.String(), RunID: f.run.String(), StepKey: "templates", Tool: "nuclei"}) {
		t.Fatalf("host wait %+v", hw)
	}
	if tasks[1].HostWait != nil || tasks[2].HostWait != nil {
		t.Fatalf("host wait on a task that is not the run's or not waiting: %+v %+v", tasks[1].HostWait, tasks[2].HostWait)
	}
	b, _ := json.Marshal(tasks)
	if strings.Contains(string(b), "203.0.113.3") {
		t.Fatalf("a host name in the list: %s", b)
	}
}

// research/191 W-1: the answer says whether the shared fleet was an option
// when no sensor of the organization may take the task.
func TestGetRunTaskPlacement_SharedFleet(t *testing.T) {
	h, f := newPlacementHandler(t)
	f.p.SharedFleet, f.p.SharedFleetReason = commandapp.SharedFleetNotAllowed, "opted out"
	w := httptest.NewRecorder()
	h.GetRunTaskPlacement(w, placementRequest(f.tenant, f.run.String(), f.task.String()))
	got := decodePlacement(t, w)
	if got.SharedFleet != "not_allowed" || got.SharedFleetReason != "opted out" {
		t.Fatalf("shared fleet %q reason %q", got.SharedFleet, got.SharedFleetReason)
	}
}
