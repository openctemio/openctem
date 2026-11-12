package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeRunEvents struct {
	tenant, run shared.ID
	events      []command.Event
}

func (f fakeRunEvents) ListForRun(_ context.Context, tenantID, runID shared.ID, _ int) ([]command.Event, bool, error) {
	if tenantID != f.tenant || runID != f.run {
		return nil, false, nil
	}
	return f.events, false, nil
}

func runEventsRequest(tenant shared.ID, run string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-runs/"+run+"/events", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", run)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
	return req.WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
}

// A platform job's events never name its sensor, and their text is masked
// like any other platform-sensor field; a tenant sensor is named. Another
// tenant's run is not found.
func TestListRunEvents(t *testing.T) {
	tenant, run, sensor := shared.NewID(), shared.NewID(), shared.NewID()
	at := time.Unix(100, 0)
	h := NewScanWorkflowHandler(nil, nil, logger.NewNop())
	h.SetRunReader(fakeRuns{tenant: tenant, run: run})
	h.SetRunEvents(fakeRunEvents{tenant: tenant, run: run, events: []command.Event{
		{ID: shared.NewID(), CommandID: shared.NewID(), Event: "claimed", SensorID: &sensor, CreatedAt: at},
		{ID: shared.NewID(), CommandID: shared.NewID(), Event: "failed", Platform: true, SensorID: &sensor,
			Message: "dial 10.20.0.7:443 from /opt/platform/bin/nuclei failed", CreatedAt: at},
	}})

	w := httptest.NewRecorder()
	h.ListRunEvents(w, runEventsRequest(tenant, run.String()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got RunEventsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 2 || got.Events[0].SensorID != sensor.String() {
		t.Fatalf("events = %+v", got.Events)
	}
	p := got.Events[1]
	if p.SensorID != "" || !p.Platform || strings.Contains(p.Message, "10.20.0.7") || strings.Contains(p.Message, "/opt/platform") {
		t.Fatalf("platform event leaks its sensor: %+v", p)
	}

	w = httptest.NewRecorder()
	h.ListRunEvents(w, runEventsRequest(shared.NewID(), run.String()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("another tenant: %d, want 404", w.Code)
	}
}
