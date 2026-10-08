package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeTaskLogs struct {
	tenant, run, task shared.ID
	page              commandlog.Page
}

func (f *fakeTaskLogs) ListForRunTask(_ context.Context, tenantID, runID, commandID shared.ID) (commandlog.Page, error) {
	if tenantID != f.tenant || runID != f.run || commandID != f.task {
		return commandlog.Page{}, commandlog.ErrNotFound
	}
	return f.page, nil
}

// fakeRuns knows one run per tenant (a scan run: no extra access check).
type fakeRuns struct{ tenant, run shared.ID }

func (f fakeRuns) GetRun(_ context.Context, tenantID, runID string) (*scanrundom.Run, error) {
	if tenantID != f.tenant.String() || runID != f.run.String() {
		return nil, shared.ErrNotFound
	}
	return &scanrundom.Run{ID: f.run, TenantID: f.tenant, Kind: scanrundom.RunKindScan}, nil
}

func taskLogsRequest(tenant shared.ID, run, task string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-runs/"+run+"/tasks/"+task+"/logs", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", run)
	rc.URLParams.Add("task_id", task)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
	return req.WithContext(context.WithValue(ctx, middleware.TenantIDKey, tenant.String()))
}

func TestGetRunTaskLogs(t *testing.T) {
	f := &fakeTaskLogs{tenant: shared.NewID(), run: shared.NewID(), task: shared.NewID(),
		page: commandlog.Page{Truncated: true, Lines: []commandlog.Line{{TS: time.Unix(10, 0).UTC(), Level: "warn", Msg: "<b>x</b>", Source: "nuclei"}}}}
	h := NewScanWorkflowHandler(nil, nil, logger.NewNop())
	h.SetTaskLogs(f)
	h.SetRunReader(fakeRuns{tenant: f.tenant, run: f.run})

	w := httptest.NewRecorder()
	h.GetRunTaskLogs(w, taskLogsRequest(f.tenant, f.run.String(), f.task.String()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got RunTaskLogsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(got.Lines) != 1 || got.Lines[0].Msg != "<b>x</b>" || got.Lines[0].Level != "warn" {
		t.Fatalf("response %+v", got)
	}

	// Another tenant, another run, an unknown task: 404 alike.
	for name, req := range map[string]*http.Request{
		"other tenant": taskLogsRequest(shared.NewID(), f.run.String(), f.task.String()),
		"other run":    taskLogsRequest(f.tenant, shared.NewID().String(), f.task.String()),
		"other task":   taskLogsRequest(f.tenant, f.run.String(), shared.NewID().String()),
	} {
		w := httptest.NewRecorder()
		h.GetRunTaskLogs(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.GetRunTaskLogs(w, taskLogsRequest(f.tenant, "nope", f.task.String()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed run id: status %d", w.Code)
	}
}
