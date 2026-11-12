package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The workflow list answers readiness for the caller's organization only
// when asked (?include=readiness), for every listed workflow in one call.
func TestScanWorkflowList_IncludeReadiness(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "wf-readiness")
	id, _ := p.create()
	calls := 0
	var seenTenant shared.ID
	p.h.SetReadiness(func(_ context.Context, tenant shared.ID, wfs []*scanworkflow.Workflow) (map[shared.ID]*scanapp.WorkflowReadiness, error) {
		calls++
		seenTenant = tenant
		out := map[shared.ID]*scanapp.WorkflowReadiness{}
		for _, w := range wfs {
			out[w.ID] = &scanapp.WorkflowReadiness{State: scanapp.ReadinessBlocked, Steps: []scanapp.StepReadiness{
				{StepKey: "discover", Name: "Discover", State: scanapp.ReadinessBlocked, Reason: "No sensor offers Subdomain discovery", Fix: "Add a sensor with subfinder"},
			}}
		}
		return out, nil
	})

	list := func(query string) map[string]json.RawMessage {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scan-workflows/"+query, nil)
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chi.NewRouteContext())
		ctx = context.WithValue(ctx, middleware.TenantIDKey, p.tenant.String())
		rec := httptest.NewRecorder()
		p.h.ListTemplates(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Data []map[string]json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		for _, w := range out.Data {
			if string(w["id"]) == `"`+id+`"` {
				return w
			}
		}
		t.Fatalf("workflow %s not listed: %s", id, rec.Body.String())
		return nil
	}

	if _, ok := list("")["readiness"]; ok || calls != 0 {
		t.Fatal("readiness computed without ?include=readiness")
	}
	got := list("?include=readiness")
	if calls != 1 || seenTenant != p.tenant {
		t.Fatalf("readiness calls=%d tenant=%s, want one call for the caller's tenant", calls, seenTenant)
	}
	var r struct {
		State string `json:"state"`
		Steps []struct {
			Fix string `json:"fix"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(got["readiness"], &r); err != nil || r.State != "blocked" || len(r.Steps) != 1 || r.Steps[0].Fix == "" {
		t.Fatalf("readiness: %s", got["readiness"])
	}
}
