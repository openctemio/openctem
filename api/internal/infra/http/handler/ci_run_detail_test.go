package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The run view carries what the console's run detail shows: whether the
// verdict passed only through warn or a break-glass, the override used, and
// where posting to the code host stands. Out of scope stays 404.
func TestCIRunResponseCarriesOutcomeAndDecoration(t *testing.T) {
	tenant := shared.NewID()
	failures := 1
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: shared.NewID(), Status: cirun.StatusEvaluated,
		Verdict: cirun.VerdictPass, ScanFailures: &failures, DecorationState: cirun.DecorationFailed,
		DecorationDetail: "could not post the check: GitHub answered 403",
		VerdictDetail: json.RawMessage(`{"verdict":"pass","would_fail":true,"reasons":[],
			"override":{"id":"o1","reason":"release hotfix","created_by":"admin@acme.test","expires_at":"2026-10-20T00:00:00Z"}}`)}
	h := NewCIAdminHandler(&fakeCIService{run: run}, nil, logger.NewNop())
	r := tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", run.ID.String())
	w := httptest.NewRecorder()
	h.GetRun(w, r)
	var got CIRunResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("get run: %d %s", w.Code, w.Body.String())
	}
	if !got.WouldFail || got.Override == nil || got.Override.Reason != "release hotfix" || got.Override.CreatedBy != "admin@acme.test" ||
		got.DecorationState != cirun.DecorationFailed || got.DecorationDetail == "" || got.ScanFailures == nil || *got.ScanFailures != 1 {
		t.Fatalf("response: %+v", got)
	}
	// The list view (no verdict detail) still says the pass would have failed.
	if v := toCIRunResponse(run, false); !v.WouldFail || v.VerdictDetail != nil {
		t.Fatalf("list view: %+v", v)
	}
	// A run without a verdict: no outcome, no decoration.
	if v := toCIRunResponse(&cirun.Run{ID: shared.NewID(), Status: cirun.StatusRunning}, true); v.WouldFail || v.Override != nil || v.DecorationState != "" {
		t.Fatalf("running run: %+v", v)
	}

	scoped := NewCIAdminHandler(&fakeCIService{run: run}, denyScope{}, logger.NewNop())
	r = tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", run.ID.String())
	w = httptest.NewRecorder()
	scoped.GetRun(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("out of scope: %d", w.Code)
	}
}
