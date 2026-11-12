package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCoverageService struct {
	CICoverageService
	expected, retired bool
	lastScope         *shared.DataScope
}

func (f *fakeCoverageService) Coverage(_ context.Context, _ shared.ID, in cirunapp.CoverageInput) (*cirunapp.CoverageOutput, error) {
	f.lastScope = in.DataScope
	return &cirunapp.CoverageOutput{}, nil
}

func (f *fakeCoverageService) SetExpectation(_ context.Context, _, id shared.ID, _ []string, _ cirunapp.Actor) (*cirun.Expectation, error) {
	f.expected = true
	return &cirun.Expectation{RepositoryAssetID: id}, nil
}

func (f *fakeCoverageService) RetirePipeline(context.Context, shared.ID, shared.ID, string, cirunapp.Actor) (*cirun.Pipeline, []shared.ID, error) {
	f.retired = true
	return &cirun.Pipeline{}, nil, nil
}

type scopeOnly struct{ scope *shared.DataScope }

func (s scopeOnly) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return s.scope, nil
}
func (scopeOnly) AssertAsset(context.Context, shared.ID, shared.ID) error {
	return cirun.ErrRepositoryNotFound
}

// Marking a repository or retiring a pipeline outside the caller's data
// scope is a 404 and never reaches the service; the coverage listing passes
// the caller's scope down; bad filters are 400.
func TestCICoverageHandlerIsolation(t *testing.T) {
	tenant := shared.NewID()
	p := cirun.Pipeline{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: shared.NewID()}
	pipes := &fakePipelineService{view: cirunapp.PipelineView{Pipeline: p, Assessment: p.Assess(time.Now(), cirun.StatusPolicy{})}}
	scope := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}

	cov := &fakeCoverageService{}
	h := NewCIAdminHandler(&fakeCIService{}, scopeOnly{scope: scope}, logger.NewNop())
	h.SetPipelineService(pipes)
	h.SetCoverageService(cov)

	r := tenantRequest(http.MethodPut, "/", `{"capabilities":["sast"]}`, tenant)
	r.SetPathValue("id", shared.NewID().String())
	w := httptest.NewRecorder()
	h.SetCoverageExpectation(w, r)
	if w.Code != http.StatusNotFound || cov.expected {
		t.Fatalf("out-of-scope expectation: %d (service called: %v)", w.Code, cov.expected)
	}

	r = tenantRequest(http.MethodPost, "/", `{"reason":"workflow deleted long ago"}`, tenant)
	r.SetPathValue("id", p.ID.String())
	w = httptest.NewRecorder()
	h.RetirePipeline(w, r)
	if w.Code != http.StatusNotFound || cov.retired {
		t.Fatalf("out-of-scope retire: %d (service called: %v)", w.Code, cov.retired)
	}
	// Another tenant's pipeline id: 404 too.
	r = tenantRequest(http.MethodPost, "/", `{"reason":"workflow deleted long ago"}`, shared.NewID())
	r.SetPathValue("id", p.ID.String())
	w = httptest.NewRecorder()
	h.RetirePipeline(w, r)
	if w.Code != http.StatusNotFound || cov.retired {
		t.Fatalf("cross-tenant retire: %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.GetCoverage(w, tenantRequest(http.MethodGet, "/api/v1/ci/coverage", "", tenant))
	if w.Code != http.StatusOK || cov.lastScope != scope {
		t.Fatalf("coverage: %d, scope passed: %v", w.Code, cov.lastScope == scope)
	}
	for _, q := range []string{"?filter=all", "?capability=dast", "?state=old"} {
		w = httptest.NewRecorder()
		h.GetCoverage(w, tenantRequest(http.MethodGet, "/api/v1/ci/coverage"+q, "", tenant))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", q, w.Code)
		}
	}

	// In scope (no enforcer): the service is reached.
	open := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	open.SetPipelineService(pipes)
	open.SetCoverageService(cov)
	r = tenantRequest(http.MethodPost, "/", `{"reason":"workflow deleted long ago"}`, tenant)
	r.SetPathValue("id", p.ID.String())
	w = httptest.NewRecorder()
	open.RetirePipeline(w, r)
	if w.Code != http.StatusOK || !cov.retired {
		t.Fatalf("in-scope retire: %d", w.Code)
	}
}
