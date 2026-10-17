package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakePipelineService serves one pipeline of one tenant on one asset.
type fakePipelineService struct {
	CIPipelineService
	view cirunapp.PipelineView
}

func (f *fakePipelineService) GetPipeline(_ context.Context, tenantID, id shared.ID) (*cirunapp.PipelineView, error) {
	if f.view.TenantID != tenantID || f.view.ID != id {
		return nil, cirun.ErrPipelineNotFound
	}
	v := f.view
	return &v, nil
}

func (f *fakePipelineService) PipelineBranches(context.Context, shared.ID, shared.ID) ([]cirun.PipelineBranch, error) {
	return nil, nil
}

func (f *fakePipelineService) PipelineGateTrend(context.Context, shared.ID, shared.ID, int) ([]cirun.GatePoint, error) {
	return nil, nil
}

type denyAllScope struct{}

func (denyAllScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) { return nil, nil }
func (denyAllScope) AssertAsset(context.Context, shared.ID, shared.ID) error {
	return errors.New("out of scope")
}

// A pipeline of another tenant, or on a repository outside the caller's
// data scope, is not found.
func TestCIPipelineGetIsolation(t *testing.T) {
	tenant := shared.NewID()
	p := cirun.Pipeline{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: shared.NewID(), Provider: cirun.ProviderGitHub,
		RepositoryName: "github.com/acme/api", WorkflowPath: ".github/workflows/scan.yml"}
	svc := &fakePipelineService{view: cirunapp.PipelineView{Pipeline: p, Assessment: p.Assess(time.Now(), cirun.StatusPolicy{})}}
	get := func(h *CIAdminHandler, tid shared.ID) int {
		r := tenantRequest(http.MethodGet, "/api/v1/ci/pipelines/"+p.ID.String(), "", tid)
		r.SetPathValue("id", p.ID.String())
		w := httptest.NewRecorder()
		h.GetPipeline(w, r)
		return w.Code
	}
	h := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	h.SetPipelineService(svc)
	if code := get(h, tenant); code != http.StatusOK {
		t.Fatalf("own pipeline: %d", code)
	}
	if code := get(h, shared.NewID()); code != http.StatusNotFound {
		t.Fatalf("another tenant: %d", code)
	}
	scoped := NewCIAdminHandler(&fakeCIService{}, denyAllScope{}, logger.NewNop())
	scoped.SetPipelineService(svc)
	if code := get(scoped, tenant); code != http.StatusNotFound {
		t.Fatalf("out of data scope: %d", code)
	}
}

func TestTruncateQuery(t *testing.T) {
	if got := truncateQuery("  repo  ", 255); got != "repo" {
		t.Fatalf("trim = %q", got)
	}
	if got := truncateQuery("abcdef", 3); got != "abc" {
		t.Fatalf("cap = %q", got)
	}
	// A cut inside a multi-byte rune drops the partial rune.
	if got := truncateQuery("aé", 2); got != "a" {
		t.Fatalf("rune-safe = %q", got)
	}
}
