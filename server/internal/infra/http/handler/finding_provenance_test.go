package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeProvenance struct {
	runCalls int
	tenant   shared.ID
}

func (f *fakeProvenance) ListFindingBranches(_ context.Context, tenantID, _ shared.ID, _ int) ([]vulnerability.BranchSighting, error) {
	f.tenant = tenantID
	now := time.Now().UTC()
	return []vulnerability.BranchSighting{
		{Name: "main", IsDefault: true, Status: "open", FirstSeenAt: now.Add(-time.Hour), LastSeenAt: now, FirstCommit: "67da69d", LastCommit: "0dacaf6"},
		{Name: "feat/bump-requests", Status: "open", FirstSeenAt: now, LastSeenAt: now, FirstCommit: "a481d52", LastCommit: "a481d52"},
	}, nil
}

func (f *fakeProvenance) ListFindingRuns(_ context.Context, _ shared.ID, _ string, _ int) ([]vulnerability.RunSighting, *vulnerability.RunSighting, error) {
	f.runCalls++
	r := vulnerability.RunSighting{ID: "r1", Provider: "gitlab", ExternalRunID: "2101", PipelineURL: "javascript:alert(1)", Branch: "main", CommitSHA: "67da69d", PullRequest: "12"}
	ok := r
	ok.PipelineURL = "https://gitlab.com/acme/app/-/pipelines/2101"
	return []vulnerability.RunSighting{r, ok}, &ok, nil
}

func provenanceDetail(t *testing.T, h *VulnerabilityHandler, tenant, id string, perms []string) FindingResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+id, nil)
	req.SetPathValue("id", id)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
	rr := httptest.NewRecorder()
	h.GetFinding(rr, req.WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp FindingResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// Branches are finding data; CI runs are CI data and need scans:ci:read.
// A run's URL is kept only when it is http(s).
func TestGetFinding_ProvenanceBranchesAndRunsByPermission(t *testing.T) {
	tenant := shared.NewID()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint("fp-1")
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	prov := &fakeProvenance{}
	h.SetProvenanceLister(prov)

	resp := provenanceDetail(t, h, tenant.String(), f.ID().String(), []string{permission.FindingsRead.String()})
	if resp.Provenance == nil || len(resp.Provenance.Branches) != 2 || resp.Provenance.Branches[0].LastCommit != "0dacaf6" {
		t.Fatalf("branches = %+v", resp.Provenance)
	}
	if len(resp.Provenance.Runs) != 0 || resp.Provenance.FirstRun != nil || prov.runCalls != 0 {
		t.Fatalf("runs must not be read without scans:ci:read: %+v calls=%d", resp.Provenance, prov.runCalls)
	}
	if prov.tenant != tenant {
		t.Fatal("branches must be read for the caller's tenant")
	}

	resp = provenanceDetail(t, h, tenant.String(), f.ID().String(), []string{permission.FindingsRead.String(), permission.CIRead.String()})
	p := resp.Provenance
	if len(p.Runs) != 2 || p.FirstRun == nil || p.FirstRun.PullRequest != "12" {
		t.Fatalf("runs = %+v", p)
	}
	if p.Runs[0].PipelineURL != "" || p.Runs[1].PipelineURL != "https://gitlab.com/acme/app/-/pipelines/2101" {
		t.Errorf("pipeline URLs must be http(s) only: %q, %q", p.Runs[0].PipelineURL, p.Runs[1].PipelineURL)
	}
}
