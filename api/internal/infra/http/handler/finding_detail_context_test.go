package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The single-finding response embeds the CVE record and the affected package
// so the detail page can say "upgrade cross-spawn 7.0.3 → 7.0.5" and show the
// exploit signals without more requests. These tests pin that contract and
// its tenant scoping.

// detailFindingRepo serves one finding, only to its own tenant. Embedding the
// interface keeps the fake small: any other method panics if called.
type detailFindingRepo struct {
	vulnerability.FindingRepository
	f *vulnerability.Finding
}

func (r *detailFindingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	if r.f == nil || r.f.ID() != id || r.f.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return r.f, nil
}

type detailVulnRepo struct {
	vulnerability.VulnerabilityRepository
	v *vulnerability.Vulnerability
}

func (r *detailVulnRepo) GetByID(_ context.Context, id shared.ID) (*vulnerability.Vulnerability, error) {
	if r.v == nil || r.v.ID() != id {
		return nil, shared.ErrNotFound
	}
	return r.v, nil
}

// detailComponents is the FindingComponentLookup fake; it records the tenant
// it was asked about so the test can check the dependency lookup is scoped.
type detailComponents struct {
	c          *component.Component
	dep        *component.AssetDependency
	depErr     error
	gotTenant  string
	gotAsset   string
	depLookups int
}

func (d *detailComponents) GetComponent(_ context.Context, id string) (*component.Component, error) {
	if d.c == nil || d.c.ID().String() != id {
		return nil, shared.ErrNotFound
	}
	return d.c, nil
}

func (d *detailComponents) GetAssetDependency(_ context.Context, tenantID, assetID, _ string) (*component.AssetDependency, error) {
	d.depLookups++
	d.gotTenant, d.gotAsset = tenantID, assetID
	return d.dep, d.depErr
}

type detailFixture struct {
	tenant  shared.ID
	asset   shared.ID
	finding *vulnerability.Finding
	vuln    *vulnerability.Vulnerability
	comp    *component.Component
}

func newDetailFixture(t *testing.T) detailFixture {
	t.Helper()
	tenant, asset := shared.NewID(), shared.NewID()

	v, err := vulnerability.NewVulnerability("CVE-2024-21538", "cross-spawn ReDoS", vulnerability.SeverityHigh)
	if err != nil {
		t.Fatal(err)
	}
	v.UpdateDescription("Regular expression denial of service in cross-spawn.")
	v.UpdateCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
	v.UpdateEPSS(0.00868, 57.276)
	v.SetFixedVersions([]string{"7.0.5", "6.0.6"})

	c, err := component.NewComponent("cross-spawn", "7.0.3", component.EcosystemNPM)
	if err != nil {
		t.Fatal(err)
	}

	f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSCA, "npm-audit",
		vulnerability.SeverityHigh, "cross-spawn ReDoS vulnerability")
	if err != nil {
		t.Fatal(err)
	}
	f.SetVulnerabilityID(v.ID())
	f.SetComponentID(c.ID())
	return detailFixture{tenant: tenant, asset: asset, finding: f, vuln: v, comp: c}
}

func getFindingDetail(t *testing.T, h *VulnerabilityHandler, tenant, id string) (*httptest.ResponseRecorder, FindingResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+id, nil)
	req.SetPathValue("id", id)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	rr := httptest.NewRecorder()
	h.GetFinding(rr, req.WithContext(ctx))
	var resp FindingResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rr, resp
}

func TestGetFinding_EmbedsVulnerabilityAndComponent(t *testing.T) {
	fx := newDetailFixture(t)
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{v: fx.vuln}, &detailFindingRepo{f: fx.finding}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())

	dep, err := component.NewAssetDependency(fx.tenant, fx.asset, fx.comp.ID(), "package-lock.json", component.DependencyTypeTransitive)
	if err != nil {
		t.Fatal(err)
	}
	dep.SetManifestFile("package-lock.json")
	dep.SetDepth(2)
	lookup := &detailComponents{c: fx.comp, dep: dep}
	h.SetComponentService(lookup)

	rr, resp := getFindingDetail(t, h, fx.tenant.String(), fx.finding.ID().String())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	v := resp.Vulnerability
	if v == nil {
		t.Fatal("vulnerability not embedded")
	}
	if v.CVEID != "CVE-2024-21538" || v.Description == "" {
		t.Errorf("vulnerability = %+v", v)
	}
	if v.EPSSScore == nil || *v.EPSSScore != 0.00868 || v.EPSSPercentile == nil || *v.EPSSPercentile != 57.276 {
		t.Errorf("epss = %v / %v", v.EPSSScore, v.EPSSPercentile)
	}
	if len(v.FixedVersions) != 2 {
		t.Errorf("fixed_versions = %v", v.FixedVersions)
	}

	c := resp.Component
	if c == nil {
		t.Fatal("component not embedded")
	}
	if c.Name != "cross-spawn" || c.Version != "7.0.3" || c.Ecosystem != "npm" {
		t.Errorf("component = %+v", c)
	}
	if c.FixedIn != "7.0.5" {
		t.Errorf("fixed_in = %q, want 7.0.5 (same major line as 7.0.3)", c.FixedIn)
	}
	if c.DependencyType != "transitive" || c.ManifestFile != "package-lock.json" || c.Depth == nil || *c.Depth != 2 {
		t.Errorf("dependency = %q %q %v", c.DependencyType, c.ManifestFile, c.Depth)
	}

	// The asset's dependency row is looked up in the caller's tenant.
	if lookup.gotTenant != fx.tenant.String() || lookup.gotAsset != fx.asset.String() {
		t.Errorf("dependency lookup scoped to tenant %q asset %q", lookup.gotTenant, lookup.gotAsset)
	}
}

func TestGetFinding_OtherTenantGetsNotFoundAndNoLookups(t *testing.T) {
	fx := newDetailFixture(t)
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{v: fx.vuln}, &detailFindingRepo{f: fx.finding}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	lookup := &detailComponents{c: fx.comp}
	h.SetComponentService(lookup)

	rr, _ := getFindingDetail(t, h, shared.NewID().String(), fx.finding.ID().String())
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if lookup.depLookups != 0 {
		t.Errorf("dependency looked up %d times for a finding the caller cannot read", lookup.depLookups)
	}
}

func TestGetFinding_ContextLookupsAreBestEffort(t *testing.T) {
	fx := newDetailFixture(t)
	// The CVE record is missing and the dependency lookup fails: the finding
	// still loads, with the component (no dependency facts, no fix version).
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: fx.finding}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	h.SetComponentService(&detailComponents{c: fx.comp, depErr: errors.New("db down")})

	rr, resp := getFindingDetail(t, h, fx.tenant.String(), fx.finding.ID().String())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if resp.Vulnerability != nil {
		t.Errorf("vulnerability = %+v, want none", resp.Vulnerability)
	}
	if resp.Component == nil || resp.Component.Name != "cross-spawn" {
		t.Fatalf("component = %+v", resp.Component)
	}
	if resp.Component.DependencyType != "" || resp.Component.Depth != nil || resp.Component.FixedIn != "" {
		t.Errorf("component claims facts it does not have: %+v", resp.Component)
	}
}

func TestGetFinding_NoComponentServiceLeavesComponentOut(t *testing.T) {
	fx := newDetailFixture(t)
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{v: fx.vuln}, &detailFindingRepo{f: fx.finding}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())

	rr, resp := getFindingDetail(t, h, fx.tenant.String(), fx.finding.ID().String())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if resp.Component != nil {
		t.Errorf("component = %+v, want none without a component service", resp.Component)
	}
	if resp.ComponentID == nil || *resp.ComponentID != fx.comp.ID().String() {
		t.Errorf("component_id = %v", resp.ComponentID)
	}
	if resp.Vulnerability == nil {
		t.Error("vulnerability should still be embedded")
	}
}
