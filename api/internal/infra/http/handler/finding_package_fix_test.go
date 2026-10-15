package handler

import (
	"context"
	"net/http"
	"testing"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeFixLister records the scope it was asked for and serves siblings.
type fakeFixLister struct {
	sib                      []vulnerability.PackageFixSibling
	tenant, asset, component shared.ID
}

func (f *fakeFixLister) ListPackageFixSiblings(_ context.Context, tenantID, assetID, componentID shared.ID, _ int) ([]vulnerability.PackageFixSibling, error) {
	f.tenant, f.asset, f.component = tenantID, assetID, componentID
	return f.sib, nil
}

// A CI finding has no catalog record: the nearest fix comes from the
// scanner's fixed versions on the finding, and the plan names what the
// upgrade resolves on this asset.
func TestGetFinding_FixFromScannerVersionsAndPackagePlan(t *testing.T) {
	tenant, asset, versionID := shared.NewID(), shared.NewID(), shared.NewID()
	f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityCritical, "django: Django SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	f.SetComponentID(versionID)
	f.SetMetadata(vulnerability.FindingMetaFixedVersions, []any{"5.2.8", "5.1.14", "4.2.26"})
	f.SetLocation("app/requirements.txt", 0, 0, 0, 0)

	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	h.SetComponentService(&detailComponents{c: &component.FindingComponent{VersionID: versionID.String(),
		ProductID: shared.NewID().String(), Name: "Django", Version: "4.2.20", Ecosystem: "pypi", PURL: "pkg:pypi/django@4.2.20"}})
	lister := &fakeFixLister{sib: []vulnerability.PackageFixSibling{
		{ID: f.ID().String(), Title: "django: Django SQL injection", Severity: "critical", CVEID: "CVE-2025-64459", Fixed: []string{"5.2.8", "5.1.14", "4.2.26"}},
		{ID: "b", Title: "other", Severity: "high", CVEID: "CVE-B", Fixed: []string{"4.2.30"}},
		{ID: "c", Title: "major only", Severity: "medium", CVEID: "CVE-C", Fixed: []string{"5.1.0"}},
	}}
	h.SetPackageFixLister(lister)

	rr, resp := getFindingDetail(t, h, tenant.String(), f.ID().String())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	c := resp.Component
	if c == nil || c.FixedIn != "4.2.26" || c.FixedInMajor || len(c.FixedVersions) != 3 {
		t.Fatalf("component = %+v, want nearest fix 4.2.26 on the same major", c)
	}
	if c.ManifestFile != "app/requirements.txt" {
		t.Errorf("manifest falls back to the finding's file, got %q", c.ManifestFile)
	}
	p := resp.PackageFix
	if p == nil || p.TargetVersion != "4.2.30" || p.MajorUpgrade || p.OpenFindings != 3 || p.ResolvesCount != 2 {
		t.Fatalf("plan = %+v", p)
	}
	if p.CompleteVersion != "5.1.14" || !p.CompleteMajor || p.CompleteResolves != 3 {
		t.Errorf("complete fix = %q major=%v resolves=%d, want 5.1.14 on the next major fixing all 3", p.CompleteVersion, p.CompleteMajor, p.CompleteResolves)
	}
	if len(p.Remaining) != 1 || p.Remaining[0].CVEID != "CVE-C" {
		t.Errorf("remaining = %+v", p.Remaining)
	}
	if lister.tenant != tenant || lister.asset != asset || lister.component != versionID {
		t.Errorf("plan must be scoped to the finding's tenant, asset and package version")
	}
}

// Another tenant's id never reaches the plan: the finding read 404s first.
func TestGetFinding_PackagePlanNotReachableCrossTenant(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	f, _ := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	f.SetComponentID(shared.NewID())
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	lister := &fakeFixLister{}
	h.SetPackageFixLister(lister)
	rr, _ := getFindingDetail(t, h, shared.NewID().String(), f.ID().String())
	if rr.Code != http.StatusNotFound || !lister.tenant.IsZero() {
		t.Fatalf("cross-tenant read: status %d, lister called=%v", rr.Code, !lister.tenant.IsZero())
	}
}
