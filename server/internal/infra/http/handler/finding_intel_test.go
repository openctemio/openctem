package handler

import (
	"context"
	"net/http"
	"testing"
	"time"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeEPSS struct{ calls int }

func (f *fakeEPSS) GetByCVEID(_ context.Context, cve string) (*threatintel.EPSSScore, error) {
	f.calls++
	return threatintel.NewEPSSScore(cve, 0.19257, 97.3, "v2025", time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)), nil
}

type fakeKEV struct{ calls int }

func (f *fakeKEV) GetByCVEID(_ context.Context, cve string) (*threatintel.KEVEntry, error) {
	f.calls++
	return threatintel.NewKEVEntry(cve, "djangoproject", "django", "SQLi", "", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 23, 0, 0, 0, 0, time.UTC), "Known", "", nil), nil
}

func intelFinding(t *testing.T, tenant shared.ID, cve string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityCritical, "django: Django SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	if cve != "" {
		if err := f.SetClassification(cve, nil, "", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// The intel block carries the advisory facts kept on the finding and the
// dates of its EPSS and KEV values.
func TestGetFinding_IntelWithSourcesAndDates(t *testing.T) {
	tenant := shared.NewID()
	f := intelFinding(t, tenant, "CVE-2025-64459")
	f.SetEPSSScore(0.19257)
	f.SetIsInKEV(true)
	f.SetMetadata(vulnerability.FindingMetaCVSSSource, "ghsa")
	f.SetMetadata(vulnerability.FindingMetaPublishedAt, "2025-11-05T15:15:41Z")
	f.SetMetadata(vulnerability.FindingMetaReferences, []any{"https://github.com/advisories/GHSA-frmv-pr5f-9mcr", "javascript:alert(1)"})

	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	h.SetIntelFeeds(&fakeEPSS{}, &fakeKEV{})

	rr, resp := getFindingDetail(t, h, tenant.String(), f.ID().String())
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	in := resp.Intel
	if in == nil {
		t.Fatal("intel missing")
	}
	if in.CVSSSource != "ghsa" || in.PublishedAt == nil || in.EPSSDate != "2026-10-15" || in.KEVDateAdded != "2026-01-02" || !in.KEVRansomware {
		t.Errorf("intel = %+v", in)
	}
	if len(in.References) != 1 {
		t.Errorf("only http(s) references are returned, got %v", in.References)
	}
}

// No CVE and no advisory facts: no block and no feed lookups; a CVE not in
// KEV never asks the KEV feed.
func TestGetFinding_IntelOmittedWithoutFacts(t *testing.T) {
	tenant := shared.NewID()
	f := intelFinding(t, tenant, "")
	svc := findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: f}, logger.NewNop())
	h := NewVulnerabilityHandler(svc, nil, logger.NewNop())
	epss, kev := &fakeEPSS{}, &fakeKEV{}
	h.SetIntelFeeds(epss, kev)
	_, resp := getFindingDetail(t, h, tenant.String(), f.ID().String())
	if resp.Intel != nil || epss.calls != 0 || kev.calls != 0 {
		t.Fatalf("intel %+v, feed calls %d/%d", resp.Intel, epss.calls, kev.calls)
	}

	g := intelFinding(t, tenant, "CVE-2025-1")
	g.SetEPSSScore(0.01)
	svc = findingapp.NewVulnerabilityService(&detailVulnRepo{}, &detailFindingRepo{f: g}, logger.NewNop())
	h = NewVulnerabilityHandler(svc, nil, logger.NewNop())
	kev = &fakeKEV{}
	h.SetIntelFeeds(&fakeEPSS{}, kev)
	_, resp = getFindingDetail(t, h, tenant.String(), g.ID().String())
	if kev.calls != 0 || resp.Intel == nil || resp.Intel.KEVDateAdded != "" {
		t.Fatalf("not in KEV: no KEV lookup, got calls=%d intel=%+v", kev.calls, resp.Intel)
	}
}
