package certmonitor

// CT discovery applies scope exclusions (RFC-042 F16): an excluded watched
// domain is not queried, an excluded host yields no exposure, and a failed
// exclusion lookup stops the sweep.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeExclusionRepo serves ListActive only; anything else panics.
type fakeExclusionRepo struct {
	scopedom.ExclusionRepository
	rows []*scopedom.Exclusion
	err  error
}

func (r *fakeExclusionRepo) ListActive(context.Context, shared.ID) ([]*scopedom.Exclusion, error) {
	return r.rows, r.err
}

func approvedExclusion(tenant shared.ID, typ scopedom.ExclusionType, pattern string) *scopedom.Exclusion {
	now := time.Now()
	return scopedom.ReconstituteExclusion(shared.NewID(), tenant, typ, pattern, "test", scopedom.StatusActive,
		nil, "approver", &now, "requester", now, now)
}

func exclusionsFor(rows []*scopedom.Exclusion, err error) *scopeapp.Service {
	return scopeapp.NewService(nil, &fakeExclusionRepo{rows: rows, err: err}, nil, testLogger())
}

func ctPayload(now time.Time) string {
	return fmt.Sprintf(`[
	  {"common_name":"example.com","name_value":"example.com\nnew.example.com","not_after":"%s"},
	  {"common_name":"vpn.example.com","name_value":"vpn.example.com","not_after":"%s","issuer_name":"LE","serial_number":"s1"}
	]`, now.Add(400*24*time.Hour).Format("2006-01-02T15:04:05"), now.Add(10*24*time.Hour).Format("2006-01-02T15:04:05"))
}

func TestMonitorTenant_ExcludedHostIsNotDiscovered(t *testing.T) {
	tenant := shared.NewID()
	srv := newCRTServer(t, ctPayload(time.Now().UTC()))
	defer srv.Close()

	expRepo := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.SetExclusions(exclusionsFor([]*scopedom.Exclusion{
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "vpn.example.com"),
	}, nil))

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("MonitorTenant: %v", err)
	}
	// Without the exclusion this sweep yields 3 exposures (two subdomains and
	// vpn's expiring certificate); vpn.example.com is excluded.
	if n != 1 {
		t.Fatalf("exposures = %d, want 1 (only new.example.com)", n)
	}
	for _, e := range expRepo.byKey {
		if d, _ := e.Details()["domain"].(string); d == "vpn.example.com" {
			t.Fatalf("excluded host discovered: %s %s", e.EventType(), e.Title())
		}
		if e.EventType() != exposuredom.EventTypeSubdomainDiscovered {
			t.Fatalf("unexpected exposure %s", e.EventType())
		}
	}
}

func TestMonitorTenant_ExcludedRootIsNotQueried(t *testing.T) {
	tenant := shared.NewID()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(ctPayload(time.Now().UTC())))
	}))
	defer srv.Close()

	expRepo := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.SetExclusions(exclusionsFor([]*scopedom.Exclusion{
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "example.com"),
	}, nil))

	n, err := svc.MonitorTenant(context.Background(), tenant)
	if err != nil {
		t.Fatalf("MonitorTenant: %v", err)
	}
	if hits.Load() != 0 || n != 0 {
		t.Fatalf("excluded domain queried %d time(s), %d exposures; want none", hits.Load(), n)
	}
}

func TestMonitorTenant_ExclusionLookupFailureStopsTheSweep(t *testing.T) {
	tenant := shared.NewID()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(ctPayload(time.Now().UTC())))
	}))
	defer srv.Close()

	expRepo := newFakeExposureRepo()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "example.com")}}, expRepo, srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	svc.SetExclusions(exclusionsFor(nil, errors.New("db down")))

	if _, err := svc.MonitorTenant(context.Background(), tenant); err == nil {
		t.Fatal("a failed exclusion lookup must stop the sweep")
	}
	if hits.Load() != 0 || len(expRepo.byKey) != 0 {
		t.Fatalf("swept without exclusions: %d queries, %d exposures", hits.Load(), len(expRepo.byKey))
	}
}

// An excluded host is not promoted to an inventory asset: CT promotion reads
// d.promotable after the exclusion filter.
func TestWithoutExcluded_DropsExcludedPromotable(t *testing.T) {
	tenant := shared.NewID()
	m, err := exclusionsFor([]*scopedom.Exclusion{
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "vpn.example.com"),
	}, nil).LoadExclusionMatcher(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	in := discoveries{
		subdomains: []string{"new.example.com", "vpn.example.com"},
		promotable: []ctHost{{Name: "new.example.com", NotAfter: now}, {Name: "vpn.example.com", NotAfter: now}},
	}
	out, dropped := withoutExcluded(in, m)
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (one excluded host, counted once)", dropped)
	}
	if len(out.promotable) != 1 || out.promotable[0].Name != "new.example.com" {
		t.Fatalf("promotable = %+v, want only new.example.com", out.promotable)
	}
	if len(in.promotable) != 2 || in.promotable[1].Name != "vpn.example.com" {
		t.Fatal("the input discoveries were modified")
	}
}

// End to end: a sweep with promotion on creates no asset for an excluded
// name and leaves an existing excluded asset untouched (no evidence, no
// attribution record); other names are promoted as before.
func TestMonitorTenant_ExcludedHostIsNotPromoted(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www", "vpn", "legacy")
	defer srv.Close()

	listed := mustDomainAsset(t, tenant, "listed.com")
	legacy, err := assetdom.NewAssetWithTenant(tenant, "legacy.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed, legacy})
	svc.SetExclusions(exclusionsFor([]*scopedom.Exclusion{
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "vpn.listed.com"),
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "legacy.listed.com"),
	}, nil))

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if _, ok := inv.byName["www.listed.com"]; !ok {
		t.Fatal("www.listed.com not promoted")
	}
	if _, ok := inv.byName["vpn.listed.com"]; ok {
		t.Fatal("excluded vpn.listed.com was promoted to an asset")
	}
	for _, names := range inv.reports {
		for _, n := range names {
			if n == "vpn.listed.com" || n == "legacy.listed.com" {
				t.Fatalf("excluded %s sent to ingest", n)
			}
		}
	}
	if inv.byName["legacy.listed.com"] != legacy {
		t.Fatal("existing excluded asset was replaced")
	}
	if ev := attr.evidence[legacy.ID().String()]; len(ev) != 0 {
		t.Fatalf("existing excluded asset got %d evidence rows, want none", len(ev))
	}
	if _, ok := attr.records[legacy.ID().String()]; ok {
		t.Fatal("existing excluded asset got an attribution record")
	}
}
