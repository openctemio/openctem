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
	return scopeapp.NewService(nil, &fakeExclusionRepo{rows: rows, err: err}, nil, nil, testLogger())
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
