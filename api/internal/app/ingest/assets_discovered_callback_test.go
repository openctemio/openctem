package ingest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memAssetRepo is a tenant-partitioned in-memory asset store implementing the
// two methods ProcessBatch uses. UpsertBatch mirrors the Postgres semantics:
// ON CONFLICT (tenant_id, name) keeps the existing row's id.
type memAssetRepo struct {
	asset.Repository
	mu   sync.Mutex
	rows map[shared.ID]map[string]*asset.Asset // tenant -> name -> asset
	// racePreinsert simulates a concurrent ingest inserting these names (for
	// the given tenant) between our lookup and our upsert.
	racePreinsert map[string]shared.ID
}

func newMemAssetRepo() *memAssetRepo {
	return &memAssetRepo{rows: map[shared.ID]map[string]*asset.Asset{}}
}

func (m *memAssetRepo) GetByNames(_ context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]*asset.Asset{}
	for _, n := range names {
		if a, ok := m.rows[tenantID][n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

func (m *memAssetRepo) UpsertBatch(_ context.Context, assets []*asset.Asset) (int, int, map[string]shared.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	created, updated := 0, 0
	persisted := map[string]shared.ID{}
	for _, a := range assets {
		t := a.TenantID()
		if m.rows[t] == nil {
			m.rows[t] = map[string]*asset.Asset{}
		}
		if id, ok := m.racePreinsert[a.Name()]; ok {
			delete(m.racePreinsert, a.Name())
			m.rows[t][a.Name()] = a
			persisted[a.Name()] = id
			updated++
			continue
		}
		if existing, ok := m.rows[t][a.Name()]; ok {
			persisted[a.Name()] = existing.ID()
			m.rows[t][a.Name()] = a
			updated++
			continue
		}
		m.rows[t][a.Name()] = a
		persisted[a.Name()] = a.ID()
		created++
	}
	return created, updated, persisted, nil
}

type discoveredCall struct {
	tenant shared.ID
	assets []*asset.Asset
}

func newDiscoveryProcessor(repo asset.Repository) (*AssetProcessor, *[]discoveredCall) {
	p := NewAssetProcessor(repo, logger.NewNop())
	calls := &[]discoveredCall{}
	p.SetAssetsDiscoveredCallback(func(_ context.Context, tenantID shared.ID, assets []*asset.Asset) {
		*calls = append(*calls, discoveredCall{tenant: tenantID, assets: assets})
	})
	return p, calls
}

func reconReport(names ...string) *ctis.Report {
	r := &ctis.Report{}
	for i, n := range names {
		r.Assets = append(r.Assets, ctis.Asset{
			ID:    "a" + string(rune('0'+i)),
			Type:  ctis.AssetTypeDomain,
			Value: n,
			Name:  n,
		})
	}
	return r
}

func TestAssetsDiscovered_FiredOncePerNewAsset(t *testing.T) {
	repo := newMemAssetRepo()
	p, calls := newDiscoveryProcessor(repo)
	tenant := shared.NewID()

	if _, err := p.ProcessBatch(context.Background(), tenant, reconReport("a.example.com", "b.example.com"), &Output{}, nil); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("callback calls = %d, want 1 (one per batch)", len(*calls))
	}
	got := (*calls)[0]
	if got.tenant != tenant {
		t.Fatalf("callback tenant = %s, want %s", got.tenant, tenant)
	}
	if len(got.assets) != 2 {
		t.Fatalf("assets in callback = %d, want 2", len(got.assets))
	}
	seen := map[shared.ID]int{}
	for _, a := range got.assets {
		seen[a.ID()]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("asset %s announced %d times, want once", id, n)
		}
	}
	// Domains are internet-facing by inference: the flag must be carried.
	for _, a := range got.assets {
		if a.Exposure() != asset.ExposurePublic {
			t.Fatalf("asset %s exposure = %s, want public (internet-facing flag lost)", a.Name(), a.Exposure())
		}
	}
}

func TestAssetsDiscovered_NotFiredOnUpdate(t *testing.T) {
	repo := newMemAssetRepo()
	p, calls := newDiscoveryProcessor(repo)
	tenant := shared.NewID()

	if _, err := p.ProcessBatch(context.Background(), tenant, reconReport("a.example.com"), &Output{}, nil); err != nil {
		t.Fatalf("first ProcessBatch: %v", err)
	}
	// Re-scan: the same asset is merged, and one genuinely new one appears.
	if _, err := p.ProcessBatch(context.Background(), tenant, reconReport("a.example.com", "c.example.com"), &Output{}, nil); err != nil {
		t.Fatalf("second ProcessBatch: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("callback calls = %d, want 2", len(*calls))
	}
	second := (*calls)[1].assets
	if len(second) != 1 || second[0].Name() != "c.example.com" {
		names := make([]string, 0, len(second))
		for _, a := range second {
			names = append(names, a.Name())
		}
		t.Fatalf("second batch announced %v, want only c.example.com (a.example.com is an update)", names)
	}

	// A pure re-scan (nothing new) must not fire at all.
	if _, err := p.ProcessBatch(context.Background(), tenant, reconReport("a.example.com", "c.example.com"), &Output{}, nil); err != nil {
		t.Fatalf("third ProcessBatch: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("callback fired on a re-scan with no new assets (calls = %d)", len(*calls))
	}
}

func TestAssetsDiscovered_TenantScoped(t *testing.T) {
	repo := newMemAssetRepo()
	p, calls := newDiscoveryProcessor(repo)
	t1, t2 := shared.NewID(), shared.NewID()

	if _, err := p.ProcessBatch(context.Background(), t1, reconReport("shared.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	// The same name in another tenant is a NEW asset for that tenant.
	if _, err := p.ProcessBatch(context.Background(), t2, reconReport("shared.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("callback calls = %d, want 2 (one per tenant)", len(*calls))
	}
	for i, want := range []shared.ID{t1, t2} {
		c := (*calls)[i]
		if c.tenant != want {
			t.Fatalf("call %d tenant = %s, want %s", i, c.tenant, want)
		}
		for _, a := range c.assets {
			if a.TenantID() != want {
				t.Fatalf("call %d carried asset of tenant %s, want %s", i, a.TenantID(), want)
			}
		}
	}
}

func TestAssetsDiscovered_ConcurrentCreateLoserNotAnnounced(t *testing.T) {
	repo := newMemAssetRepo()
	// Another ingest inserts x.example.com between our lookup and our upsert.
	repo.racePreinsert = map[string]shared.ID{"x.example.com": shared.NewID()}
	p, calls := newDiscoveryProcessor(repo)

	if _, err := p.ProcessBatch(context.Background(), shared.NewID(), reconReport("x.example.com", "y.example.com"), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("callback calls = %d, want 1", len(*calls))
	}
	for _, a := range (*calls)[0].assets {
		if a.Name() == "x.example.com" {
			t.Fatal("x.example.com was inserted by the other ingest; announcing it here would announce it twice")
		}
	}
	if n := len((*calls)[0].assets); n != 1 {
		t.Fatalf("announced %d assets, want 1 (y.example.com)", n)
	}
}

// Root domains auto-created for orphaned subdomains are discoveries too, and
// arrive in the SAME single callback as the report's own assets.
func TestAssetsDiscovered_DerivedRootDomainInSameBatch(t *testing.T) {
	repo := newMemAssetRepo()
	p, calls := newDiscoveryProcessor(repo)
	report := &ctis.Report{Assets: []ctis.Asset{{
		ID: "s1", Type: ctis.AssetTypeSubdomain, Value: "api.acme-example.com", Name: "api.acme-example.com",
		Properties: ctis.Properties{"root_domain": "acme-example.com"},
	}}}

	if _, err := p.ProcessBatch(context.Background(), shared.NewID(), report, &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("callback calls = %d, want 1", len(*calls))
	}
	names := map[string]bool{}
	for _, a := range (*calls)[0].assets {
		names[a.Name()] = true
	}
	if !names["api.acme-example.com"] || !names["acme-example.com"] || len(names) != 2 {
		t.Fatalf("announced %v, want the subdomain and its derived root domain", names)
	}
}

// An existing asset that a re-scan turns internet-facing goes to the exposed
// callback (notification), never to the discovered one (asset_discovered).
func TestAssetsExposed_ExistingAssetBecomesInternetFacing(t *testing.T) {
	repo := newMemAssetRepo()
	p, discoveredCalls := newDiscoveryProcessor(repo)
	var exposedCalls []discoveredCall
	p.SetAssetsExposedCallback(func(_ context.Context, tenantID shared.ID, assets []*asset.Asset) {
		exposedCalls = append(exposedCalls, discoveredCall{tenant: tenantID, assets: assets})
	})
	tenant := shared.NewID()
	host := func(internet bool) *ctis.Report {
		return &ctis.Report{Assets: []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "10.1.2.3", Name: "10.1.2.3", IsInternetAccessible: internet}}}
	}

	if _, err := p.ProcessBatch(context.Background(), tenant, host(false), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(exposedCalls) != 0 {
		t.Fatal("an internal asset was reported exposed")
	}
	if _, err := p.ProcessBatch(context.Background(), tenant, host(true), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*discoveredCalls) != 1 {
		t.Fatalf("discovered fired %d times, want 1 (only the first, creating ingest)", len(*discoveredCalls))
	}
	if len(exposedCalls) != 1 || len(exposedCalls[0].assets) != 1 || exposedCalls[0].tenant != tenant {
		t.Fatalf("exposed calls = %+v, want one call with the host", exposedCalls)
	}
	// Still internet-facing on the next scan: not reported again.
	if _, err := p.ProcessBatch(context.Background(), tenant, host(true), &Output{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(exposedCalls) != 1 {
		t.Fatalf("exposed re-reported on an unchanged re-scan (%d calls)", len(exposedCalls))
	}
}

func TestExposureTransitions_RecordedOnRescan(t *testing.T) {
	tenant := shared.NewID()
	a, err := asset.NewAssetWithTenant(tenant, "10.0.0.5", asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	p := NewAssetProcessor(nil, logger.NewNop())
	var recovered []shared.ID
	var exposed []*asset.Asset

	changes := p.mergeTrackingExposure(tenant, a, &ctis.Asset{IsInternetAccessible: true}, nil, time.Time{}, &recovered, &exposed)
	if len(exposed) != 1 || exposed[0] != a {
		t.Fatalf("asset that became internet-facing not reported (got %d)", len(exposed))
	}

	byType := map[asset.StateChangeType]*asset.AssetStateChange{}
	for _, c := range changes {
		byType[c.ChangeType()] = c
	}
	ie := byType[asset.StateChangeInternetExposureChanged]
	if ie == nil || ie.OldValue() != "false" || ie.NewValue() != "true" {
		t.Fatalf("want internet_exposure_changed false->true, got %+v", ie)
	}
	ex := byType[asset.StateChangeExposureChanged]
	if ex == nil || ex.NewValue() != string(asset.ExposurePublic) {
		t.Fatalf("want exposure_changed ->public, got %+v", ex)
	}

	// Same signal again: no transition, no rows.
	if again := p.mergeTrackingExposure(tenant, a, &ctis.Asset{IsInternetAccessible: true}, nil, time.Time{}, &recovered, &exposed); len(again) != 0 {
		t.Fatalf("unchanged exposure produced %d rows", len(again))
	}
	if len(exposed) != 1 {
		t.Fatalf("already internet-facing asset reported again (got %d)", len(exposed))
	}
}
