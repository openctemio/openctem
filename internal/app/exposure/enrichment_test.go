package exposure

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes for the enricher's optional dependencies ---

type fakeAssetRepo struct {
	assets      map[shared.ID]*asset.Asset
	gotTenantID shared.ID
}

func (f *fakeAssetRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	f.gotTenantID = tenantID
	if a, ok := f.assets[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

type fakeBiz struct {
	m map[shared.ID]asset.BusinessContext
}

func (f fakeBiz) GetForAssets(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]asset.BusinessContext, error) {
	return f.m, nil
}

type fakeReach struct{ set map[string]bool }

func (f fakeReach) ReachableFromPublic(_ context.Context, _ shared.ID) (map[string]bool, error) {
	return f.set, nil
}

type fakeEPSS struct{ m map[string]EPSSData }

func (f fakeEPSS) GetByCVEIDs(_ context.Context, _ []string) (map[string]EPSSData, error) {
	return f.m, nil
}

type fakeKEV struct{ m map[string]KEVData }

func (f fakeKEV) GetByCVEIDs(_ context.Context, _ []string) (map[string]KEVData, error) {
	return f.m, nil
}

func mustEvent(t *testing.T, tenantID shared.ID, et exposuredom.EventType, details map[string]any) *exposuredom.ExposureEvent {
	t.Helper()
	ev, err := exposuredom.NewExposureEvent(tenantID, et, exposuredom.SeverityMedium, "t", "src", details)
	if err != nil {
		t.Fatalf("NewExposureEvent: %v", err)
	}
	return ev
}

func mustAsset(t *testing.T, tenantID shared.ID, crit asset.Criticality, exposureLevel asset.Exposure) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset("host-"+shared.NewID().String(), asset.AssetTypeHost, crit)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	a.SetTenantID(tenantID)
	a.SetExposure(exposureLevel)
	return a
}

func TestEnrichBatch_AssetReachabilityAndCriticality(t *testing.T) {
	tenantID := shared.NewID()
	a := mustAsset(t, tenantID, asset.CriticalityHigh, asset.ExposurePublic)
	repo := &fakeAssetRepo{assets: map[shared.ID]*asset.Asset{a.ID(): a}}

	e := NewExposureEnricher(repo, logger.NewNop())
	e.SetReachabilityOracle(fakeReach{set: map[string]bool{a.ID().String(): true}})

	aid := a.ID()
	ev := mustEvent(t, tenantID, exposuredom.EventTypeMisconfiguration, nil)
	ev.SetAssetID(&aid)

	out := e.EnrichBatch(context.Background(), tenantID, []*exposuredom.ExposureEvent{ev})
	enr := out[ev.ID()]

	if enr.EffectiveCriticality != string(asset.CriticalityHigh) {
		t.Errorf("effective criticality = %q, want high", enr.EffectiveCriticality)
	}
	if enr.IsInternetAccessible == nil || !*enr.IsInternetAccessible {
		t.Errorf("expected internet-accessible true")
	}
	if enr.OnAttackPath == nil || !*enr.OnAttackPath {
		t.Errorf("expected on-attack-path true")
	}
	// Tenant-scoped asset lookup.
	if repo.gotTenantID != tenantID {
		t.Errorf("asset lookup tenant = %s, want %s", repo.gotTenantID, tenantID)
	}
}

func TestEnrichBatch_BusinessContextRaisesCriticality(t *testing.T) {
	tenantID := shared.NewID()
	a := mustAsset(t, tenantID, asset.CriticalityMedium, asset.ExposurePrivate)
	repo := &fakeAssetRepo{assets: map[shared.ID]*asset.Asset{a.ID(): a}}

	e := NewExposureEnricher(repo, logger.NewNop())
	e.SetBusinessContextLookup(fakeBiz{m: map[shared.ID]asset.BusinessContext{
		a.ID(): {BusinessUnitCriticality: asset.CriticalityCritical},
	}})

	aid := a.ID()
	ev := mustEvent(t, tenantID, exposuredom.EventTypePortOpen, nil)
	ev.SetAssetID(&aid)

	out := e.EnrichBatch(context.Background(), tenantID, []*exposuredom.ExposureEvent{ev})
	if got := out[ev.ID()].EffectiveCriticality; got != string(asset.CriticalityCritical) {
		t.Errorf("effective criticality = %q, want critical (raised by BU)", got)
	}
}

func TestEnrichBatch_EPSSKEVFromCVEDetail(t *testing.T) {
	tenantID := shared.NewID()
	e := NewExposureEnricher(nil, logger.NewNop()) // no asset repo needed for this path
	due := time.Now().UTC().Add(14 * 24 * time.Hour)
	e.SetThreatIntel(
		fakeEPSS{m: map[string]EPSSData{"CVE-2021-44228": {Score: 0.97, Percentile: 0.99}}},
		fakeKEV{m: map[string]KEVData{"CVE-2021-44228": {DueDate: &due}}},
	)

	ev := mustEvent(t, tenantID, exposuredom.EventTypeMisconfiguration, map[string]any{"cve_id": "cve-2021-44228"})

	out := e.EnrichBatch(context.Background(), tenantID, []*exposuredom.ExposureEvent{ev})
	enr := out[ev.ID()]
	if enr.CVEID != "CVE-2021-44228" {
		t.Errorf("cve id = %q, want CVE-2021-44228 (normalized)", enr.CVEID)
	}
	if enr.EPSSScore == nil || *enr.EPSSScore != 0.97 {
		t.Errorf("epss score = %v, want 0.97", enr.EPSSScore)
	}
	if enr.IsInKEV == nil || !*enr.IsInKEV {
		t.Errorf("expected is_in_kev true")
	}
	if enr.KEVDueDate == nil {
		t.Errorf("expected kev due date")
	}
}

func TestEnrichBatch_NoAssetNoCVE_EmptyEnrichment(t *testing.T) {
	tenantID := shared.NewID()
	e := NewExposureEnricher(&fakeAssetRepo{assets: map[shared.ID]*asset.Asset{}}, logger.NewNop())

	ev := mustEvent(t, tenantID, exposuredom.EventTypeMisconfiguration, nil)
	out := e.EnrichBatch(context.Background(), tenantID, []*exposuredom.ExposureEvent{ev})
	enr := out[ev.ID()]

	if enr.EffectiveCriticality != "" || enr.IsInternetAccessible != nil || enr.EPSSScore != nil || enr.IsInKEV != nil {
		t.Errorf("expected empty enrichment for asset-less, CVE-less exposure, got %+v", enr)
	}
}

func TestEnrichBatch_NilEnricherAndEmptyBatch(t *testing.T) {
	var e *ExposureEnricher
	if got := e.EnrichBatch(context.Background(), shared.NewID(), nil); len(got) != 0 {
		t.Errorf("nil enricher must return empty map, got %d", len(got))
	}
}
