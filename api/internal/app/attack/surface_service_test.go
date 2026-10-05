package attack

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fakeSurfaceAssets answers Count from a callback over the filter, so a test
// can prove which filter produced which number.
type fakeSurfaceAssets struct {
	asset.Repository // unimplemented methods panic: GetStats must not call them
	count            func(f asset.Filter) int64
	list             []*asset.Asset
	breakdown        map[string]asset.AssetTypeStats
	listOpts         []asset.ListOptions
}

func (f *fakeSurfaceAssets) Count(_ context.Context, filter asset.Filter) (int64, error) {
	return f.count(filter), nil
}

func (f *fakeSurfaceAssets) List(_ context.Context, _ asset.Filter, opts asset.ListOptions, _ pagination.Pagination) (pagination.Result[*asset.Asset], error) {
	f.listOpts = append(f.listOpts, opts)
	return pagination.Result[*asset.Asset]{Data: f.list, Total: int64(len(f.list))}, nil
}

func (f *fakeSurfaceAssets) GetAssetTypeBreakdown(context.Context, shared.ID) (map[string]asset.AssetTypeStats, error) {
	return f.breakdown, nil
}

func (f *fakeSurfaceAssets) GetAverageRiskScore(context.Context, shared.ID) (float64, error) {
	return 42, nil
}

// The trend fields used to be hard-coded 0. They now count what is new in the
// last 7 days, each from its own filter.
func TestGetStats_TrendsCountNewInWindow(t *testing.T) {
	before := time.Now().UTC().Add(-trendWindow)
	repo := &fakeSurfaceAssets{count: func(f asset.Filter) int64 {
		switch {
		case f.CreatedAfter != nil:
			if f.CreatedAfter.Before(before.Add(-time.Minute)) || f.CreatedAfter.After(time.Now().UTC().Add(-trendWindow).Add(time.Minute)) {
				t.Errorf("CreatedAfter = %v, want about now-7d", f.CreatedAfter)
			}
			return 7
		case f.ExposureChangedOrCreatedAfter != nil && len(f.Criticalities) > 0:
			return 2
		case f.ExposureChangedOrCreatedAfter != nil:
			if !reflect.DeepEqual(f.Exposures, []asset.Exposure{asset.ExposurePublic}) {
				t.Errorf("newly exposed must filter public, got %v", f.Exposures)
			}
			return 3
		case len(f.Criticalities) > 0:
			return 10
		case len(f.Exposures) > 0:
			return 20
		default:
			return 100
		}
	}}
	svc := NewSurfaceService(repo, nil, logger.NewNop())

	got, err := svc.GetStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if got.TotalAssets != 100 || got.ExposedServices != 20 || got.CriticalExposures != 10 {
		t.Fatalf("totals = %d/%d/%d, want 100/20/10", got.TotalAssets, got.ExposedServices, got.CriticalExposures)
	}
	if got.TotalAssetsChange != 7 || got.ExposedServicesChange != 3 || got.CriticalExposuresChange != 2 {
		t.Fatalf("trends = %d/%d/%d, want 7/3/2", got.TotalAssetsChange, got.ExposedServicesChange, got.CriticalExposuresChange)
	}
	if got.TrendWindowDays != 7 {
		t.Fatalf("TrendWindowDays = %d, want 7", got.TrendWindowDays)
	}
	// The exposed list is ordered by risk, not by creation date.
	if len(repo.listOpts) == 0 || repo.listOpts[0].Sort == nil || repo.listOpts[0].Sort.IsEmpty() {
		t.Fatalf("exposed list must be sorted, got %+v", repo.listOpts)
	}
	if sql := repo.listOpts[0].Sort.SQL(); sql != "risk_score DESC, last_seen DESC" {
		t.Fatalf("exposed list sort = %q", sql)
	}
}

// Legacy names fold into their core type, every type the tenant has is
// listed (the old fixed list hid subdomains, IPs and certificates), and the
// largest bucket comes first.
func TestFoldAssetTypeBreakdown(t *testing.T) {
	got := foldAssetTypeBreakdown(map[string]asset.AssetTypeStats{
		"application": {Total: 3, Exposed: 1},
		"website":     {Total: 2, Exposed: 2}, // pre-000130 rows
		"subdomain":   {Total: 9, Exposed: 4},
		"ip_address":  {Total: 5, Exposed: 0},
		"certificate": {Total: 5, Exposed: 0},
		"repository":  {Total: 0, Exposed: 0},
	})
	want := []AssetTypeBreakdown{
		{Type: "subdomain", Total: 9, Exposed: 4},
		{Type: "application", Total: 5, Exposed: 3},
		{Type: "certificate", Total: 5, Exposed: 0},
		{Type: "ip_address", Total: 5, Exposed: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("breakdown =\n%+v\nwant\n%+v", got, want)
	}
}

type fakeHistory struct {
	rows []*asset.AssetStateChange
	refs map[shared.ID]asset.StateChangeAssetRef
}

func (h *fakeHistory) List(context.Context, shared.ID, asset.ListStateHistoryOptions) ([]*asset.AssetStateChange, int, error) {
	return h.rows, len(h.rows), nil
}

func (h *fakeHistory) GetAssetRefs(context.Context, shared.ID, []shared.ID) (map[shared.ID]asset.StateChangeAssetRef, error) {
	return h.refs, nil
}

func mustAsset(t *testing.T, tenant shared.ID, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetTenantID(tenant)
	return a
}

func change(t *testing.T, tenant, assetID shared.ID, ct asset.StateChangeType, at time.Time) *asset.AssetStateChange {
	t.Helper()
	c := asset.ReconstituteStateChange(shared.NewID(), tenant, assetID, ct, "", "", "", "", "", asset.ChangeSourceScan, nil, at, at)
	return c
}

// Recent changes: additions from the inventory, removals and other changes
// from state history, newest first; an "appeared" row of an asset already
// listed as added is not shown twice; restricted members see additions only.
func TestGetRecentChanges_MergesHistory(t *testing.T) {
	tenant := shared.NewID()
	added := mustAsset(t, tenant, "new.example.com")
	gone, changed := shared.NewID(), shared.NewID()
	now := time.Now().UTC()

	repo := &fakeSurfaceAssets{list: []*asset.Asset{added}}
	svc := NewSurfaceService(repo, nil, logger.NewNop())
	svc.SetStateHistory(&fakeHistory{
		rows: []*asset.AssetStateChange{
			change(t, tenant, added.ID(), asset.StateChangeAppeared, now),
			change(t, tenant, gone, asset.StateChangeDisappeared, now.Add(time.Hour)),
			change(t, tenant, changed, asset.StateChangeExposureChanged, now.Add(-time.Hour)),
		},
		refs: map[shared.ID]asset.StateChangeAssetRef{
			added.ID(): {Name: "new.example.com", Type: "domain"},
			gone:       {Name: "old.example.com", Type: "domain"},
			changed:    {Name: "api.example.com", Type: "subdomain"},
		},
	})

	got := svc.getRecentChanges(context.Background(), tenant, nil, 5)
	var kinds []string
	for _, c := range got {
		kinds = append(kinds, c.Type+":"+c.AssetName)
	}
	want := []string{"removed:old.example.com", "added:new.example.com", "changed:api.example.com"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("recent changes = %v, want %v", kinds, want)
	}

	scoped := svc.getRecentChanges(context.Background(), tenant, &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}, 5)
	if len(scoped) != 1 || scoped[0].Type != "added" {
		t.Fatalf("restricted member must see only in-scope additions, got %+v", scoped)
	}
}

// research/22 P0-12: every count and the exposed list cover approved assets
// only, so a rejected or unreviewed name is never shown as exposed surface.
func TestGetStats_ApprovedOnly(t *testing.T) {
	var unfiltered int
	repo := &fakeSurfaceAssets{count: func(f asset.Filter) int64 {
		if f.Attribution == nil || !f.Attribution.Unrecorded || len(f.Attribution.States) != 3 {
			unfiltered++
		}
		return 1
	}}
	svc := NewSurfaceService(repo, nil, logger.NewNop())
	if _, err := svc.GetStats(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if unfiltered != 0 {
		t.Fatalf("%d counts without the approved attribution filter", unfiltered)
	}
}
