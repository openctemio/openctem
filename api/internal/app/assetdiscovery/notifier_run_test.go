package assetdiscovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeRuns resolves step runs by a fixed table, per tenant.
type fakeRuns struct {
	byStep map[shared.ID]struct{ tenant, run shared.ID }
}

func (f fakeRuns) RunOfStepRun(_ context.Context, tenant, step shared.ID) (shared.ID, bool) {
	e, ok := f.byStep[step]
	if !ok || e.tenant != tenant {
		return shared.ID{}, false
	}
	return e.run, true
}

// A summary links to the assets it is about, never to the scan run that
// found them: the inventory filtered to the internet-facing assets added in
// the window (no id list). The run stays in the metadata, inside the tenant.
func TestNotifier_SummaryLinksToTheAssetsNotTheRun(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	start := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	now := start
	n.now = func() time.Time { return now }
	tenant, other := shared.NewID(), shared.NewID()
	step, run := shared.NewID(), shared.NewID()
	n.SetRunResolver(fakeRuns{byStep: map[shared.ID]struct{ tenant, run shared.ID }{step: {tenant, run}}})

	ctx := WithStepRun(context.Background(), &step)
	n.AssetsDiscovered(ctx, tenant, []*asset.Asset{publicAsset(t, tenant, "a.example.com"), publicAsset(t, tenant, "b.example.com")})
	now = start.Add(2 * time.Minute)
	n.AssetsDiscovered(ctx, tenant, []*asset.Asset{publicAsset(t, tenant, "c.example.com"), publicAsset(t, tenant, "d.example.com")})
	now = start.Add(5 * time.Minute)
	clk.fire()

	if len(in.items) != 2 || len(o.items) != 2 {
		t.Fatalf("inapp=%d outbox=%d, want 2/2", len(in.items), len(o.items))
	}
	want := "/assets?first_seen_after=2026-11-05T08%3A02%3A00Z&first_seen_before=2026-11-05T08%3A05%3A01Z&internet_facing=true"
	if o.items[1].URL != want || in.items[1].URL != want {
		t.Fatalf("summary url = %q / %q, want %q", o.items[1].URL, in.items[1].URL, want)
	}
	for _, it := range o.items {
		if strings.Contains(it.URL, "/scans/runs") || strings.Contains(it.URL, run.String()) {
			t.Fatalf("links to the run: %q", it.URL)
		}
	}
	if o.items[0].Metadata["run_id"] != run.String() {
		t.Fatalf("run id missing from metadata: %v", o.items[0].Metadata)
	}

	// The same step run seen by another tenant resolves to nothing.
	n.AssetsDiscovered(ctx, other, []*asset.Asset{publicAsset(t, other, "x.example.com"), publicAsset(t, other, "y.example.com")})
	last := o.items[len(o.items)-1]
	if last.TenantID != other || last.Metadata["run_id"] != nil {
		t.Fatalf("cross-tenant step run named: %+v", last)
	}
}

// One asset links to that asset.
func TestNotifier_OneAssetLinksToIt(t *testing.T) {
	n, o, _, _ := newTestNotifier()
	tenant := shared.NewID()
	a := publicAsset(t, tenant, "a.example.com")
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{a})
	if len(o.items) != 1 || o.items[0].URL != "/assets/"+a.ID().String() {
		t.Fatalf("url = %v", o.items)
	}
}

// Addresses inside a provider's published shared front-end ranges are not
// the organization's assets: the notice says so and names the provider.
func TestNotifier_SharedEdgeAddressesAreLabelled(t *testing.T) {
	n, o, _, _ := newTestNotifier()
	tenant := shared.NewID()
	var assets []*asset.Asset
	for _, ip := range []string{"2603:1000:4::5e1", "2603:1000:4::5e2"} {
		a, err := asset.NewAssetWithTenant(tenant, ip, asset.AssetTypeIPAddress, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		a.SetExposure(asset.ExposurePublic)
		assets = append(assets, a)
	}
	n.AssetsDiscovered(context.Background(), tenant, assets)
	if len(o.items) != 1 {
		t.Fatalf("outbox = %d", len(o.items))
	}
	got := o.items[0]
	if !strings.Contains(got.Title, "shared provider edge") || !strings.Contains(got.Title, "Azure Front Door") ||
		strings.Contains(got.Title, "internet-facing assets") {
		t.Fatalf("title = %q", got.Title)
	}
	if got.Metadata["shared_count"] != 2 || got.Metadata["shared_provider"] != "Azure Front Door" {
		t.Fatalf("metadata = %v", got.Metadata)
	}
}
