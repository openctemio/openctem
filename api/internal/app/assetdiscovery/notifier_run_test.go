package assetdiscovery

import (
	"context"
	"testing"

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

func TestNotifier_SummaryLinksToTheRunThatFoundTheAssets(t *testing.T) {
	n, o, in, clk := newTestNotifier()
	tenant, other := shared.NewID(), shared.NewID()
	step, run := shared.NewID(), shared.NewID()
	n.SetRunResolver(fakeRuns{byStep: map[shared.ID]struct{ tenant, run shared.ID }{step: {tenant, run}}})

	ctx := WithStepRun(context.Background(), &step)
	n.AssetsDiscovered(ctx, tenant, []*asset.Asset{publicAsset(t, tenant, "a.example.com"), publicAsset(t, tenant, "b.example.com")})
	n.AssetsDiscovered(ctx, tenant, []*asset.Asset{publicAsset(t, tenant, "c.example.com"), publicAsset(t, tenant, "d.example.com")})
	clk.fire()

	want := "/scans/runs?run=" + run.String()
	if len(in.items) != 2 || len(o.items) != 2 {
		t.Fatalf("inapp=%d outbox=%d, want 2/2", len(in.items), len(o.items))
	}
	for _, it := range in.items {
		if it.URL != want {
			t.Fatalf("in-app url = %q, want %q", it.URL, want)
		}
	}
	if o.items[0].URL != want || o.items[0].Metadata["run_id"] != run.String() {
		t.Fatalf("outbox url/metadata = %q / %v", o.items[0].URL, o.items[0].Metadata["run_id"])
	}

	// The same step run seen by another tenant resolves to nothing: the
	// summary falls back to the changes view and names no run.
	n.AssetsDiscovered(ctx, other, []*asset.Asset{publicAsset(t, other, "x.example.com"), publicAsset(t, other, "y.example.com")})
	last := in.items[len(in.items)-1]
	if last.TenantID != other || last.URL == want || last.URL == "" {
		t.Fatalf("cross-tenant step run linked: %+v", last)
	}
}

func TestNotifier_SeveralRunsOrUnknownRunKeepTheChangesLink(t *testing.T) {
	n, _, in, clk := newTestNotifier()
	tenant := shared.NewID()
	s1, s2 := shared.NewID(), shared.NewID()
	n.SetRunResolver(fakeRuns{byStep: map[shared.ID]struct{ tenant, run shared.ID }{
		s1: {tenant, shared.NewID()}, s2: {tenant, shared.NewID()},
	}})

	n.AssetsDiscovered(WithStepRun(context.Background(), &s1), tenant, []*asset.Asset{publicAsset(t, tenant, "a.example.com")})
	n.AssetsDiscovered(WithStepRun(context.Background(), &s1), tenant, []*asset.Asset{publicAsset(t, tenant, "b.example.com")})
	n.AssetsDiscovered(WithStepRun(context.Background(), &s2), tenant, []*asset.Asset{publicAsset(t, tenant, "c.example.com")})
	n.AssetsDiscovered(context.Background(), tenant, []*asset.Asset{publicAsset(t, tenant, "d.example.com")})
	clk.fire()

	for _, it := range in.items {
		if it.URL != ChangesURL+"?view=appeared&internet=true" && it.URL != "/assets/"+it.ResourceID.String() {
			t.Fatalf("url = %q, want the changes view", it.URL)
		}
	}
}
