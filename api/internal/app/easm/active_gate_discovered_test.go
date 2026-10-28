package easm

import (
	"context"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Inventory first (research/124, RFC-054 §15): a discovered asset is in the
// inventory, and only a scope entry lets active probes reach it.
func TestActiveGate_Discovered(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	g.SetManagedService(true)
	ctx := context.Background()

	uncovered := f.add(t, "cdn-target.thirdparty.example", asset.AssetTypeDomain)
	f.record(uncovered, attribution.StateDiscovered, false)
	covered := f.add(t, "api.scoped.com", asset.AssetTypeSubdomain)
	f.record(covered, attribution.StateDiscovered, false)
	addrIn := f.add(t, "198.51.100.7", asset.AssetTypeIPAddress)
	f.record(addrIn, attribution.StateDiscovered, false)
	addrOut := f.add(t, "203.0.113.9", asset.AssetTypeIPAddress)
	f.record(addrOut, attribution.StateDiscovered, false)
	svcIn := f.add(t, "api.scoped.com:443:tcp", asset.AssetTypeService)
	f.record(svcIn, attribution.StateDiscovered, false)
	svcOut := f.add(t, "203.0.113.9:22:tcp", asset.AssetTypeService)
	f.record(svcOut, attribution.StateDiscovered, false)
	heldByPerson := f.add(t, "held.scoped.com", asset.AssetTypeSubdomain)
	f.record(heldByPerson, attribution.StateNeedsReview, true)
	watched := f.add(t, "watched.scoped.com", asset.AssetTypeSubdomain)
	f.record(watched, attribution.StateMonitorOnly, true)

	ids := []string{}
	for _, a := range []*asset.Asset{uncovered, covered, addrIn, addrOut, svcIn, svcOut, heldByPerson, watched} {
		ids = append(ids, a.ID().String())
	}
	got, err := g.ActiveCheckBlocked(ctx, f.tenant, ids)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]attribution.State{
		uncovered.ID().String():    attribution.StateDiscovered,
		addrOut.ID().String():      attribution.StateDiscovered,
		svcOut.ID().String():       attribution.StateDiscovered,
		heldByPerson.ID().String(): attribution.StateNeedsReview,
		watched.ID().String():      attribution.StateMonitorOnly,
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("asset %s = %q, want %q", id, got[id], w)
		}
	}
	for _, a := range []*asset.Asset{covered, addrIn, svcIn} {
		if s, no := got[a.ID().String()]; no {
			t.Errorf("%s refused (%s), want allowed", a.Name(), s)
		}
	}
	// The refusal code the scan paths report: not in scope.
	if c := scansvc.RefusalCodeForState(attribution.StateDiscovered); c != scopedom.RefusalNoEntry {
		t.Errorf("discovered code = %s, want no_entry", c)
	}

	// Typed text naming a discovered asset gets the same answer.
	typed, err := g.BlockedTargets(ctx, f.tenant, []string{"https://cdn-target.thirdparty.example/x", "api.scoped.com"})
	if err != nil {
		t.Fatal(err)
	}
	if typed["https://cdn-target.thirdparty.example/x"] != attribution.StateDiscovered {
		t.Fatalf("typed: %v", typed)
	}
	if _, no := typed["api.scoped.com"]; no {
		t.Fatalf("typed covered discovered refused: %v", typed)
	}

	// Another tenant asking about this tenant's covered discovered asset:
	// not its asset, refused.
	other, err := g.ActiveCheckBlocked(ctx, shared.NewID(), []string{covered.ID().String()})
	if err != nil || other[covered.ID().String()] != attribution.StateUnattributed {
		t.Fatalf("cross-tenant: %v %v", other, err)
	}
	// Another tenant's entry never covers this tenant's discovered asset.
	f2 := newGateFixture(t)
	g2 := NewActiveGate(f2, f2, f2, f2)
	g2.SetManagedService(true)
	foreign := f2.add(t, "app.foreign.example", asset.AssetTypeSubdomain)
	f2.record(foreign, attribution.StateDiscovered, false)
	if b, err := g2.ActiveCheckBlocked(ctx, f2.tenant, []string{foreign.ID().String()}); err != nil || b[foreign.ID().String()] != attribution.StateDiscovered {
		t.Fatalf("foreign: %v %v", b, err)
	}
}
