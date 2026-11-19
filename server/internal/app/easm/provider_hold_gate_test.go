package easm

// The hold on scope entries that name a provider's shared addresses
// (research/531 D3, E6): while the organization holds them, an address only
// such an entry covers is passive (provider_held), whether it is typed text
// or an inventory asset, so no job targeting it is built, signed or sent.
// Names resolving to the address are unaffected. Off (the default), the
// entry authorizes as any other.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// holdingScope is the fixture's scope with the hold answer of the scope
// service (scopeauth.ProviderHolds).
type holdingScope struct {
	*gateFixture
	held map[shared.ID]bool
	err  error
}

func (h *holdingScope) HeldProviderEntries(_ context.Context, t shared.ID, targets []*scopedom.Target) (map[shared.ID]bool, error) {
	if h.err != nil {
		return nil, h.err
	}
	if !h.mine(t) {
		return nil, nil
	}
	out := map[shared.ID]bool{}
	for _, x := range targets {
		if h.held[x.ID()] {
			out[x.ID()] = true
		}
	}
	return out, nil
}

// sharedM365Address is an address inside a Microsoft 365 shared range of
// the shipped dataset.
func sharedM365Address(t *testing.T) string {
	t.Helper()
	for _, p := range edgeaddr.Default().SharedFrontEndPrefixes() {
		if !p.Addr().Is4() {
			continue
		}
		a := p.Addr().Next().String()
		if r, ok := edgeaddr.Default().SharedFrontEnd(a); ok && r.Provider == "Microsoft 365" {
			return a
		}
	}
	t.Fatal("no Microsoft 365 range in the dataset")
	return ""
}

// This tests the active-check gate with a fake scope that holds on demand,
// not signing: the real dispatch path is tested in internal/app/scan
// (TestResolveDispatchTargets_HeldProviderEntryIsRefused).
func TestActiveGate_HeldProviderAddress_IsPassive(t *testing.T) {
	f := newGateFixture(t)
	addr := sharedM365Address(t)
	entry, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeIPAddress, addr, "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, entry)
	ip := f.add(t, addr, asset.AssetTypeIPAddress)
	name := f.add(t, "mail.scoped.com", asset.AssetTypeSubdomain)
	hs := &holdingScope{gateFixture: f}
	g := NewActiveGate(f, f, hs, f)
	ctx := context.Background()
	targets := []string{addr, addr + ":443", "mail.scoped.com"}

	// Hold off (nothing held): the entry authorizes the address.
	got, err := g.BlockedTargets(ctx, f.tenant, targets)
	if err != nil || len(got) != 0 {
		t.Fatalf("hold off: blocked %v, %v", got, err)
	}
	if b, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{ip.ID().String(), name.ID().String()}); err != nil || len(b) != 0 {
		t.Fatalf("hold off: assets blocked %v, %v", b, err)
	}

	// Held: the address is passive with its own reason; the name is not.
	hs.held = map[shared.ID]bool{entry.ID(): true}
	got, err = g.BlockedTargets(ctx, f.tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	if got[addr] != attribution.StateProviderHeld || got[addr+":443"] != attribution.StateProviderHeld {
		t.Fatalf("held: %v", got)
	}
	if _, no := got["mail.scoped.com"]; no {
		t.Fatalf("held: the name behind the address was refused: %v", got)
	}
	b, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{ip.ID().String(), name.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if b[ip.ID().String()] != attribution.StateProviderHeld {
		t.Fatalf("held asset: %v", b)
	}
	if _, no := b[name.ID().String()]; no {
		t.Fatalf("held: the name asset was refused: %v", b)
	}
	// An address no entry covers stays an ordinary refusal.
	if got, _ := g.BlockedTargets(ctx, f.tenant, []string{"203.0.113.9"}); got["203.0.113.9"] != attribution.StateUnattributed {
		t.Fatalf("uncovered address: %v", got)
	}

	// Another tenant: never allowed by A's entry, never held by A's hold.
	other, err := g.BlockedTargets(ctx, shared.NewID(), []string{addr})
	if err != nil || other[addr] != attribution.StateUnattributed {
		t.Fatalf("another tenant: %v, %v", other, err)
	}

	// The hold cannot be read: nothing is dispatched (fail closed).
	hs.err = errors.New("settings unavailable")
	if _, err := g.BlockedTargets(ctx, f.tenant, targets); err == nil {
		t.Fatal("a hold lookup error must refuse")
	}
}
