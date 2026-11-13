package easm

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// passiveAddressFixture: www.scoped.com (in scope through *.scoped.com)
// resolves to .10; x.thirdparty.net (no scope authority) resolves to .11;
// .12 is an address asset nothing in scope points at.
func passiveAddressFixture(t *testing.T) (*gateFixture, *ActiveGate) {
	t.Helper()
	f := newGateFixture(t)
	f.add(t, "www.scoped.com", asset.AssetTypeSubdomain)
	f.add(t, "x.thirdparty.net", asset.AssetTypeSubdomain)
	for _, a := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"} {
		f.add(t, a, asset.AssetTypeIPAddress)
	}
	f.resolves = map[string][]string{
		"www.scoped.com":   {"203.0.113.10"},
		"x.thirdparty.net": {"203.0.113.11"},
	}
	g := NewActiveGate(f, f, f, f)
	g.SetManagedService(true)
	// Unclassified scans off: only scope authority (and this rule) admits.
	g.SetUnclassified(func(context.Context, shared.ID) (string, error) { return unclassifiedOff, nil }, f)
	return f, g
}

var passiveAddrs = []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"}

// SECURITY (research/425 F5): a passive step may look up the network of an
// address the organization's own in-scope names resolve to (nothing is sent
// to it); any other uncovered address stays refused.
func TestUncoveredTargets_AddressBehindInScopeName(t *testing.T) {
	f, g := passiveAddressFixture(t)
	got, err := g.UncoveredTargets(context.Background(), f.tenant, passiveAddrs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"}
	if !slices.Equal(got, want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}
}

// SECURITY: another tenant's names never lend the exception.
func TestUncoveredTargets_AddressBehindNameCrossTenant(t *testing.T) {
	_, g := passiveAddressFixture(t)
	got, err := g.UncoveredTargets(context.Background(), shared.NewID(), passiveAddrs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, passiveAddrs) {
		t.Fatalf("other tenant: uncovered = %v, want all", got)
	}
}

// SECURITY: a failed lookup of the names leaves every address refused.
func TestUncoveredTargets_AddressBehindNameFailsClosed(t *testing.T) {
	f, g := passiveAddressFixture(t)
	f.resolveErr = errors.New("db down")
	got, err := g.UncoveredTargets(context.Background(), f.tenant, passiveAddrs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, passiveAddrs) {
		t.Fatalf("lookup failed: uncovered = %v, want all", got)
	}
}

// A name or a range is never admitted by the address rule.
func TestUncoveredTargets_AddressRuleTakesBareAddressesOnly(t *testing.T) {
	f, g := passiveAddressFixture(t)
	in := []string{"203.0.113.10:443", "203.0.113.0/28", "x.thirdparty.net"}
	got, err := g.UncoveredTargets(context.Background(), f.tenant, in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, in) {
		t.Fatalf("uncovered = %v, want %v", got, in)
	}
}
