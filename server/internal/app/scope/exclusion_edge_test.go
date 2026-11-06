package scope

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	edgeIP      = "104.16.1.1"    // Cloudflare published range
	edgeIPv6    = "2606:4700::10" // Cloudflare published range
	dedicatedIP = "203.0.113.7"
	heldIP      = "198.51.100.9" // an edge only by its network holder's name
)

// SECURITY (owner decision 2026-10-30): an exclusion of a shared front end
// stays on the address. The values a name is matched by keep every address
// not proven shared (fail closed) and drop only addresses inside a
// published shared range.
func TestAssetExclusionValues_SharedFrontEndDoesNotPropagate(t *testing.T) {
	props := map[string]any{"ip_addresses": []any{edgeIP, edgeIPv6, dedicatedIP, heldIP, "::ffff:104.16.1.2"}}
	got := AssetExclusionValues("subdomain", "shop.example.com", props)
	for _, want := range []string{"shop.example.com", dedicatedIP, heldIP} {
		if !slices.Contains(got, want) {
			t.Errorf("values %v lack %q", got, want)
		}
	}
	for _, edge := range []string{edgeIP, edgeIPv6, "104.16.1.2", "::ffff:104.16.1.2"} {
		if slices.Contains(got, edge) {
			t.Errorf("values %v hold the shared front end %q", got, edge)
		}
	}
	// The asset's own name is never dropped, even when it is an edge address.
	if got := AssetExclusionValues("ip_address", edgeIP, map[string]any{"ip_addresses": []any{edgeIP}}); !slices.Contains(got, edgeIP) {
		t.Fatalf("an edge address asset lost its own name: %v", got)
	}
	// Unparsable values are kept (never read as shared).
	if got := PropagatingAddresses([]string{"not-an-ip", "fe80::1%eth0"}); len(got) != 2 {
		t.Fatalf("unreadable addresses dropped: %v", got)
	}
}

func approvedExcl(t *testing.T, tenant shared.ID, typ scopedom.ExclusionType, pattern string) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenant, typ, pattern, "test", nil, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("approver"); err != nil {
		t.Fatal(err)
	}
	return e
}

func namedAsset(t *testing.T, name string, ips ...string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, asset.AssetTypeSubdomain, asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	list := make([]any, len(ips))
	for i, ip := range ips {
		list[i] = ip
	}
	a.SetProperty("ip_addresses", list)
	return a
}

// The ingest and discovery matcher (ExcludedAsset) follows the same rule:
// an excluded edge address or a range of edge addresses leaves names behind
// it alone; an excluded dedicated address, or a range holding one, excludes
// the names resolving to it; an address known as an edge only by its network
// holder counts as dedicated.
func TestExcludedAsset_EdgeExclusionStaysOnTheAddress(t *testing.T) {
	tenant := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		approvedExcl(t, tenant, scopedom.ExclusionTypeIPAddress, edgeIP),
		approvedExcl(t, tenant, scopedom.ExclusionTypeCIDR, "104.16.2.0/24"),
		approvedExcl(t, tenant, scopedom.ExclusionTypeIPAddress, dedicatedIP),
		approvedExcl(t, tenant, scopedom.ExclusionTypeIPRange, "198.51.100.1-198.51.100.20"),
	}})
	m, err := svc.LoadExclusionMatcher(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		a    *asset.Asset
		want bool
	}{
		{"name behind the excluded edge address", namedAsset(t, "shop.example.com", edgeIP), false},
		{"name behind an edge address in an excluded range", namedAsset(t, "blog.example.com", "104.16.2.9"), false},
		{"name on the excluded dedicated address", namedAsset(t, "vpn.example.com", dedicatedIP), true},
		{"name on edge and dedicated addresses", namedAsset(t, "mix.example.com", edgeIP, dedicatedIP), true},
		{"name on an address only a network holder calls edge", namedAsset(t, "media.example.com", heldIP), true},
	}
	for _, tc := range cases {
		if got := m.ExcludedAsset(tc.a); got != tc.want {
			t.Errorf("%s: excluded = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The edge address itself, and its host:port and URL forms, stay excluded.
	for _, v := range []string{edgeIP, edgeIP + ":443", "https://" + edgeIP + ":8443/x", "104.16.2.9"} {
		if !m.Excluded(v) {
			t.Errorf("%q not excluded", v)
		}
	}
	ipAsset, _ := asset.NewAsset(edgeIP, asset.AssetTypeIPAddress, asset.CriticalityLow)
	if !m.ExcludedAsset(ipAsset) {
		t.Fatal("the excluded edge address asset is not excluded")
	}
}

// The preview marks a pattern as a shared front end only when every address
// of it is one.
func TestPatternEdge(t *testing.T) {
	for _, tc := range []struct {
		typ     scopedom.ExclusionType
		pattern string
		edge    bool
	}{
		{scopedom.ExclusionTypeIPAddress, edgeIP, true},
		{scopedom.ExclusionTypeIPAddress, edgeIPv6, true},
		{scopedom.ExclusionTypeCIDR, "104.16.1.0/24", true},
		{scopedom.ExclusionTypeIPRange, "104.16.1.1-104.16.1.9", true},
		{scopedom.ExclusionTypeCIDR, "104.0.0.0/8", false}, // only overlaps a published range
		{scopedom.ExclusionTypeIPAddress, dedicatedIP, false},
		{scopedom.ExclusionTypeIPAddress, heldIP, false},
		{scopedom.ExclusionTypeDomain, "cdn.example.com", false},
	} {
		got := patternEdge(tc.typ, tc.pattern)
		if (got != nil) != tc.edge {
			t.Errorf("%s %s: edge = %+v, want %v", tc.typ, tc.pattern, got, tc.edge)
		}
		if got != nil && (got.Class != edgeaddr.Edge || got.Provider != "Cloudflare") {
			t.Errorf("%s: %+v", tc.pattern, got)
		}
	}
}
