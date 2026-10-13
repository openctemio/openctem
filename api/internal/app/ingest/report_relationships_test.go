package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func relTestAsset(t *testing.T, tenant shared.ID, name string, typ asset.AssetType) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithSubType(name, typ, "", asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	a.SetTenantID(tenant)
	return a
}

// Each CTIS relationship maps to the platform's direction, and only a pair
// the registry allows is planned.
func TestMapReportRelationship(t *testing.T) {
	tenant := shared.NewID()
	vm := relTestAsset(t, tenant, "vm01.example.com", asset.AssetTypeHost)
	esx := relTestAsset(t, tenant, "esx01.example.com", asset.AssetTypeHost)
	ip := relTestAsset(t, tenant, "192.0.2.10", asset.AssetTypeIPAddress)
	dom := relTestAsset(t, tenant, "example.com", asset.AssetTypeDomain)
	sub := relTestAsset(t, tenant, "www.example.com", asset.AssetTypeSubdomain)

	cases := []struct {
		name     string
		typ      ctis.RelationshipType
		from, to *asset.Asset
		wantType asset.RelationshipType
		wantSrc  *asset.Asset
		allowed  bool
	}{
		{"vm hosted by hypervisor", ctis.RelHostedBy, vm, esx, asset.RelTypeRunsOn, vm, true},
		{"address hosted by host", ctis.RelHostedBy, ip, vm, asset.RelTypeContains, vm, true},
		{"subdomain stored parent first", ctis.RelSubdomainOf, sub, dom, asset.RelTypeContains, dom, true},
		{"resolves to address", ctis.RelResolvesTo, sub, ip, asset.RelTypeResolvesTo, sub, true},
		{"host hosted by an address is not a pair", ctis.RelHostedBy, vm, ip, asset.RelTypeRunsOn, vm, false},
		{"domain resolves to a host is not a pair", ctis.RelResolvesTo, dom, vm, asset.RelTypeResolvesTo, dom, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, src, dst, ok := mapReportRelationship(tc.typ, tc.from, tc.to)
			if !ok || rt != tc.wantType || src != tc.wantSrc {
				t.Fatalf("got (%s, %v, ok=%v), want (%s, %s)", rt, src.Name(), ok, tc.wantType, tc.wantSrc.Name())
			}
			if got := edgeAllowed(rt, src, dst); got != tc.allowed {
				t.Fatalf("edgeAllowed = %v, want %v", got, tc.allowed)
			}
		})
	}
	if _, _, _, ok := mapReportRelationship("member_of", vm, esx); ok {
		t.Fatal("an unknown relationship type was mapped")
	}
}

// A report relationship is planned only when the report may change the
// edge's source, and never between unknown refs or an asset and itself.
func TestPlanReportRelationships_Gated(t *testing.T) {
	tenant := shared.NewID()
	vm := relTestAsset(t, tenant, "vm01.example.com", asset.AssetTypeHost)
	esx := relTestAsset(t, tenant, "esx01.example.com", asset.AssetTypeHost)
	stored := map[string]*asset.Asset{"vm": vm, "esx": esx}
	report := &ctis.Report{Relationships: []ctis.Relationship{
		{Type: ctis.RelHostedBy, FromRef: "vm", ToRef: "esx"},
		{Type: ctis.RelHostedBy, FromRef: "vm", ToRef: "missing"},
		{Type: ctis.RelHostedBy, FromRef: "vm", ToRef: "vm"},
	}}
	if got := planReportRelationships(report, stored, func(shared.ID) bool { return true }); len(got) != 1 ||
		got[0].src != vm || got[0].dst != esx || got[0].relType != asset.RelTypeRunsOn {
		t.Fatalf("planned %+v, want one vm runs_on esx", got)
	}
	if got := planReportRelationships(report, stored, func(shared.ID) bool { return false }); len(got) != 0 {
		t.Fatalf("planned %d edges for a source the report may not change", len(got))
	}
}

// Placement edges link only assets of the tenant: an address or a
// hypervisor host of another tenant under the same name is never linked.
func TestPlanPlacementEdges_TenantOnly(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	vm := relTestAsset(t, tenant, "vm01.example.com", asset.AssetTypeHost)
	report := &ctis.Report{Assets: []ctis.Asset{{ID: "vm", Type: ctis.AssetTypeHost, Value: "vm01.example.com",
		Properties: ctis.Properties{"esxi_host": "esx01.example.com", "ip_addresses": []any{"192.0.2.10"}}}}}
	stored := map[string]*asset.Asset{"vm": vm}
	all := func(shared.ID) bool { return true }

	foreign := map[string]*asset.Asset{
		"esx01.example.com": relTestAsset(t, other, "esx01.example.com", asset.AssetTypeHost),
		"192.0.2.10":        relTestAsset(t, other, "192.0.2.10", asset.AssetTypeIPAddress),
	}
	if got := planPlacementEdges(tenant, report, stored, foreign, all); len(got) != 0 {
		t.Fatalf("linked %d assets of another tenant", len(got))
	}
	own := map[string]*asset.Asset{
		"esx01.example.com": relTestAsset(t, tenant, "esx01.example.com", asset.AssetTypeHost),
		"192.0.2.10":        relTestAsset(t, tenant, "192.0.2.10", asset.AssetTypeIPAddress),
	}
	if got := planPlacementEdges(tenant, report, stored, own, all); len(got) != 2 {
		t.Fatalf("planned %d edges, want runs_on and contains", len(got))
	}
	if got := planPlacementEdges(tenant, report, stored, own, func(shared.ID) bool { return false }); len(got) != 0 {
		t.Fatalf("planned %d edges for a host the report may not change", len(got))
	}
}
