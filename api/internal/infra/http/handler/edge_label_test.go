package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

func edgeAsset(t *testing.T, name string, typ asset.AssetType, props map[string]any) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetProperties(props)
	return a
}

func TestAssetEdgeLabel(t *testing.T) {
	for _, tc := range []struct {
		name            string
		a               *asset.Asset
		class, provider string
		address         string
		none            bool
	}{
		{name: "cloudflare edge address", a: edgeAsset(t, "104.16.1.1", asset.AssetTypeIPAddress, nil),
			class: "edge", provider: "Cloudflare", address: "104.16.1.1"},
		{name: "address whose record names a CDN", a: edgeAsset(t, "198.51.100.1", asset.AssetTypeIPAddress, map[string]any{"cdn": "cloudfront"}),
			class: "edge", provider: "cloudfront", address: "198.51.100.1"},
		{name: "akamai by network holder", a: edgeAsset(t, "198.51.100.2", asset.AssetTypeIPAddress, map[string]any{"asn_org": "Akamai Technologies, Inc."}),
			class: "edge", provider: "Akamai", address: "198.51.100.2"},
		{name: "cloud static address is not labeled", a: edgeAsset(t, "198.51.100.3", asset.AssetTypeIPAddress, map[string]any{"asn_org": "AMAZON-02"}), none: true},
		{name: "own address", a: edgeAsset(t, "203.0.113.9", asset.AssetTypeIPAddress, nil), none: true},
		{name: "name behind cloudfront", a: edgeAsset(t, "app.acme.example", asset.AssetTypeSubdomain, map[string]any{"cname_target": "d1.cloudfront.net"}),
			class: "edge", provider: "Amazon CloudFront"},
		{name: "name on cloudflare addresses", a: edgeAsset(t, "api.acme.example", asset.AssetTypeSubdomain, map[string]any{"ip_addresses": []any{"104.16.1.1"}}),
			class: "edge", provider: "Cloudflare"},
		{name: "name served directly", a: edgeAsset(t, "vpn.acme.example", asset.AssetTypeSubdomain, map[string]any{"ip_addresses": []any{"203.0.113.9"}}), none: true},
		{name: "web service through a CDN", a: edgeAsset(t, "https://app.acme.example", asset.AssetTypeService, map[string]any{"cdn": "cloudflare"}),
			class: "edge", provider: "Cloudflare"},
	} {
		got := assetEdgeLabel(tc.a)
		if tc.none {
			if got != nil {
				t.Errorf("%s: got %+v, want no label", tc.name, got)
			}
			continue
		}
		if got == nil || got.Class != tc.class || got.Provider != tc.provider || got.Address != tc.address {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
	if assetEdgeLabel(nil) != nil {
		t.Error("nil asset labeled")
	}
	if r := toAssetResponse(edgeAsset(t, "104.16.1.1", asset.AssetTypeIPAddress, nil)); r.Edge == nil {
		t.Error("asset response carries no edge label")
	}
}

func TestScopeEntryEdgeLabel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typ      scopedom.TargetType
		pattern  string
		provider string
		address  string
	}{
		{"edge address entry", scopedom.TargetTypeIPAddress, "104.16.1.1", "Cloudflare", "104.16.1.1"},
		{"edge cidr entry", scopedom.TargetTypeCIDR, "151.101.0.0/24", "Fastly", "151.101.0.0/24"},
		{"edge range entry", scopedom.TargetTypeIPRange, "104.16.1.1-104.16.1.9", "Cloudflare", "104.16.1.1-104.16.1.9"},
		{"cidr wider than the edge range", scopedom.TargetTypeCIDR, "104.0.0.0/8", "", ""},
		{"own cidr", scopedom.TargetTypeCIDR, "203.0.113.0/24", "", ""},
		{"hosting name", scopedom.TargetTypeDomain, "*.acme.github.io", "GitHub", ""},
		{"own domain", scopedom.TargetTypeDomain, "acme.example", "", ""},
		{"repository", scopedom.TargetTypeRepository, "github.com/acme/app", "", ""},
	} {
		got := scopeEntryEdgeLabel(tc.typ, tc.pattern)
		if tc.provider == "" {
			if got != nil {
				t.Errorf("%s: got %+v, want none", tc.name, got)
			}
			continue
		}
		if got == nil || got.Provider != tc.provider || got.Address != tc.address {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
}
