package ctemid

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
)

func TestMap(t *testing.T) {
	sys := func(typ asset.AssetType, scope asset.Scope, internet bool) *Asset {
		return &Asset{Type: typ, Scope: scope, InternetFacing: internet}
	}
	cred := func(src, cls string) map[string]any {
		return map[string]any{"source_type": src, "classification": cls}
	}
	tests := []struct {
		name  string
		in    Input
		want  Code
		basis Basis
	}{
		// Lookalike domains.
		{"homoglyph", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": "homoglyph"}}, CodeDOM2, BasisLookalikeTechnique},
		{"homoglyph typed value", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": lookalike.TechHomoglyph}}, CodeDOM2, BasisLookalikeTechnique},
		{"omission", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": "omission"}}, CodeDOM1, BasisLookalikeTechnique},
		{"tld swap, case and space", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": " TLD "}}, CodeDOM1, BasisLookalikeTechnique},
		{"lookalike unknown technique", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": "combo"}}, "", ""},
		{"lookalike no technique", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{}}, "", ""},
		{"lookalike technique not a string", Input{EventType: exposure.EventTypeLookalikeDomain, Details: map[string]any{"technique": 3}}, "", ""},

		// Leaked credentials.
		{"breach, internal", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("data_breach", "internal")}, CodeCRD1, BasisCredentialDump},
		{"paste site, internal", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("paste_site", "internal")}, CodeCRD1, BasisCredentialDump},
		{"dark web, vendor", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("dark_web", "vendor")}, CodeCRD2, BasisCredentialDump},
		{"forum, vendor, upper case", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("UNDERGROUND_FORUM", "Vendor")}, CodeCRD2, BasisCredentialDump},
		{"breach, partner", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("data_breach", "partner")}, "", ""},
		{"breach, unknown", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("data_breach", "unknown")}, "", ""},
		{"breach, unclassified", Input{EventType: exposure.EventTypeCredentialLeaked, Details: map[string]any{"source_type": "data_breach"}}, "", ""},
		{"malware log, internal (infected device owner unknown)", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("malware", "internal")}, "", ""},
		{"code repository, internal", Input{EventType: exposure.EventTypeCredentialLeaked, Details: cred("code_repository", "internal")}, "", ""},
		{"web page secret (no source)", Input{EventType: exposure.EventTypeCredentialLeaked, Details: map[string]any{"secret_kind": "token"}}, "", ""},

		// Public repositories.
		{"repo on vendor asset", Input{EventType: exposure.EventTypeRepoPublic, Asset: sys(asset.AssetTypeRepository, asset.ScopeVendor, false)}, CodeSRC3, BasisAssetScope},
		{"repo on default-scope asset", Input{EventType: exposure.EventTypeRepoPublic, Asset: sys(asset.AssetTypeRepository, asset.ScopeInternal, false)}, "", ""},
		{"repo on shadow asset", Input{EventType: exposure.EventTypeRepoPublic, Asset: sys(asset.AssetTypeRepository, asset.ScopeShadow, false)}, "", ""},
		{"repo without asset", Input{EventType: exposure.EventTypeRepoPublic}, "", ""},

		// Systems reachable from the internet.
		{"vendor system", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeHost, asset.ScopeVendor, true)}, CodeEXP6, BasisAssetScope},
		{"vendor firewall stays vendor", Input{EventType: exposure.EventTypeServiceDetected, Asset: sys(asset.AssetTypeFirewall, asset.ScopeVendor, true)}, CodeEXP6, BasisAssetScope},
		{"shadow system", Input{EventType: exposure.EventTypeWebInterfaceExposed, Asset: sys(asset.AssetTypeWebsite, asset.ScopeShadow, true)}, CodeEXP5, BasisAssetScope},
		{"firewall", Input{EventType: exposure.EventTypeServiceDetected, Asset: sys(asset.AssetTypeFirewall, asset.ScopeInternal, true)}, CodeEXP3, BasisAssetType},
		{"cloud firewall is a gateway", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeFirewall, asset.ScopeCloud, true)}, CodeEXP3, BasisAssetType},
		{"firewall as the stored pair", Input{EventType: exposure.EventTypeServiceDetected, Asset: &Asset{Type: asset.AssetTypeNetwork, SubType: "firewall", Scope: asset.ScopeInternal, InternetFacing: true}}, CodeEXP3, BasisAssetType},
		{"network router is not a gateway", Input{EventType: exposure.EventTypeServiceDetected, Asset: &Asset{Type: asset.AssetTypeNetwork, SubType: "router", Scope: asset.ScopeInternal, InternetFacing: true}}, "", ""},
		{"cloud api", Input{EventType: exposure.EventTypeAPIExposed, Asset: sys(asset.AssetTypeAPI, asset.ScopeCloud, true)}, CodeEXP4, BasisAssetScope},
		{"cloud mcp server", Input{EventType: exposure.EventTypeMCPServerExposed, Asset: sys(asset.AssetTypeService, asset.ScopeCloud, true)}, CodeEXP4, BasisAssetScope},
		{"partner system", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeHost, asset.ScopePartner, true)}, "", ""},
		{"default-scope host", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeHost, asset.ScopeInternal, true)}, "", ""},
		{"external host", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeHost, asset.ScopeExternal, true)}, "", ""},
		{"vendor system not internet-facing", Input{EventType: exposure.EventTypePortOpen, Asset: sys(asset.AssetTypeHost, asset.ScopeVendor, false)}, "", ""},
		{"system without asset", Input{EventType: exposure.EventTypePortOpen}, "", ""},

		// Classes the catalog has no code for.
		{"port closed", Input{EventType: exposure.EventTypePortClosed, Asset: sys(asset.AssetTypeHost, asset.ScopeVendor, true)}, "", ""},
		{"expired certificate", Input{EventType: exposure.EventTypeCertificateExpired, Asset: sys(asset.AssetTypeHost, asset.ScopeCloud, true)}, "", ""},
		{"misconfiguration", Input{EventType: exposure.EventTypeMisconfiguration, Asset: sys(asset.AssetTypeHost, asset.ScopeShadow, true)}, "", ""},
		{"identity", Input{EventType: exposure.EventTypeIdentityMFAGap}, "", ""},
		{"custom", Input{EventType: exposure.EventTypeCustom, Details: map[string]any{"technique": "homoglyph"}}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Map(tt.in)
			if tt.want == "" {
				if ok {
					t.Fatalf("got %+v, want no code", got)
				}
				return
			}
			if !ok || got.Code != tt.want || got.Basis != tt.basis {
				t.Fatalf("got %+v (%v), want %s by %s", got, ok, tt.want, tt.basis)
			}
		})
	}
}

// Every event type answers without panicking, and any code returned is one
// of the catalog's.
func TestMapEveryEventTypeYieldsKnownCodeOrNone(t *testing.T) {
	scopes := []asset.Scope{asset.ScopeInternal, asset.ScopeExternal, asset.ScopeCloud, asset.ScopePartner, asset.ScopeVendor, asset.ScopeShadow}
	for _, et := range exposure.AllEventTypes() {
		for _, sc := range scopes {
			m, ok := Map(Input{EventType: et, Details: map[string]any{"technique": "homoglyph", "source_type": "data_breach", "classification": "internal"},
				Asset: &Asset{Type: asset.AssetTypeFirewall, Scope: sc, InternetFacing: true}})
			if ok && !m.Code.Known() {
				t.Fatalf("%s/%s: unknown code %s", et, sc, m.Code)
			}
		}
	}
}

func TestCodes(t *testing.T) {
	codes := Codes()
	if len(codes) != 29 {
		t.Fatalf("catalog %s has 29 codes, got %d", CatalogVersion, len(codes))
	}
	seen := map[Code]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate %s", c)
		}
		seen[c] = true
	}
	if got := CodeDOM2.URL(); got != "https://ctem.org/docs/ctem-dom-2" {
		t.Fatalf("url %q", got)
	}
	if Code("CTEM-XYZ-1").Known() || Code("CTEM-XYZ-1").URL() != "" {
		t.Fatal("unknown code accepted")
	}
}
