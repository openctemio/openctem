package asset

import (
	"slices"
	"testing"
)

// Probe for RFC-042 §6.3.8 Q2: exposure inference compared against website
// and api, which are never stored, so a stored (application, website) was
// never internet-facing by nature.
func TestDefaultExposure_StoredPairs(t *testing.T) {
	cases := []struct {
		typ  AssetType
		sub  string
		want Exposure
	}{
		{AssetTypeApplication, "website", ExposurePublic},
		{AssetTypeApplication, "website", ExposurePublic},
		// O3: web_application is no stored sub-type any more
		{AssetTypeApplication, "", ExposureUnknown},
		{AssetTypeApplication, "api", ExposurePublic},
		{AssetTypeApplication, "mobile_app", ExposureUnknown},
		{AssetTypeApplication, "", ExposureUnknown},
		{AssetTypeDomain, "", ExposurePublic},
		{AssetTypeSubdomain, "", ExposurePublic},
		{AssetTypeCertificate, "", ExposurePublic},
		{AssetTypeHost, "", ExposureUnknown},
		{AssetTypeWebsite, "", ExposurePublic}, // a legacy row stored under the alias name
		{"no_such_type", "", ExposureUnknown},
	}
	for _, c := range cases {
		if got := DefaultExposure(c.typ, c.sub); got != c.want {
			t.Errorf("DefaultExposure(%s, %q) = %s, want %s", c.typ, c.sub, got, c.want)
		}
	}
}

// Probe for Q2 (scanner mappings): only alias names were mapped for url, so
// every stored application was "skipped" by url scanners.
func TestScannableBy_StoredPairs(t *testing.T) {
	cases := []struct {
		typ  AssetType
		sub  string
		want []string
	}{
		{AssetTypeApplication, "website", []string{"url"}},
		{AssetTypeApplication, "", []string{"url"}},
		{AssetTypeApplication, "api", []string{"url", "api"}},
		{AssetTypeApplication, "mobile_app", []string{"mobile"}},
		{AssetTypeService, "http", []string{"url", "service", "port"}},
		{AssetTypeService, "discovered_url", []string{"url"}},
		{AssetTypeKubernetes, "cluster", []string{"kubernetes"}}, // alias without a list inherits
		{AssetTypeKubernetes, "workload", []string{"kubernetes"}},
		{AssetTypeNetwork, "router", []string{"network"}},
		{AssetTypeIdentity, "", []string{}},
		{AssetTypeUnclassified, "", []string{}},
	}
	for _, c := range cases {
		got := ScannableBy(c.typ, c.sub)
		if got == nil {
			got = []string{}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("ScannableBy(%s, %q) = %v, want %v", c.typ, c.sub, got, c.want)
		}
	}
}

// The registry must keep every type/target pair the seeded
// target_asset_type_mappings rows declared (000060/000234), re-keyed to the
// stored pair, so making compatibility enforcing (O6) never refuses a pair
// that was compatible before.
func TestScannableBy_CoversTheSeededTargetMappings(t *testing.T) {
	legacy := map[string][]string{
		"api":           {"api"},
		"certificate":   {"certificate"},
		"cloud_account": {"cloud_account"},
		"compute":       {"compute"},
		"container":     {"container", "container_registry"},
		"database":      {"database", "data_store"},
		"domain":        {"domain", "subdomain"},
		"file":          {"repository"},
		"host":          {"host", "ip_address", "compute"},
		"ip":            {"ip_address", "host"},
		"kubernetes":    {"kubernetes_cluster", "kubernetes_namespace"},
		"mobile":        {"mobile_app"},
		"network":       {"network", "subnet", "vpc", "firewall", "load_balancer"},
		"port":          {"open_port", "service"},
		"repository":    {"repository"},
		"serverless":    {"serverless"},
		"service":       {"service", "open_port", "http_service"},
		"storage":       {"storage", "s3_bucket"},
		"url":           {"website", "web_application", "api", "http_service", "discovered_url"},
	}
	for target, types := range legacy {
		for _, name := range types {
			r, err := ResolveInputType(name, "")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(ScannableBy(r.Type, r.SubType), target) {
				t.Errorf("%s (stored %s/%s) lost target %q", name, r.Type, r.SubType, target)
			}
		}
	}
}

func TestCanonicalPair(t *testing.T) {
	cases := []struct {
		typ  AssetType
		sub  string
		want TypeRef
	}{
		{AssetTypeWebsite, "", TypeRef{Type: AssetTypeApplication, SubType: "website"}},
		{AssetTypeFirewall, "", TypeRef{Type: AssetTypeNetwork, SubType: "firewall"}},
		{AssetTypeApplication, "api", TypeRef{Type: AssetTypeApplication, SubType: "api"}},
		{AssetTypeHost, "", TypeRef{Type: AssetTypeHost}},
	}
	for _, c := range cases {
		if got := CanonicalPair(c.typ, c.sub); got != c.want {
			t.Errorf("CanonicalPair(%s, %q) = %v, want %v", c.typ, c.sub, got, c.want)
		}
	}
}

// Probe for Q6: the constraints resolved to alias names, so no stored
// application, identity or kubernetes asset matched any rule.
func TestRelationshipAllowed_StoredPairs(t *testing.T) {
	cases := []struct {
		rel      RelationshipType
		src, tgt TypeRef
		want     bool
	}{
		{RelTypeRunsOn, TypeRef{Type: AssetTypeApplication, SubType: "website"}, TypeRef{Type: AssetTypeHost}, true},
		{RelTypeRunsOn, TypeRef{Type: AssetTypeApplication, SubType: "api"}, TypeRef{Type: AssetTypeKubernetes, SubType: "workload"}, true},
		{RelTypeAuthenticatesTo, TypeRef{Type: AssetTypeApplication, SubType: "website"}, TypeRef{Type: AssetTypeIdentity, SubType: "identity_provider"}, true},
		{RelTypeAuthenticatesTo, TypeRef{Type: AssetTypeApplication, SubType: "website"}, TypeRef{Type: AssetTypeIdentity, SubType: "iam_user"}, false},
		{RelTypeRunsOn, TypeRef{Type: AssetTypeWebsite}, TypeRef{Type: AssetTypeHost}, true}, // legacy alias row
		{RelTypeContains, TypeRef{Type: AssetTypeService}, TypeRef{Type: AssetTypeService}, false},
		{RelTypeRunsOn, TypeRef{Type: AssetTypeHost}, TypeRef{Type: AssetTypeApplication, SubType: "website"}, false},
		// an application whose kind was never recorded matches the rules of
		// every kind; a different recorded kind does not
		{RelTypeRunsOn, TypeRef{Type: AssetTypeApplication}, TypeRef{Type: AssetTypeHost}, true},
		{RelTypeRunsOn, TypeRef{Type: AssetTypeApplication, SubType: "mobile_app"}, TypeRef{Type: AssetTypeHost}, false},
		{RelTypeAuthenticatesTo, TypeRef{Type: AssetTypeApplication, SubType: "website"}, TypeRef{Type: AssetTypeIdentity}, true},
	}
	for _, c := range cases {
		if got := RelationshipAllowed(c.rel, c.src, c.tgt); got != c.want {
			t.Errorf("RelationshipAllowed(%s, %v, %v) = %v, want %v", c.rel, c.src, c.tgt, got, c.want)
		}
	}
}

// No relationship rule may name an alias type: every peer and every rule
// owner is a stored (core type, declared sub-type) pair.
func TestRelationshipRules_UseStoredPairsOnly(t *testing.T) {
	for _, d := range registryTypes {
		if d.AliasOf != nil {
			if len(d.Relationships.Out)+len(d.Relationships.In) > 0 {
				t.Errorf("alias %s carries relationship rules", d.Type)
			}
			continue
		}
		for _, rules := range [][]RelationshipRule{d.Relationships.Out, d.Relationships.In} {
			for _, r := range rules {
				if !IsValidSubType(d.Type, r.SubType) {
					t.Errorf("%s %s: own sub-type %q not declared", d.Type, r.Relationship, r.SubType)
				}
				for _, p := range r.Peers {
					if !p.Type.IsStored() || !IsValidSubType(p.Type, p.SubType) {
						t.Errorf("%s %s: peer %v is not a stored pair", d.Type, r.Relationship, p)
					}
				}
			}
		}
	}
}

func TestTypeNameMatches(t *testing.T) {
	web := TypeRef{Type: AssetTypeApplication, SubType: "website"}
	cases := []struct {
		name string
		ref  TypeRef
		want bool
	}{
		{"website", web, true},
		{"application", web, true},
		{"api", web, false},
		{"website", TypeRef{Type: AssetTypeApplication}, true}, // kind never recorded
		{"s3_bucket", TypeRef{Type: AssetTypeStorage, SubType: "bucket"}, true},
		{"subnet", TypeRef{Type: AssetTypeNetwork, SubType: "vpc"}, false},
		{"", web, false},
		{"bogus", web, false},
	}
	for _, c := range cases {
		if got := TypeNameMatches(c.name, c.ref); got != c.want {
			t.Errorf("TypeNameMatches(%q, %+v) = %v, want %v", c.name, c.ref, got, c.want)
		}
	}
}
