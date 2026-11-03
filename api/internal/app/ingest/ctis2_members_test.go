package ingest

import (
	"reflect"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// dirtyProps is a producer's properties bag full of keys the receiver used
// to read meaning from.
func dirtyProps() ctis.Properties {
	return ctis.Properties{
		"sub_type": "x", "kind": "Namespace", "root_domain": "evil.example", "exposure": "private",
		"aliases": []any{"a"}, "technologies": []any{"nginx"}, "zone_visibility": "private", "last_seen": "2020-01-01T00:00:00Z",
		asset.PropKeyDiscoverySource: "manual", asset.PropKeyDiscoveryTool: "x", asset.PropKeyWebContent: map[string]any{"a": 1},
		PropImportScope: "x", "candidate_exposure": "x", "candidate_unverified": true,
		"sans": []any{"a.example.com"}, "subject_cn": "a", "owner": "boss", "http_posture": map[string]any{"hsts": true},
		"status_code": 200, "title": "t", "url": "https://x", "ip_addresses": []any{"198.51.100.9"}, "ips": []any{"198.51.100.8"},
		"harmless": "kept",
	}
}

// properties carry no meaning for an external producer: every key the
// receiver used to interpret is dropped, any other key stays as an opaque
// display attribute.
func TestAdoptCTIS2Members_StripsInterpretedProperties(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomainName, Value: "api.example.com", Properties: dirtyProps()}}}
	adoptCTIS2Members(r, false)
	got := r.Assets[0].Properties
	for _, k := range interpretedPropertyKeys {
		if _, ok := got[k]; ok {
			t.Errorf("interpreted key %q survived the strip", k)
		}
	}
	for _, k := range asset.AddressPropertyKeys() {
		if _, ok := got[k]; ok {
			t.Errorf("address key %q survived the strip", k)
		}
	}
	if got["harmless"] != "kept" {
		t.Errorf("an uninterpreted key was dropped: %v", got)
	}
}

// A report the platform built itself keeps its own properties.
func TestAdoptCTIS2Members_ServerSideKeepsProperties(t *testing.T) {
	r := &ctis.Report{Assets: []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomainName, Value: "api.example.com", Properties: dirtyProps()}}}
	adoptCTIS2Members(r, true)
	got := r.Assets[0].Properties
	for _, k := range []string{"sub_type", "root_domain", asset.PropKeyDiscoverySource, "sans", "ip_addresses"} {
		if _, ok := got[k]; !ok {
			t.Errorf("server-side report lost %q", k)
		}
	}
	adoptCTIS2Members(nil, false)
}

// ip_addresses of a name come from its A and AAAA records and from the
// ip_address assets it resolves_to: canonical, deduplicated; a producer's own
// property is replaced, other record types and other asset types give none.
func TestAdoptCTIS2Members_IPAddressesFromDNSAndResolvesTo(t *testing.T) {
	r := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "d", Type: ctis.AssetTypeDomainName, Value: "www.example.com",
				Properties: ctis.Properties{"ip_addresses": []any{"6.6.6.6"}},
				Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{DNSRecords: []ctis.DNSRecord{
					{Type: "A", Name: "www.example.com", Value: "192.0.2.10"},
					{Type: "AAAA", Name: "www.example.com", Value: "2001:db8:0:0:0:0:0:1"},
					{Type: "CNAME", Name: "www.example.com", Value: "edge.example.net"},
					{Type: "A", Name: "www.example.com", Value: "192.0.2.10"}, // duplicate
					{Type: "A", Name: "www.example.com", Value: "not-an-ip"},
				}}}},
			{ID: "ip1", Type: ctis.AssetTypeIPAddress, Value: "192.0.2.77"},
			{ID: "ip2", Type: ctis.AssetTypeIPAddress, Value: "192.0.2.10"},
			{ID: "h", Type: ctis.AssetTypeHost, Value: "web01"},
		},
		Relationships: []ctis.Relationship{
			{Type: ctis.RelResolvesTo, FromRef: "d", ToRef: "ip1"},
			{Type: ctis.RelResolvesTo, FromRef: "d", ToRef: "ip2"}, // already from the A record
			{Type: ctis.RelResolvesTo, FromRef: "h", ToRef: "ip1"}, // not a name: no addresses
		},
	}
	adoptCTIS2Members(r, false)
	got, _ := r.Assets[0].Properties[asset.PropKeyIPAddresses].([]string)
	want := []string{"192.0.2.10", "2001:db8::1", "192.0.2.77"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ip_addresses = %v, want %v", got, want)
	}
	if _, ok := r.Assets[3].Properties[asset.PropKeyIPAddresses]; ok {
		t.Fatal("a host got ip_addresses from a resolves_to edge")
	}
}

// root_domain of a subdomain comes only from a subdomain_of relationship to a
// domain_name of the document: never from the public suffix list, never from
// a property, never on a name that is not a subdomain.
func TestAdoptCTIS2Members_RootDomainOnlyFromSubdomainOf(t *testing.T) {
	r := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "root", Type: ctis.AssetTypeDomainName, Value: "example.com"},
			{ID: "withrel", Type: ctis.AssetTypeDomainName, Value: "api.example.com", Properties: ctis.Properties{"root_domain": "evil.example"}},
			{ID: "norel", Type: ctis.AssetTypeDomainName, Value: "www.example.com", Properties: ctis.Properties{"root_domain": "evil.example"}},
			{ID: "apex", Type: ctis.AssetTypeDomainName, Value: "example.org"},
			{ID: "h", Type: ctis.AssetTypeHost, Value: "web01"},
		},
		Relationships: []ctis.Relationship{
			{Type: ctis.RelSubdomainOf, FromRef: "withrel", ToRef: "root"},
			{Type: ctis.RelSubdomainOf, FromRef: "apex", ToRef: "root"}, // an apex is not a subdomain
			{Type: ctis.RelSubdomainOf, FromRef: "h", ToRef: "root"},    // not a DNS name
			{Type: ctis.RelSubdomainOf, FromRef: "norel", ToRef: "missing"},
		},
	}
	adoptCTIS2Members(r, false)
	if got := r.Assets[1].Properties["root_domain"]; got != "example.com" {
		t.Errorf("root_domain = %v, want example.com (from subdomain_of, not the producer's property)", got)
	}
	for _, i := range []int{0, 2, 3, 4} {
		if v, ok := r.Assets[i].Properties["root_domain"]; ok {
			t.Errorf("asset %s got root_domain %v without a subdomain_of edge to a document domain", r.Assets[i].ID, v)
		}
	}
}

// import_scope, candidate_exposure, candidate_unverified and web_content come
// from the asset's io.openctem extension.
func TestAdoptCTIS2Members_ExtensionsToProperties(t *testing.T) {
	a := ctis.Asset{ID: "a", Type: ctis.AssetTypeDomainName, Value: "example.com", Properties: ctis.Properties{PropImportScope: "forged"}}
	a.Extensions.Set(ctis.OpenCTEMNamespace, PropImportScope, "program")
	a.Extensions.Set(ctis.OpenCTEMNamespace, "candidate_exposure", "public")
	a.Extensions.Set(ctis.OpenCTEMNamespace, "candidate_unverified", true)
	a.Extensions.Set(ctis.OpenCTEMNamespace, asset.PropKeyWebContent, map[string]any{"k": "v"})
	a.Extensions.Set("com.other", PropImportScope, "other-namespace")
	r := &ctis.Report{Assets: []ctis.Asset{a}}
	adoptCTIS2Members(r, false)
	p := r.Assets[0].Properties
	if p[PropImportScope] != "program" || p["candidate_exposure"] != "public" || p["candidate_unverified"] != true {
		t.Fatalf("properties = %v", p)
	}
	if _, ok := p[asset.PropKeyWebContent].(map[string]any); !ok {
		t.Fatalf("web_content = %v", p[asset.PropKeyWebContent])
	}
}

// A finding that names a rule of the document fills its rule name from it;
// its own rule_id is never replaced and an own name is kept.
func TestFillFromRules(t *testing.T) {
	r := &ctis.Report{
		Rules: []ctis.Rule{
			{ID: "r1", RuleID: "tool-rule-1", Name: "SQL injection", ShortDescription: "short", FullDescription: "full"},
			{ID: "r2", RuleID: "tool-rule-2", Name: "Other", ShortDescription: "short2"},
		},
		Findings: []ctis.Finding{
			{RuleRef: "r1", RuleID: "finding-own-id"},
			{RuleRef: "r1", RuleID: "x", RuleName: "own name", Description: "own description"},
			{RuleRef: "r2"},
			{RuleRef: "nope", RuleID: "y"},
		},
	}
	fillFromRules(r)
	f := r.Findings
	if f[0].RuleName != "SQL injection" || f[0].Description != "full" || f[0].RuleID != "finding-own-id" {
		t.Errorf("finding 0 = %+v (rule_id must stay the finding's own)", f[0])
	}
	if f[1].RuleName != "own name" || f[1].Description != "own description" {
		t.Errorf("finding 1 lost its own text: %+v", f[1])
	}
	if f[2].RuleName != "Other" || f[2].Description != "short2" || f[2].RuleID != "" {
		t.Errorf("finding 2 = %+v (short description when no full one; rule_id left empty)", f[2])
	}
	if f[3].RuleName != "" {
		t.Errorf("finding 3 named an unknown rule: %+v", f[3])
	}
	fillFromRules(&ctis.Report{Findings: []ctis.Finding{{RuleRef: "r1"}}}) // no rules: no-op
}
