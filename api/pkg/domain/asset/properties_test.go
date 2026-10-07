package asset

import (
	"slices"
	"sort"
	"testing"
)

func sortedStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, x...)
	}
	sort.Strings(out)
	return out
}

// Every spelling of "the asset's addresses" folds into ip_addresses, once.
func TestNormalizeProperties_FoldsAddressSynonyms(t *testing.T) {
	props := map[string]any{
		"ip":           "203.0.113.1",
		"ips":          []any{"203.0.113.2", "203.0.113.1"},
		"resolved_ips": "203.0.113.3, 203.0.113.4;2001:DB8::1",
		"resolved_ip":  "203.0.113.5",
		"addresses":    []string{"203.0.113.6", "not-an-address"},
		"ip_address":   "203.0.113.7",
		"ip_addresses": []any{"203.0.113.8"},
		"title":        "kept",
	}
	NormalizeProperties(props)
	want := []string{"2001:db8::1", "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4",
		"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8"}
	if got := sortedStrings(props[PropKeyIPAddresses]); !slices.Equal(got, want) {
		t.Fatalf("ip_addresses = %v, want %v", got, want)
	}
	for _, k := range []string{"ip", "ips", "resolved_ips", "resolved_ip", "addresses", "ip_address"} {
		if _, ok := props[k]; ok {
			t.Errorf("synonym %q left in place", k)
		}
	}
	if props["title"] != "kept" {
		t.Errorf("an unrelated key changed: %v", props["title"])
	}
	// Idempotent.
	before := sortedStrings(props[PropKeyIPAddresses])
	NormalizeProperties(props)
	if got := sortedStrings(props[PropKeyIPAddresses]); !slices.Equal(got, before) {
		t.Errorf("second pass changed ip_addresses: %v", got)
	}
}

// The CTIS technical ip_address block is an object: its address joins
// ip_addresses, the block itself stays.
func TestNormalizeProperties_ObjectSynonymStays(t *testing.T) {
	block := map[string]any{"address": "198.51.100.4", "asn": 64500}
	props := map[string]any{"ip_address": block}
	NormalizeProperties(props)
	if _, ok := props["ip_address"].(map[string]any); !ok {
		t.Fatalf("technical block removed: %v", props)
	}
	if got := sortedStrings(props[PropKeyIPAddresses]); !slices.Equal(got, []string{"198.51.100.4"}) {
		t.Errorf("ip_addresses = %v", got)
	}
}

func TestNormalizeProperties_OtherSynonyms(t *testing.T) {
	props := map[string]any{"nameserver": "ns1.example.com", "nameservers": []any{"ns2.example.com"},
		"technology": "nginx", "san": "www.example.com"}
	NormalizeProperties(props)
	if got := sortedStrings(props["nameservers"]); !slices.Equal(got, []string{"ns1.example.com", "ns2.example.com"}) {
		t.Errorf("nameservers = %v", got)
	}
	if got := sortedStrings(props["technologies"]); !slices.Equal(got, []string{"nginx"}) {
		t.Errorf("technologies = %v", got)
	}
	if got := sortedStrings(props["sans"]); !slices.Equal(got, []string{"www.example.com"}) {
		t.Errorf("sans = %v", got)
	}
	for _, k := range []string{"nameserver", "technology", "san"} {
		if _, ok := props[k]; ok {
			t.Errorf("synonym %q left in place", k)
		}
	}
}

// Nothing to fold: the map is left as it is (no empty canonical key).
func TestNormalizeProperties_NoSynonyms(t *testing.T) {
	props := map[string]any{"title": "x"}
	NormalizeProperties(props)
	if len(props) != 1 {
		t.Errorf("props = %v", props)
	}
	if NormalizeProperties(nil) != nil {
		t.Error("nil map not kept nil")
	}
	// A synonym holding nothing usable goes, and leaves no empty key.
	props = map[string]any{"ip": "not-an-address"}
	NormalizeProperties(props)
	if len(props) != 0 {
		t.Errorf("props = %v", props)
	}
}

// Readers see a row written before the normalisation too, without changing it.
func TestIPAddresses_ReadsLegacyRowsWithoutWriting(t *testing.T) {
	props := map[string]any{"ip": "192.0.2.1", "ip_addresses": []string{"192.0.2.2"}}
	got := IPAddresses(props)
	sort.Strings(got)
	if !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("IPAddresses = %v", got)
	}
	if _, ok := props["ip"]; !ok {
		t.Error("a read changed the map")
	}
	if IPAddresses(nil) != nil {
		t.Error("nil props")
	}
}

func TestAddIPAddress(t *testing.T) {
	props := map[string]any{"ip": "192.0.2.1"}
	AddIPAddress(props, "192.0.2.2")
	AddIPAddress(props, "192.0.2.1")
	AddIPAddress(props, "nope")
	if got := sortedStrings(props[PropKeyIPAddresses]); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("ip_addresses = %v", got)
	}
	if _, ok := props["ip"]; ok {
		t.Error("synonym not folded")
	}
}

// A port belongs on a service (or a database); on a domain it is misplaced.
func TestMisplacedPropertyKeys(t *testing.T) {
	props := map[string]any{"port": 443, "status_code": 200, "title": "x", "ip_addresses": []any{"192.0.2.1"}}
	if got := MisplacedPropertyKeys(AssetTypeDomain, "", props); !slices.Equal(got, []string{"port", "status_code"}) {
		t.Errorf("domain: %v", got)
	}
	if got := MisplacedPropertyKeys(AssetTypeService, "open_port", props); len(got) != 0 {
		t.Errorf("service: %v", got)
	}
	if got := MisplacedPropertyKeys(AssetTypeDatabase, "", map[string]any{"port": 5432}); len(got) != 0 {
		t.Errorf("database: %v", got)
	}
	// A discovered URL is a web endpoint: a status code and a port are its
	// own, a banner is not.
	if got := MisplacedPropertyKeys(AssetTypeService, "discovered_url", map[string]any{"port": 1, "status_code": 200, "banner": "x"}); !slices.Equal(got, []string{"banner"}) {
		t.Errorf("discovered_url: %v", got)
	}
}

func TestUnknownPropertyKeys(t *testing.T) {
	props := map[string]any{
		"registrar": "x", "ip_addresses": nil, "aliases": nil, "x_vendor_field": 1,
		"ip": "192.0.2.1", "is_crown_jewel": true, "shoe_size": "blue",
	}
	if got := UnknownPropertyKeys(AssetTypeDomain, "", props); !slices.Equal(got, []string{"shoe_size"}) {
		t.Errorf("UnknownPropertyKeys = %v", got)
	}
	// An alias's own attributes count for its stored pair.
	if got := UnknownPropertyKeys(AssetTypeService, "http", map[string]any{"status_code": 200, "cdn": "x"}); len(got) != 0 {
		t.Errorf("http service: %v", got)
	}
}

// The schema itself: every attribute has labels, every synonym resolves.
func TestPropertySchema_Consistent(t *testing.T) {
	for _, d := range registryTypes {
		for _, a := range d.Attributes {
			p, ok := LookupProperty(a.Name)
			if !ok || p.Label == "" || p.LabelVI == "" {
				t.Errorf("type %s attribute %s: no property entry with both labels", d.Type, a.Name)
			}
		}
	}
	for _, s := range PropertySynonyms() {
		c := CanonicalPropertyKey(s)
		if c == s {
			t.Errorf("synonym %q does not resolve", s)
		}
		if _, ok := LookupProperty(c); !ok {
			t.Errorf("synonym %q resolves to unknown %q", s, c)
		}
	}
	if !slices.Contains(AddressPropertyKeys(), "resolved_ips") || AddressPropertyKeys()[0] != PropKeyIPAddresses {
		t.Errorf("AddressPropertyKeys = %v", AddressPropertyKeys())
	}
}
