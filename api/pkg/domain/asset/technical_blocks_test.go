package asset

import (
	"slices"
	"testing"
)

// A certificate's CTIS block becomes its flat keys; CTIS field names that
// differ from the schema are renamed, and the block goes.
func TestPromoteTechnicalBlocks_Certificate(t *testing.T) {
	props := map[string]any{
		"certificate": map[string]any{
			"subject_cn": "*.example.com", "sans": []any{"*.example.com", "example.com"},
			"issuer_cn": "R11", "issuer_org": "Example CA", "not_before": "2026-01-01T00:00:00Z",
			"not_after": "2026-04-01T00:00:00Z", "key_size": 2048, "fingerprint": "ab12",
			"self_signed": false, "expired": false, "serial_number": "01",
		},
	}
	PromoteTechnicalBlocks(AssetTypeCertificate, "", props)
	want := map[string]any{
		"subject_cn": "*.example.com", "issuer_cn": "R11", "issuer_org": "Example CA",
		"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
		"key_size": 2048, "fingerprint_sha256": "ab12", "is_self_signed": false,
		"is_expired": false, "serial_number": "01",
	}
	for k, v := range want {
		if props[k] != v {
			t.Errorf("%s = %#v, want %#v", k, props[k], v)
		}
	}
	if _, ok := props["certificate"]; ok {
		t.Error("the block must go once promoted")
	}
	if got := sortedStrings(props["sans"]); !slices.Equal(got, []string{"*.example.com", "example.com"}) {
		t.Errorf("sans = %v", got)
	}
}

// A flat value already on the asset wins over the block's.
func TestPromoteTechnicalBlocks_FlatWins(t *testing.T) {
	props := map[string]any{
		"not_after":   "2027-01-01T00:00:00Z",
		"certificate": map[string]any{"not_after": "2026-01-01T00:00:00Z"},
	}
	PromoteTechnicalBlocks(AssetTypeCertificate, "", props)
	if props["not_after"] != "2027-01-01T00:00:00Z" || len(props) != 1 {
		t.Errorf("props = %v", props)
	}
}

// A domain's block gives its registration keys and, from the DNS records,
// the summary a list filters on: record types, addresses, CNAME target.
func TestPromoteTechnicalBlocks_Domain(t *testing.T) {
	props := map[string]any{
		"domain": map[string]any{
			"registrar": "Example Registrar", "expires_at": "2027-05-14T00:00:00Z",
			"nameservers": []any{"ns1.example.com"},
			"dns_records": []any{
				map[string]any{"type": "cname", "value": "edge.example-cdn.net.", "ttl": 300},
				map[string]any{"type": "A", "value": "203.0.113.7"},
				map[string]any{"type": "AAAA", "value": "2001:db8::7"},
			},
		},
	}
	PromoteTechnicalBlocks(AssetTypeDomain, "", props)
	if props["registrar"] != "Example Registrar" || props["expires_at"] != "2027-05-14T00:00:00Z" {
		t.Errorf("registration not promoted: %v", props)
	}
	if props["dns_record_types"] != "CNAME, A, AAAA" {
		t.Errorf("dns_record_types = %v", props["dns_record_types"])
	}
	if props["cname_target"] != "edge.example-cdn.net" {
		t.Errorf("cname_target = %v", props["cname_target"])
	}
	if got := IPAddresses(props); !slices.Equal(got, []string{"203.0.113.7", "2001:db8::7"}) {
		t.Errorf("ip_addresses = %v", got)
	}
	if _, ok := props["dns_records"]; !ok {
		t.Error("the records themselves are a domain attribute and stay")
	}
	if _, ok := props["domain"]; ok {
		t.Error("the block must go once promoted")
	}

	// A subdomain keeps its records too, but has no registrar of its own.
	sub := map[string]any{"domain": map[string]any{
		"registrar":   "Example Registrar",
		"dns_records": []any{map[string]any{"type": "A", "value": "203.0.113.8"}},
	}}
	PromoteTechnicalBlocks(AssetTypeSubdomain, "", sub)
	if _, ok := sub["registrar"]; ok {
		t.Error("a key the type does not declare is not promoted")
	}
	if _, ok := sub["dns_records"]; !ok || sub["dns_record_types"] != "A" {
		t.Errorf("subdomain = %v", sub)
	}
}

// An IP address's block fills its own keys; on a host only the hostname
// applies (ASN and geography belong to the IP asset), and the address joins
// the host's ip_addresses.
func TestPromoteTechnicalBlocks_IPAddress(t *testing.T) {
	ip := map[string]any{"ip_address": map[string]any{
		"version": 4, "hostname": "edge-7", "asn": 64500, "asn_org": "Example Transit",
		"country": "VN", "ports": []any{map[string]any{"port": 443, "protocol": "tcp"}},
	}}
	PromoteTechnicalBlocks(AssetTypeIPAddress, "", ip)
	for _, k := range []string{"version", "hostname", "asn", "asn_org", "country", "ports"} {
		if _, ok := ip[k]; !ok {
			t.Errorf("%s not promoted: %v", k, ip)
		}
	}
	if _, ok := ip["ip_address"]; ok {
		t.Error("the block must go once promoted")
	}

	host := map[string]any{"ip_address": map[string]any{
		"address": "10.0.0.5", "hostname": "db-1", "asn": 64500,
	}}
	PromoteTechnicalBlocks(AssetTypeHost, "", host)
	if host["hostname"] != "db-1" {
		t.Errorf("hostname = %v", host["hostname"])
	}
	if _, ok := host["asn"]; ok {
		t.Error("a host has no asn key")
	}
	if got := IPAddresses(host); !slices.Equal(got, []string{"10.0.0.5"}) {
		t.Errorf("ip_addresses = %v", got)
	}
}

// A service's block fills the open port's keys; the nmap service name goes
// to `service` on an open port and to `server` on an HTTP service.
func TestPromoteTechnicalBlocks_Service(t *testing.T) {
	port := map[string]any{"service": map[string]any{
		"name": "ssh", "port": 22, "protocol": "tcp", "version": "9.6", "banner": "SSH-2.0",
		"tls": false, "tls_cert_issuer": "x", "extra_info": "y",
	}}
	PromoteTechnicalBlocks(AssetTypeService, "open_port", port)
	if port["service"] != "ssh" || port["port"] != 22 || port["version"] != "9.6" || port["banner"] != "SSH-2.0" {
		t.Errorf("open port = %v", port)
	}
	if _, ok := port["tls_cert_issuer"]; ok {
		t.Error("a field the type has no key for is dropped")
	}

	web := map[string]any{"service": map[string]any{"name": "nginx", "port": 443, "tls": true}}
	PromoteTechnicalBlocks(AssetTypeService, "http", web)
	if web["server"] != "nginx" {
		t.Errorf("server = %v (%v)", web["server"], web)
	}
	if _, isBlock := web["service"].(map[string]any); isBlock {
		t.Error("the block must go once promoted")
	}
}

// Not a block: a string under a block key is left to NormalizeProperties
// (an ip_address string is an ip_addresses synonym), and an empty props map
// stays as it is.
func TestPromoteTechnicalBlocks_NotABlock(t *testing.T) {
	props := map[string]any{"ip_address": "192.0.2.1"}
	NormalizeAssetProperties(AssetTypeDomain, "", props)
	if got := IPAddresses(props); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Errorf("ip_addresses = %v (%v)", got, props)
	}
	if PromoteTechnicalBlocks(AssetTypeHost, "", nil) != nil {
		t.Error("nil stays nil")
	}
}
