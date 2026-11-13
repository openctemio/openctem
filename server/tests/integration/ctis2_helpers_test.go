package integration

import (
	"crypto/sha256"
	"encoding/hex"

	"strings"

	"fmt"

	"github.com/openctemio/ctis/v2"
)

// Small builders for CTIS 2.0 literals shared by the integration tests.

func f64p(v float64) *float64 { return &v }

// vulnOf is a vulnerability block naming ids (CVE-..., GHSA-...).
func vulnOf(ids ...string) *ctis.VulnerabilityDetails {
	v := &ctis.VulnerabilityDetails{}
	for _, id := range ids {
		v.AddID(id, "test")
	}
	return v
}

// cvssScoreOf is a CVSS score of a version.
func cvssScoreOf(version string, value float64) ctis.Score {
	return ctis.Score{System: ctis.ScoreSystemCVSS, Version: version, Value: f64p(value)}
}

// vprScoreOf is the Tenable VPR score (vendor system, source tenable).
func vprScoreOf(value float64) ctis.Score {
	return ctis.Score{System: ctis.ScoreSystemVendor, Source: "tenable", Value: f64p(value)}
}

// cveIDsOf is vulnerability.ids[] holding the given CVE ids (normalised).
func cveIDsOf(cves ...string) []ctis.VulnerabilityID {
	return vulnOf(cves...).IDs
}

// withOpenPorts returns host (an ip_address or host asset, document id
// host.ID) followed by one open tcp service asset per port, and the exposes
// relationships that link them: how CTIS 2.0 reports open ports.
func withOpenPorts(host ctis.Asset, ports ...int) ([]ctis.Asset, []ctis.Relationship) {
	assets := []ctis.Asset{host}
	var rels []ctis.Relationship
	for _, p := range ports {
		id := fmt.Sprintf("%s-p%d", host.ID, p)
		assets = append(assets, ctis.Asset{ID: id, Type: ctis.AssetTypeService, Value: fmt.Sprintf("%s:%d/tcp", host.Value, p),
			Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: p, Transport: ctis.TransportTCP, State: ctis.PortOpen}}})
		rels = append(rels, ctis.Relationship{Type: ctis.RelExposes, FromRef: host.ID, ToRef: id})
	}
	return assets, rels
}

// techsOf is asset.technologies[] from "Name" or "Name:Version" strings.
func techsOf(items ...any) []ctis.Technology {
	var out []ctis.Technology
	for _, it := range items {
		s, _ := it.(string)
		t := ctis.Technology{Name: s}
		if i := strings.LastIndex(s, ":"); i > 0 {
			t.Name, t.Version = s[:i], s[i+1:]
		}
		out = append(out, t)
	}
	return out
}

// dnsAddrs is the technical block of a domain_name asset resolving to ips
// (A and AAAA records).
func dnsAddrs(name string, ips ...string) *ctis.AssetTechnical {
	d := &ctis.DomainTechnical{}
	for _, ip := range ips {
		t := "A"
		if strings.Contains(ip, ":") {
			t = "AAAA"
		}
		d.DNSRecords = append(d.DNSRecords, ctis.DNSRecord{Type: t, Name: name, Value: ip})
	}
	return &ctis.AssetTechnical{Domain: d}
}

// certFingerprintOf is a certificate asset value (lower-case SHA-256 hex)
// derived from seed.
func certFingerprintOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}
