package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The properties ingest writes itself stay inside the property schema of the
// stored type (RFC-042 §6.3.9): a key the platform adds must be declared in
// configs/asset-types.yaml, so the web can label it and readers know it.
// Scanner-supplied keys outside the schema are kept and warned about; the
// platform's own never are.
func TestIngestBuiltProperties_StayInTheSchema(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	cases := []struct {
		name string
		in   ctis.Asset
	}{
		{"domain with technical data", ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "example.com",
			Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{Registrar: "r", Nameservers: []string{"ns1.example.com"}}}}},
		{"ip address with technical data", ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "203.0.113.5",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: "h.example.com", ASN: 64500}}}},
		{"host named by an address", ctis.Asset{Type: ctis.AssetTypeHost, Value: "10.0.0.5", Name: "10.0.0.5",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Hostname: "db-1"}}}},
		{"service with technical data", ctis.Asset{Type: ctis.AssetTypeService, Value: "203.0.113.5:443/tcp",
			Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{AppProtocol: "https", Port: 443, Transport: ctis.TransportTCP, IsTLS: true, Version: "1.1", Product: "nginx"}}}},
		{"web origin with http facts", ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: "https://example.com",
			Technical: &ctis.AssetTechnical{HTTP: &ctis.HTTPTechnical{StatusCode: 200, Title: "t", WebServer: "nginx"}}}},
		{"certificate", ctis.Asset{Type: ctis.AssetTypeCertificate, Value: "abc",
			Technical: &ctis.AssetTechnical{Certificate: &ctis.CertificateTechnical{SubjectCN: "example.com"}}}},
		{"identity hints", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-1",
			IdentityHints: &ctis.IdentityHints{FQDN: "web-1.example.com"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			props := p.buildPropertiesFromCTIS(&c.in)
			stored := resolveCTISAssetType(&c.in).stored
			if unknown := asset.UnknownPropertyKeys(stored.Type, stored.SubType, props); len(unknown) > 0 {
				t.Errorf("ingest wrote keys outside the %s schema: %v", stored.Type, unknown)
			}
			if bad := asset.MisplacedPropertyKeys(stored.Type, stored.SubType, props); len(bad) > 0 {
				t.Errorf("ingest wrote keys of another class on a %s: %v", stored.Type, bad)
			}
		})
	}

	// The root domains ingest creates for orphaned subdomains.
	for _, typ := range []asset.AssetType{asset.AssetTypeDomain, asset.AssetTypeSubdomain} {
		if unknown := asset.UnknownPropertyKeys(typ, "", asset.BuildDomainMetadata("a.b.example.com", asset.DiscoverySourceDNS)); len(unknown) > 0 {
			t.Errorf("BuildDomainMetadata keys outside the %s schema: %v", typ, unknown)
		}
	}
}
