package ingest

import (
	"slices"
	"testing"

	"github.com/openctemio/ctis"

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
		{"domain with technical data", ctis.Asset{Type: ctis.AssetTypeDomain, Value: "example.com",
			Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{Registrar: "r", Nameservers: []string{"ns1.example.com"}}}}},
		{"ip address with technical data", ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "203.0.113.5",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: "h.example.com", ASN: 64500}}}},
		{"host named by an address", ctis.Asset{Type: ctis.AssetTypeHost, Value: "10.0.0.5", Name: "10.0.0.5",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Hostname: "db-1"}}}},
		{"service with technical data", ctis.Asset{Type: ctis.AssetTypeService, Value: "203.0.113.5:443",
			Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Name: "https", Port: 443, TLS: true}}}},
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

	// The port assets ingest adds (open ports listed on an address, and a
	// port routed off a domain).
	rep := &ctis.Report{Tool: &ctis.Tool{Name: "naabu"}, Assets: []ctis.Asset{
		{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.9", Technical: &ctis.AssetTechnical{
			IPAddress: &ctis.IPAddressTechnical{Ports: []ctis.PortInfo{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}}}}},
		{ID: "d", Type: ctis.AssetTypeDomain, Value: "example.com", Properties: ctis.Properties{"port": 8443, "status_code": 200}},
	}}
	expandOpenPorts(rep)
	routeMisplacedProperties(rep)
	ports := 0
	for i := range rep.Assets {
		a := &rep.Assets[i]
		if a.Type != ctis.AssetTypeOpenPort {
			continue
		}
		ports++
		stored := resolveCTISAssetType(a).stored
		if unknown := asset.UnknownPropertyKeys(stored.Type, stored.SubType, a.Properties); len(unknown) > 0 {
			t.Errorf("port asset %s: keys outside the schema: %v", a.Name, unknown)
		}
	}
	if ports != 2 {
		t.Errorf("port assets = %d, want 2", ports)
	}
}

// A port on a domain, host or address becomes that asset's service; on any
// other asset it is dropped. Synonyms fold on the way.
func TestRouteMisplacedProperties(t *testing.T) {
	rep := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Assets: []ctis.Asset{
		// nuclei: an ip_address asset named by the URL it reached.
		{Type: ctis.AssetTypeIPAddress, Value: "203.0.113.10", Name: "https://app.example.com/login",
			Properties: ctis.Properties{"ip": "203.0.113.10", "port": "443", "protocol": "TCP"}},
		{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/app", Properties: ctis.Properties{"port": 22}},
		{ID: "bad", Type: ctis.AssetTypeDomain, Value: "bad.example.com", Properties: ctis.Properties{"port": "http"}},
		{ID: "svc", Type: ctis.AssetTypeService, Value: "x.example.com:80", Properties: ctis.Properties{"port": 80}},
	}}
	added, dropped, _ := routeMisplacedProperties(rep)
	if added != 1 || dropped != 2 {
		t.Fatalf("added %d, dropped %d; want 1, 2", added, dropped)
	}
	src := rep.Assets[0]
	if _, ok := src.Properties["port"]; ok {
		t.Errorf("port left on the holder: %v", src.Properties)
	}
	if _, ok := src.Properties["protocol"]; ok {
		t.Errorf("the port's protocol left on the holder: %v", src.Properties)
	}
	if !slices.Equal(asset.IPAddresses(src.Properties), []string{"203.0.113.10"}) || src.Properties["ip"] != nil {
		t.Errorf("synonyms not folded: %v", src.Properties)
	}
	svc := rep.Assets[len(rep.Assets)-1]
	if svc.Type != ctis.AssetTypeOpenPort || svc.Name != "app.example.com:443/tcp" {
		t.Fatalf("routed asset = %s %q", svc.Type, svc.Name)
	}
	if svc.Properties["host"] != "app.example.com" || svc.Properties["port"] != 443 || svc.Properties["protocol"] != "tcp" {
		t.Errorf("routed props = %v", svc.Properties)
	}
	if src.ID == "" || !slices.Contains(src.RelatedAssets, svc.ID) {
		t.Errorf("holder not linked to its service: id %q related %v", src.ID, src.RelatedAssets)
	}
	if relatedRelType(src.Type, svc.Type) != asset.RelTypeExposes {
		t.Error("holder -> routed service is not an exposes edge")
	}
	if _, ok := rep.Assets[1].Properties["port"]; ok {
		t.Error("a port on a repository was kept")
	}
	if rep.Assets[3].Properties["port"] != 80 {
		t.Error("a service lost its own port")
	}

	// Twice the same port: one service.
	rep = &ctis.Report{Assets: []ctis.Asset{
		{ID: "a", Type: ctis.AssetTypeDomain, Value: "example.com", Properties: ctis.Properties{"port": 443}},
		{ID: "b", Type: ctis.AssetTypeSubdomain, Value: "example.com", Properties: ctis.Properties{"port": 443.0}},
	}}
	if added, _, _ := routeMisplacedProperties(rep); added != 1 || len(rep.Assets) != 3 {
		t.Errorf("added %d, assets %d", added, len(rep.Assets))
	}
}
