package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/severity"
	"github.com/stretchr/testify/assert"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// =============================================================================
// mapCTISAssetType tests
// =============================================================================

func identityAsset(k ctis.IdentityKind) *ctis.Asset {
	return &ctis.Asset{Type: ctis.AssetTypeIdentity, Value: "u1",
		Technical: &ctis.AssetTechnical{Identity: &ctis.IdentityTechnical{Kind: k}}}
}

// The wire type to stored type table: domain_name is a domain at the
// public-suffix apex and a subdomain below it; identity takes its sub-type
// from technical.identity.kind; the other wire-only types are placed here,
// not by the registry's type_inputs (the REST API's inputs).
func TestMapCTISAssetType_WireToStored(t *testing.T) {
	tests := []struct {
		name     string
		in       *ctis.Asset
		wantType asset.AssetType
		wantSub  string
	}{
		{"apex domain", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "example.com"}, asset.AssetTypeDomain, ""},
		{"subdomain", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "api.example.com"}, asset.AssetTypeSubdomain, ""},
		{"deep subdomain", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "a.b.example.com"}, asset.AssetTypeSubdomain, ""},
		{"multi-label suffix apex", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "example.co.uk"}, asset.AssetTypeDomain, ""},
		{"multi-label suffix subdomain", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "www.example.co.uk"}, asset.AssetTypeSubdomain, ""},
		{"private suffix is not guessed", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "localhost"}, asset.AssetTypeDomain, ""},
		{"identity user", identityAsset(ctis.IdentityUser), asset.AssetTypeIdentity, "iam_user"},
		{"identity role", identityAsset(ctis.IdentityRole), asset.AssetTypeIdentity, "iam_role"},
		{"identity service account", identityAsset(ctis.IdentityServiceAccount), asset.AssetTypeIdentity, "service_account"},
		{"identity group keeps its kind", identityAsset(ctis.IdentityGroup), asset.AssetTypeIdentity, "group"},
		{"identity without technical", &ctis.Asset{Type: ctis.AssetTypeIdentity, Value: "u1"}, asset.AssetTypeIdentity, ""},
		{"service", &ctis.Asset{Type: ctis.AssetTypeService, Value: "203.0.113.5:443/tcp"}, asset.AssetTypeService, "open_port"},
		{"web origin", &ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: "https://example.com"}, asset.AssetTypeService, "http"},
		{"ip range", &ctis.Asset{Type: ctis.AssetTypeIPRange, Value: "10.0.0.0/24"}, asset.AssetTypeNetwork, ""},
		{"container image", &ctis.Asset{Type: ctis.AssetTypeContainerImage}, asset.AssetTypeContainer, "image"},
		{"kubernetes workload", &ctis.Asset{Type: ctis.AssetTypeKubernetesWorkload}, asset.AssetTypeKubernetes, "workload"},
		{"endpoint device", &ctis.Asset{Type: ctis.AssetTypeEndpointDevice}, asset.AssetTypeHost, "workstation"},
		{"host", &ctis.Asset{Type: ctis.AssetTypeHost, Value: "h1"}, asset.AssetTypeHost, ""},
		{"ip address", &ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "203.0.113.7"}, asset.AssetTypeIPAddress, ""},
		{"empty type", &ctis.Asset{}, asset.AssetTypeUnclassified, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotSub := mapCTISAssetType(tt.in)
			assert.Equal(t, tt.wantType, gotType)
			assert.Equal(t, tt.wantSub, gotSub)
		})
	}
}

// A network_device takes its stored sub-type from technical.network_device.kind;
// a wireless access point is stored as access_point; other or absent kinds
// have no sub-type.
func TestMapCTISAssetType_NetworkDeviceKinds(t *testing.T) {
	dev := func(k ctis.NetworkDeviceKind) *ctis.Asset {
		return &ctis.Asset{Type: ctis.AssetTypeNetworkDevice, Value: "sw1",
			Technical: &ctis.AssetTechnical{NetworkDevice: &ctis.NetworkDeviceTechnical{Kind: k}}}
	}
	cases := map[string]struct {
		in   *ctis.Asset
		want string
	}{
		"router":        {dev(ctis.NetworkDeviceRouter), "router"},
		"switch":        {dev(ctis.NetworkDeviceSwitch), "switch"},
		"firewall":      {dev(ctis.NetworkDeviceFirewall), "firewall"},
		"load balancer": {dev(ctis.NetworkDeviceLoadBalancer), "load_balancer"},
		"vpn gateway":   {dev(ctis.NetworkDeviceVPNGateway), "vpn_gateway"},
		"access point":  {dev(ctis.NetworkDeviceWirelessAccessPoint), "access_point"},
		"other":         {dev(ctis.NetworkDeviceOther), ""},
		"no technical":  {&ctis.Asset{Type: ctis.AssetTypeNetworkDevice, Value: "sw1"}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			typ, sub := mapCTISAssetType(c.in)
			assert.Equal(t, asset.AssetTypeNetwork, typ)
			assert.Equal(t, c.want, sub)
			got := resolveCTISAssetType(c.in).stored
			assert.Equal(t, asset.AssetTypeNetwork, got.Type)
			assert.Equal(t, c.want, got.SubType)
		})
	}
}

// What the registry stores each wire type as.
func TestResolveCTISAssetType_StoredPairs(t *testing.T) {
	tests := []struct {
		name     string
		in       *ctis.Asset
		wantType asset.AssetType
		wantSub  string
	}{
		{"apex", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "example.com"}, asset.AssetTypeDomain, ""},
		{"subdomain", &ctis.Asset{Type: ctis.AssetTypeDomainName, Value: "www.example.co.uk"}, asset.AssetTypeSubdomain, ""},
		{"identity role", identityAsset(ctis.IdentityRole), asset.AssetTypeIdentity, "iam_role"},
		{"web origin", &ctis.Asset{Type: ctis.AssetTypeWebOrigin}, asset.AssetTypeService, "http"},
		{"service", &ctis.Asset{Type: ctis.AssetTypeService}, asset.AssetTypeService, "open_port"},
		{"ip range", &ctis.Asset{Type: ctis.AssetTypeIPRange}, asset.AssetTypeNetwork, ""},
		{"container image", &ctis.Asset{Type: ctis.AssetTypeContainerImage}, asset.AssetTypeContainer, "image"},
		{"kubernetes workload", &ctis.Asset{Type: ctis.AssetTypeKubernetesWorkload}, asset.AssetTypeKubernetes, "workload"},
		{"endpoint device", &ctis.Asset{Type: ctis.AssetTypeEndpointDevice}, asset.AssetTypeHost, "workstation"},
		{"network device", &ctis.Asset{Type: ctis.AssetTypeNetworkDevice}, asset.AssetTypeNetwork, ""},
		{"unknown", &ctis.Asset{Type: "nonexistent_type"}, asset.AssetTypeUnclassified, ""},
		{"empty", &ctis.Asset{}, asset.AssetTypeUnclassified, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveCTISAssetType(tt.in)
			assert.Equal(t, tt.wantType, got.stored.Type)
			assert.Equal(t, tt.wantSub, got.stored.SubType)
		})
	}
}

// =============================================================================
// mapCTISCriticality tests
// =============================================================================

func TestMapCTISCriticality(t *testing.T) {
	tests := []struct {
		input    ctis.Criticality
		expected asset.Criticality
	}{
		{ctis.CriticalityCritical, asset.CriticalityCritical},
		{ctis.CriticalityHigh, asset.CriticalityHigh},
		{ctis.CriticalityMedium, asset.CriticalityMedium},
		{ctis.CriticalityLow, asset.CriticalityLow},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			assert.Equal(t, tt.expected, mapCTISCriticality(tt.input))
		})
	}
}

func TestMapCTISCriticality_DefaultsToMedium(t *testing.T) {
	assert.Equal(t, asset.CriticalityMedium, mapCTISCriticality("unknown"))
	assert.Equal(t, asset.CriticalityMedium, mapCTISCriticality(""))
}

// =============================================================================
// mapSDKSeverity tests
// =============================================================================

func TestMapSDKSeverity(t *testing.T) {
	tests := []struct {
		input    severity.Level
		expected vulnerability.Severity
	}{
		{severity.Critical, vulnerability.SeverityCritical},
		{severity.High, vulnerability.SeverityHigh},
		{severity.Medium, vulnerability.SeverityMedium},
		{severity.Low, vulnerability.SeverityLow},
		{severity.Info, vulnerability.SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			assert.Equal(t, tt.expected, mapSDKSeverity(tt.input))
		})
	}
}

func TestMapSDKSeverity_DefaultsToMedium(t *testing.T) {
	assert.Equal(t, vulnerability.SeverityMedium, mapSDKSeverity("unknown"))
	assert.Equal(t, vulnerability.SeverityMedium, mapSDKSeverity(""))
}

// =============================================================================
// detectFindingSource tests
// =============================================================================

func TestDetectFindingSource_FromTechniques(t *testing.T) {
	tests := []struct {
		name       string
		techniques []ctis.Technique
		expected   vulnerability.FindingSource
	}{
		{"sast technique", []ctis.Technique{ctis.TechniqueSAST}, vulnerability.FindingSourceSAST},
		{"sca technique", []ctis.Technique{ctis.TechniqueSCA}, vulnerability.FindingSourceSCA},
		{"dast technique", []ctis.Technique{ctis.TechniqueDAST}, vulnerability.FindingSourceDAST},
		{"secret technique", []ctis.Technique{ctis.TechniqueSecret}, vulnerability.FindingSourceSecret},
		{"container technique", []ctis.Technique{ctis.TechniqueContainer}, vulnerability.FindingSourceContainer},
		{"iac technique", []ctis.Technique{ctis.TechniqueIaC}, vulnerability.FindingSourceIaC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFindingSource("generic-tool", tt.techniques...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectFindingSource_FromToolName(t *testing.T) {
	tests := []struct {
		tool     string
		expected vulnerability.FindingSource
	}{
		{"semgrep", vulnerability.FindingSourceSAST},
		{"Semgrep-Pro", vulnerability.FindingSourceSAST},
		{"codeql", vulnerability.FindingSourceSAST},
		{"snyk", vulnerability.FindingSourceSCA},
		{"dependabot", vulnerability.FindingSourceSCA},
		{"nuclei", vulnerability.FindingSourceDAST},
		{"zap", vulnerability.FindingSourceDAST},
		{"betterleaks", vulnerability.FindingSourceSecret},
		{"trufflehog", vulnerability.FindingSourceSecret},
		{"trivy", vulnerability.FindingSourceContainer},
		{"grype", vulnerability.FindingSourceContainer},
		{"tfsec", vulnerability.FindingSourceIaC},
		{"checkov", vulnerability.FindingSourceIaC},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result := detectFindingSource(tt.tool)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectFindingSource_TechniquesTakePrecedence(t *testing.T) {
	// Tool name says "trivy" (container) but the technique says SCA
	result := detectFindingSource("trivy", ctis.TechniqueSCA)
	assert.Equal(t, vulnerability.FindingSourceSCA, result)
}

// Was TestDetectFindingSource_UnknownToolDefaultsToSAST, which asserted that an
// unrecognized tool is recorded as static code analysis. That default was not
// harmless: the Nessus/Tenable and DefectDojo importers set no capabilities, so
// every network vulnerability and every synced finding reached the database
// labeled "sast". "Which findings came from our VA scanner" was unanswerable as
// a direct result.
//
// Unknown provenance is now recorded as such. See mappers_source_test.go for
// the full matrix.
func TestDetectFindingSource_UnknownToolIsRecordedAsExternal(t *testing.T) {
	result := detectFindingSource("my-custom-tool")
	assert.Equal(t, vulnerability.FindingSourceExternal, result)
}

// =============================================================================
// buildDomainProperties tests
// =============================================================================

func TestBuildDomainProperties_AllFields(t *testing.T) {
	now := time.Now()
	domain := &ctis.DomainTechnical{
		Registrar:    "GoDaddy",
		RegisteredAt: &now,
		ExpiresAt:    &now,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DNSRecords: []ctis.DNSRecord{
			{Type: "A", Name: "@", Value: "1.2.3.4", TTL: 300},
		},
		WHOIS: map[string]string{"org": "Example Inc"},
	}

	props := buildDomainProperties(domain)

	assert.Equal(t, "GoDaddy", props["registrar"])
	assert.NotEmpty(t, props["registered_at"])
	assert.NotEmpty(t, props["expires_at"])
	assert.Len(t, props["nameservers"], 2)
	records := props["dns_records"].([]map[string]any)
	assert.Len(t, records, 1)
	assert.Equal(t, "A", records[0]["type"])
	assert.Equal(t, map[string]string{"org": "Example Inc"}, props["whois"])
}

func TestBuildDomainProperties_EmptyFields(t *testing.T) {
	domain := &ctis.DomainTechnical{}
	props := buildDomainProperties(domain)
	assert.Empty(t, props)
}

// =============================================================================
// buildIPAddressProperties tests
// =============================================================================

func TestBuildIPAddressProperties_AllFields(t *testing.T) {
	ip := &ctis.IPAddressTechnical{
		Version:  4,
		Hostname: "example.com",
		ASN:      15169,
		ASNOrg:   "Google LLC",
		Country:  "US",
		City:     "Mountain View",
		Geolocation: &ctis.Geolocation{
			Latitude:  37.386,
			Longitude: -122.084,
			Accuracy:  100,
		},
	}

	props := buildIPAddressProperties(ip)

	assert.Equal(t, 4, props["version"])
	assert.Equal(t, "example.com", props["hostname"])
	assert.Equal(t, 15169, props["asn"])
	assert.Equal(t, "Google LLC", props["asn_org"])
	// Ports are service assets in CTIS 2.0, never a property of the address.
	assert.NotContains(t, props, "ports")
	geo := props["geolocation"].(map[string]any)
	assert.Equal(t, 37.386, geo["latitude"])
}

func TestBuildIPAddressProperties_EmptyFields(t *testing.T) {
	ip := &ctis.IPAddressTechnical{}
	props := buildIPAddressProperties(ip)
	assert.Empty(t, props)
}

// =============================================================================
// buildCertificateProperties tests
// =============================================================================

func TestBuildCertificateProperties_AllFields(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	cert := &ctis.CertificateTechnical{
		SerialNumber:       "1234567890",
		SubjectCN:          "example.com",
		SubjectAltNames:    []string{"*.example.com", "example.com"},
		IssuerCN:           "Let's Encrypt",
		IssuerOrg:          "Let's Encrypt",
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		SignatureAlgorithm: "SHA256WithRSA",
		KeyAlgorithm:       "RSA",
		KeySize:            2048,
		SHA256Fingerprint:  "abcdef1234",
		IsSelfSigned:       false,
	}

	props := buildCertificateProperties(cert)

	assert.Equal(t, "1234567890", props["serial_number"])
	assert.Equal(t, "example.com", props["subject_cn"])
	assert.Len(t, props["sans"], 2)
	assert.Equal(t, "Let's Encrypt", props["issuer_cn"])
	assert.Equal(t, 2048, props["key_size"])
	assert.Equal(t, false, props["self_signed"])
	assert.Equal(t, false, props["expired"], "expired is derived from not_after")
	assert.Equal(t, "abcdef1234", props["fingerprint"])
}

// =============================================================================
// buildServiceProperties tests
// =============================================================================

func TestBuildServiceProperties_AllFields(t *testing.T) {
	svc := &ctis.ServiceTechnical{
		Version:     "1.21.0",
		Product:     "nginx",
		Port:        443,
		AppProtocol: "https",
		IsTLS:       true,
		Banner:      "nginx/1.21.0",
		Transport:   ctis.TransportTCP,
		ExtraInfo:   "OpenSSL/1.1.1",
	}

	props := buildServiceProperties(svc)

	assert.Equal(t, "nginx", props["product"])
	assert.Equal(t, "https", props["protocol"])
	assert.Equal(t, "1.21.0", props["version"])
	assert.Equal(t, 443, props["port"])
	assert.Equal(t, true, props["tls"])
	assert.Equal(t, "nginx/1.21.0", props["banner"])
}

// A false TLS is also what a report that never measured TLS sends, so it is
// not recorded: the web shows "not collected", never "No TLS", for it.
func TestBuildServiceProperties_TLSOnlyWhenSeen(t *testing.T) {
	props := buildServiceProperties(&ctis.ServiceTechnical{})
	assert.NotContains(t, props, "tls")
}

// The whole report path: a CTIS asset's technical blocks are stored as the
// stored type's flat keys, and no block object is left.
func TestBuildPropertiesFromCTIS_PromotesTechnicalBlocks(t *testing.T) {
	p := &AssetProcessor{logger: logger.NewNop(), propsValidator: validator.NewPropertiesValidator()}
	notAfter := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	cert := p.buildPropertiesFromCTIS(&ctis.Asset{
		Type: ctis.AssetTypeCertificate, Value: "*.example.com",
		Technical: &ctis.AssetTechnical{Certificate: &ctis.CertificateTechnical{
			SubjectCN: "*.example.com", IssuerOrg: "Example CA", NotAfter: &notAfter,
			SHA256Fingerprint: "ab:cd", IsSelfSigned: true,
		}},
	})
	assert.Equal(t, "*.example.com", cert["subject_cn"])
	assert.Equal(t, "Example CA", cert["issuer_org"])
	assert.Equal(t, "2027-01-02T00:00:00Z", cert["not_after"])
	assert.Equal(t, "ab:cd", cert["fingerprint_sha256"])
	assert.Equal(t, true, cert["is_self_signed"])
	assert.NotContains(t, cert, "certificate")

	dom := p.buildPropertiesFromCTIS(&ctis.Asset{
		Type: ctis.AssetTypeDomainName, Value: "example.com",
		Technical: &ctis.AssetTechnical{Domain: &ctis.DomainTechnical{
			Registrar: "Example Registrar",
			DNSRecords: []ctis.DNSRecord{
				{Type: "CNAME", Name: "example.com", Value: "edge.example-cdn.net."},
				{Type: "A", Name: "example.com", Value: "203.0.113.9"},
			},
		}},
	})
	assert.Equal(t, "Example Registrar", dom["registrar"])
	assert.Equal(t, "CNAME, A", dom["dns_record_types"])
	assert.Equal(t, "edge.example-cdn.net", dom["cname_target"])
	assert.Equal(t, []string{"203.0.113.9"}, asset.IPAddresses(dom))
	assert.NotContains(t, dom, "domain")

	port := p.buildPropertiesFromCTIS(&ctis.Asset{
		Type: ctis.AssetTypeService, Value: "198.51.100.7:22/tcp",
		Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{
			Port: 22, Transport: ctis.TransportTCP, AppProtocol: "ssh", Version: "9.6",
		}},
	})
	assert.Equal(t, "ssh", port["protocol"])
	assert.Equal(t, 22, port["port"])
	assert.Equal(t, "9.6", port["version"])
	assert.NotContains(t, port, "tls")
}

// The CTIS 2.0 wire-only types are not REST API asset type inputs: the
// receiver places them, the API refuses them as it did before 2.0.
func TestCTISWireTypes_NotAPIInputs(t *testing.T) {
	for wire := range ctisWireTypes {
		if _, err := asset.ResolveInputType(string(wire), ""); err == nil {
			t.Errorf("%s is accepted as a REST asset type input", wire)
		}
		got := resolveCTISAssetType(&ctis.Asset{Type: wire, Value: "x"})
		if got.stored.Type == asset.AssetTypeUnclassified {
			t.Errorf("%s resolves to unclassified in the receiver", wire)
		}
	}
}

// A host's own listening sockets keep their local view; other details keys
// and malformed values are not stored.
func TestBuildServiceProperties_LocalListener(t *testing.T) {
	props := buildServiceProperties(&ctis.ServiceTechnical{Port: 8443, Transport: ctis.TransportTCP, Details: map[string]string{
		"observed_from": "host", "bind_address": "192.0.2.10", "process": "exampled", "ssh_kex": "x",
	}})
	assert.Equal(t, "host", props["observed_from"])
	assert.Equal(t, "192.0.2.10", props["bind_address"])
	assert.Equal(t, "exampled", props["process"])
	assert.NotContains(t, props, "ssh_kex")

	props = buildServiceProperties(&ctis.ServiceTechnical{Details: map[string]string{
		"observed_from": "elsewhere", "bind_address": "192.0.2.10",
	}})
	assert.NotContains(t, props, "observed_from")
	assert.NotContains(t, props, "bind_address")

	props = buildServiceProperties(&ctis.ServiceTechnical{Details: map[string]string{
		"observed_from": "network", "bind_address": "not-an-address", "process": strings.Repeat("p", 200),
	}})
	assert.Equal(t, "network", props["observed_from"])
	assert.NotContains(t, props, "bind_address")
	assert.NotContains(t, props, "process")
}
