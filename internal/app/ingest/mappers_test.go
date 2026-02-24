package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/shared/severity"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// mapCTISAssetType tests
// =============================================================================

func TestMapCTISAssetType_AllKnownTypes(t *testing.T) {
	tests := []struct {
		ctisType ctis.AssetType
		expected asset.AssetType
	}{
		{ctis.AssetTypeDomain, asset.AssetTypeDomain},
		{ctis.AssetTypeSubdomain, asset.AssetTypeSubdomain},
		{ctis.AssetTypeIPAddress, asset.AssetTypeIPAddress},
		{ctis.AssetTypeCertificate, asset.AssetTypeCertificate},
		{ctis.AssetTypeWebsite, asset.AssetTypeWebsite},
		{ctis.AssetTypeWebApplication, asset.AssetTypeWebApplication},
		{ctis.AssetTypeAPI, asset.AssetTypeAPI},
		{ctis.AssetTypeMobileApp, asset.AssetTypeMobileApp},
		{ctis.AssetTypeService, asset.AssetTypeService},
		{ctis.AssetTypeRepository, asset.AssetTypeRepository},
		{ctis.AssetTypeCloudAccount, asset.AssetTypeCloudAccount},
		{ctis.AssetTypeCompute, asset.AssetTypeCompute},
		{ctis.AssetTypeStorage, asset.AssetTypeStorage},
		{ctis.AssetTypeDatabase, asset.AssetTypeDatabase},
		{ctis.AssetTypeServerless, asset.AssetTypeServerless},
		{ctis.AssetTypeContainerRegistry, asset.AssetTypeContainerRegistry},
		{ctis.AssetTypeHost, asset.AssetTypeHost},
		{ctis.AssetTypeServer, asset.AssetTypeServer},
		{ctis.AssetTypeContainer, asset.AssetTypeContainer},
		{ctis.AssetTypeKubernetes, asset.AssetTypeKubernetesCluster},
		{ctis.AssetTypeKubernetesCluster, asset.AssetTypeKubernetesCluster},
		{ctis.AssetTypeKubernetesNamespace, asset.AssetTypeKubernetesNamespace},
		{ctis.AssetTypeNetwork, asset.AssetTypeNetwork},
		{ctis.AssetTypeVPC, asset.AssetTypeVPC},
		{ctis.AssetTypeSubnet, asset.AssetTypeSubnet},
		{ctis.AssetTypeLoadBalancer, asset.AssetTypeLoadBalancer},
		{ctis.AssetTypeFirewall, asset.AssetTypeFirewall},
		{ctis.AssetTypeIAMUser, asset.AssetTypeIAMUser},
		{ctis.AssetTypeIAMRole, asset.AssetTypeIAMRole},
		{ctis.AssetTypeServiceAccount, asset.AssetTypeServiceAccount},
		{ctis.AssetTypeHTTPService, asset.AssetTypeHTTPService},
		{ctis.AssetTypeOpenPort, asset.AssetTypeOpenPort},
		{ctis.AssetTypeDiscoveredURL, asset.AssetTypeDiscoveredURL},
	}

	for _, tt := range tests {
		t.Run(string(tt.ctisType), func(t *testing.T) {
			result := mapCTISAssetType(tt.ctisType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapCTISAssetType_UnknownType(t *testing.T) {
	result := mapCTISAssetType("nonexistent_type")
	assert.Equal(t, asset.AssetTypeUnclassified, result)
}

func TestMapCTISAssetType_EmptyType(t *testing.T) {
	result := mapCTISAssetType("")
	assert.Equal(t, asset.AssetTypeUnclassified, result)
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
		{severity.Info, vulnerability.SeverityNone},
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

func TestDetectFindingSource_FromCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
		expected     vulnerability.FindingSource
	}{
		{"sast capability", []string{"SAST"}, vulnerability.FindingSourceSAST},
		{"sca capability", []string{"SCA"}, vulnerability.FindingSourceSCA},
		{"dast capability", []string{"DAST"}, vulnerability.FindingSourceDAST},
		{"secret capability", []string{"secret_detection"}, vulnerability.FindingSourceSecret},
		{"container capability", []string{"container_scanning"}, vulnerability.FindingSourceContainer},
		{"iac capability", []string{"iac_analysis"}, vulnerability.FindingSourceIaC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectFindingSource("generic-tool", tt.capabilities)
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
		{"gitleaks", vulnerability.FindingSourceSecret},
		{"trufflehog", vulnerability.FindingSourceSecret},
		{"trivy", vulnerability.FindingSourceContainer},
		{"grype", vulnerability.FindingSourceContainer},
		{"tfsec", vulnerability.FindingSourceIaC},
		{"checkov", vulnerability.FindingSourceIaC},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result := detectFindingSource(tt.tool, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectFindingSource_CapabilitiesTakePrecedence(t *testing.T) {
	// Tool name says "trivy" (container) but capability says SCA
	result := detectFindingSource("trivy", []string{"sca"})
	assert.Equal(t, vulnerability.FindingSourceSCA, result)
}

func TestDetectFindingSource_UnknownToolDefaultsToSAST(t *testing.T) {
	result := detectFindingSource("my-custom-tool", nil)
	assert.Equal(t, vulnerability.FindingSourceSAST, result)
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
		Ports: []ctis.PortInfo{
			{Port: 80, Protocol: "tcp", State: "open", Service: "http"},
			{Port: 443, Protocol: "tcp", State: "open", Service: "https", Version: "1.1", Banner: "nginx"},
		},
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
	ports := props["ports"].([]map[string]any)
	assert.Len(t, ports, 2)
	assert.Equal(t, 80, ports[0]["port"])
	assert.Equal(t, "nginx", ports[1]["banner"])
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
		SANs:               []string{"*.example.com", "example.com"},
		IssuerCN:           "Let's Encrypt",
		IssuerOrg:          "Let's Encrypt",
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		SignatureAlgorithm: "SHA256WithRSA",
		KeyAlgorithm:       "RSA",
		KeySize:            2048,
		Fingerprint:        "AB:CD:EF:12:34",
		SelfSigned:         false,
		Expired:            false,
	}

	props := buildCertificateProperties(cert)

	assert.Equal(t, "1234567890", props["serial_number"])
	assert.Equal(t, "example.com", props["subject_cn"])
	assert.Len(t, props["sans"], 2)
	assert.Equal(t, "Let's Encrypt", props["issuer_cn"])
	assert.Equal(t, 2048, props["key_size"])
	assert.Equal(t, false, props["self_signed"])
	assert.Equal(t, false, props["expired"])
}

// =============================================================================
// buildServiceProperties tests
// =============================================================================

func TestBuildServiceProperties_AllFields(t *testing.T) {
	svc := &ctis.ServiceTechnical{
		Name:      "nginx",
		Version:   "1.21.0",
		Product:   "nginx",
		Port:      443,
		Protocol:  "https",
		TLS:       true,
		Banner:    "nginx/1.21.0",
		Transport: "tcp",
		ExtraInfo: "OpenSSL/1.1.1",
	}

	props := buildServiceProperties(svc)

	assert.Equal(t, "nginx", props["name"])
	assert.Equal(t, "1.21.0", props["version"])
	assert.Equal(t, 443, props["port"])
	assert.Equal(t, true, props["tls"])
	assert.Equal(t, "nginx/1.21.0", props["banner"])
}

func TestBuildServiceProperties_TLSAlwaysPresent(t *testing.T) {
	svc := &ctis.ServiceTechnical{}
	props := buildServiceProperties(svc)
	// TLS is always set (even if false)
	assert.Contains(t, props, "tls")
	assert.Equal(t, false, props["tls"])
}
