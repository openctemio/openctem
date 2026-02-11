package ingest

import (
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/ctis"
	"github.com/openctemio/sdk/pkg/shared/severity"
)

// =============================================================================
// Asset Type Mapping
// =============================================================================

// mapCTISAssetType maps CTIS asset type to domain asset type.
//
//nolint:cyclop // Type mapping switch requires a case per asset type
func mapCTISAssetType(ctisType ctis.AssetType) asset.AssetType {
	switch ctisType {
	// Discovery / External Attack Surface
	case ctis.AssetTypeDomain:
		return asset.AssetTypeDomain
	case ctis.AssetTypeSubdomain:
		return asset.AssetTypeSubdomain
	case ctis.AssetTypeIPAddress:
		return asset.AssetTypeIPAddress
	case ctis.AssetTypeCertificate:
		return asset.AssetTypeCertificate

	// Applications
	case ctis.AssetTypeWebsite:
		return asset.AssetTypeWebsite
	case ctis.AssetTypeWebApplication:
		return asset.AssetTypeWebApplication
	case ctis.AssetTypeAPI:
		return asset.AssetTypeAPI
	case ctis.AssetTypeMobileApp:
		return asset.AssetTypeMobileApp
	case ctis.AssetTypeService:
		return asset.AssetTypeService

	// Code / Repository
	case ctis.AssetTypeRepository:
		return asset.AssetTypeRepository

	// Cloud
	case ctis.AssetTypeCloudAccount:
		return asset.AssetTypeCloudAccount
	case ctis.AssetTypeCompute:
		return asset.AssetTypeCompute
	case ctis.AssetTypeStorage:
		return asset.AssetTypeStorage
	case ctis.AssetTypeDatabase:
		return asset.AssetTypeDatabase
	case ctis.AssetTypeServerless:
		return asset.AssetTypeServerless
	case ctis.AssetTypeContainerRegistry:
		return asset.AssetTypeContainerRegistry

	// Infrastructure
	case ctis.AssetTypeHost:
		return asset.AssetTypeHost
	case ctis.AssetTypeServer:
		return asset.AssetTypeServer
	case ctis.AssetTypeContainer:
		return asset.AssetTypeContainer
	case ctis.AssetTypeKubernetes:
		return asset.AssetTypeKubernetesCluster
	case ctis.AssetTypeKubernetesCluster:
		return asset.AssetTypeKubernetesCluster
	case ctis.AssetTypeKubernetesNamespace:
		return asset.AssetTypeKubernetesNamespace

	// Network
	case ctis.AssetTypeNetwork:
		return asset.AssetTypeNetwork
	case ctis.AssetTypeVPC:
		return asset.AssetTypeVPC
	case ctis.AssetTypeSubnet:
		return asset.AssetTypeSubnet
	case ctis.AssetTypeLoadBalancer:
		return asset.AssetTypeLoadBalancer
	case ctis.AssetTypeFirewall:
		return asset.AssetTypeFirewall

	// Identity / IAM
	case ctis.AssetTypeIAMUser:
		return asset.AssetTypeIAMUser
	case ctis.AssetTypeIAMRole:
		return asset.AssetTypeIAMRole
	case ctis.AssetTypeServiceAccount:
		return asset.AssetTypeServiceAccount

	// Recon-discovered
	case ctis.AssetTypeHTTPService:
		return asset.AssetTypeHTTPService
	case ctis.AssetTypeOpenPort:
		return asset.AssetTypeOpenPort
	case ctis.AssetTypeDiscoveredURL:
		return asset.AssetTypeDiscoveredURL

	default:
		return asset.AssetTypeUnclassified
	}
}

// =============================================================================
// Criticality Mapping
// =============================================================================

// mapCTISCriticality maps CTIS criticality to domain criticality.
func mapCTISCriticality(ctisCrit ctis.Criticality) asset.Criticality {
	switch ctisCrit {
	case ctis.CriticalityCritical:
		return asset.CriticalityCritical
	case ctis.CriticalityHigh:
		return asset.CriticalityHigh
	case ctis.CriticalityMedium:
		return asset.CriticalityMedium
	case ctis.CriticalityLow:
		return asset.CriticalityLow
	default:
		return asset.CriticalityMedium
	}
}

// =============================================================================
// Severity Mapping
// =============================================================================

// mapSDKSeverity maps SDK severity level to domain severity.
func mapSDKSeverity(sev severity.Level) vulnerability.Severity {
	switch sev {
	case severity.Critical:
		return vulnerability.SeverityCritical
	case severity.High:
		return vulnerability.SeverityHigh
	case severity.Medium:
		return vulnerability.SeverityMedium
	case severity.Low:
		return vulnerability.SeverityLow
	case severity.Info:
		return vulnerability.SeverityNone
	default:
		return vulnerability.SeverityMedium
	}
}

// =============================================================================
// Finding Source Detection
// =============================================================================

// detectFindingSource determines the finding source from tool info.
func detectFindingSource(toolName string, capabilities []string) vulnerability.FindingSource {
	toolLower := strings.ToLower(toolName)

	// Check capabilities first
	for _, cap := range capabilities {
		capLower := strings.ToLower(cap)
		switch {
		case strings.Contains(capLower, "sast"):
			return vulnerability.FindingSourceSAST
		case strings.Contains(capLower, "sca"):
			return vulnerability.FindingSourceSCA
		case strings.Contains(capLower, "dast"):
			return vulnerability.FindingSourceDAST
		case strings.Contains(capLower, "secret"):
			return vulnerability.FindingSourceSecret
		case strings.Contains(capLower, "container"):
			return vulnerability.FindingSourceContainer
		case strings.Contains(capLower, "iac"):
			return vulnerability.FindingSourceIaC
		}
	}

	// Infer from tool name
	switch {
	case strings.Contains(toolLower, "semgrep"), strings.Contains(toolLower, "codeql"):
		return vulnerability.FindingSourceSAST
	case strings.Contains(toolLower, "snyk"), strings.Contains(toolLower, "dependabot"):
		return vulnerability.FindingSourceSCA
	case strings.Contains(toolLower, "nuclei"), strings.Contains(toolLower, "zap"):
		return vulnerability.FindingSourceDAST
	case strings.Contains(toolLower, "gitleaks"), strings.Contains(toolLower, "trufflehog"):
		return vulnerability.FindingSourceSecret
	case strings.Contains(toolLower, "trivy"), strings.Contains(toolLower, "grype"):
		return vulnerability.FindingSourceContainer
	case strings.Contains(toolLower, "tfsec"), strings.Contains(toolLower, "checkov"):
		return vulnerability.FindingSourceIaC
	default:
		return vulnerability.FindingSourceSAST
	}
}

// =============================================================================
// Property Builders
// =============================================================================

// buildDomainProperties builds properties from CTIS DomainTechnical.
func buildDomainProperties(domain *ctis.DomainTechnical) map[string]any {
	props := make(map[string]any)

	if domain.Registrar != "" {
		props["registrar"] = domain.Registrar
	}
	if domain.RegisteredAt != nil {
		props["registered_at"] = domain.RegisteredAt.Format(time.RFC3339)
	}
	if domain.ExpiresAt != nil {
		props["expires_at"] = domain.ExpiresAt.Format(time.RFC3339)
	}
	if len(domain.Nameservers) > 0 {
		props["nameservers"] = domain.Nameservers
	}
	if len(domain.DNSRecords) > 0 {
		records := make([]map[string]any, 0, len(domain.DNSRecords))
		for _, rec := range domain.DNSRecords {
			records = append(records, map[string]any{
				"type":  rec.Type,
				"name":  rec.Name,
				"value": rec.Value,
				"ttl":   rec.TTL,
			})
		}
		props["dns_records"] = records
	}
	if len(domain.WHOIS) > 0 {
		props["whois"] = domain.WHOIS
	}

	return props
}

// buildIPAddressProperties builds properties from CTIS IPAddressTechnical.
func buildIPAddressProperties(ip *ctis.IPAddressTechnical) map[string]any {
	props := make(map[string]any)

	if ip.Version != 0 {
		props["version"] = ip.Version
	}
	if ip.Hostname != "" {
		props["hostname"] = ip.Hostname
	}
	if ip.ASN != 0 {
		props["asn"] = ip.ASN
	}
	if ip.ASNOrg != "" {
		props["asn_org"] = ip.ASNOrg
	}
	if ip.Country != "" {
		props["country"] = ip.Country
	}
	if ip.City != "" {
		props["city"] = ip.City
	}
	if len(ip.Ports) > 0 {
		ports := make([]map[string]any, 0, len(ip.Ports))
		for _, p := range ip.Ports {
			portInfo := map[string]any{
				"port":     p.Port,
				"protocol": p.Protocol,
				"state":    p.State,
			}
			if p.Service != "" {
				portInfo["service"] = p.Service
			}
			if p.Version != "" {
				portInfo["version"] = p.Version
			}
			if p.Banner != "" {
				portInfo["banner"] = p.Banner
			}
			ports = append(ports, portInfo)
		}
		props["ports"] = ports
	}
	if ip.Geolocation != nil {
		props["geolocation"] = map[string]any{
			"latitude":  ip.Geolocation.Latitude,
			"longitude": ip.Geolocation.Longitude,
			"accuracy":  ip.Geolocation.Accuracy,
		}
	}

	return props
}

// buildServiceProperties builds properties from CTIS ServiceTechnical.
func buildServiceProperties(svc *ctis.ServiceTechnical) map[string]any {
	props := make(map[string]any)

	if svc.Name != "" {
		props["name"] = svc.Name
	}
	if svc.Version != "" {
		props["version"] = svc.Version
	}
	if svc.Product != "" {
		props["product"] = svc.Product
	}
	if svc.Port != 0 {
		props["port"] = svc.Port
	}
	if svc.Protocol != "" {
		props["protocol"] = svc.Protocol
	}
	props["tls"] = svc.TLS
	if svc.Banner != "" {
		props["banner"] = svc.Banner
	}
	if svc.Transport != "" {
		props["transport"] = svc.Transport
	}
	if svc.ExtraInfo != "" {
		props["extra_info"] = svc.ExtraInfo
	}

	return props
}

// buildCertificateProperties builds properties from CTIS CertificateTechnical.
func buildCertificateProperties(cert *ctis.CertificateTechnical) map[string]any {
	props := make(map[string]any)

	if cert.SerialNumber != "" {
		props["serial_number"] = cert.SerialNumber
	}
	if cert.SubjectCN != "" {
		props["subject_cn"] = cert.SubjectCN
	}
	if len(cert.SANs) > 0 {
		props["sans"] = cert.SANs
	}
	if cert.IssuerCN != "" {
		props["issuer_cn"] = cert.IssuerCN
	}
	if cert.IssuerOrg != "" {
		props["issuer_org"] = cert.IssuerOrg
	}
	if cert.NotBefore != nil {
		props["not_before"] = cert.NotBefore.Format(time.RFC3339)
	}
	if cert.NotAfter != nil {
		props["not_after"] = cert.NotAfter.Format(time.RFC3339)
	}
	if cert.SignatureAlgorithm != "" {
		props["signature_algorithm"] = cert.SignatureAlgorithm
	}
	if cert.KeyAlgorithm != "" {
		props["key_algorithm"] = cert.KeyAlgorithm
	}
	if cert.KeySize != 0 {
		props["key_size"] = cert.KeySize
	}
	if cert.Fingerprint != "" {
		props["fingerprint"] = cert.Fingerprint
	}
	props["self_signed"] = cert.SelfSigned
	props["expired"] = cert.Expired

	return props
}
