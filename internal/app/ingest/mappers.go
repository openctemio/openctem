package ingest

import (
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/eis"
	"github.com/openctemio/sdk/pkg/shared/severity"
)

// =============================================================================
// Asset Type Mapping
// =============================================================================

// mapEISAssetType maps EIS asset type to domain asset type.
//
//nolint:cyclop // Type mapping switch requires a case per asset type
func mapEISAssetType(eisType eis.AssetType) asset.AssetType {
	switch eisType {
	// Discovery / External Attack Surface
	case eis.AssetTypeDomain:
		return asset.AssetTypeDomain
	case eis.AssetTypeSubdomain:
		return asset.AssetTypeSubdomain
	case eis.AssetTypeIPAddress:
		return asset.AssetTypeIPAddress
	case eis.AssetTypeCertificate:
		return asset.AssetTypeCertificate

	// Applications
	case eis.AssetTypeWebsite:
		return asset.AssetTypeWebsite
	case eis.AssetTypeWebApplication:
		return asset.AssetTypeWebApplication
	case eis.AssetTypeAPI:
		return asset.AssetTypeAPI
	case eis.AssetTypeMobileApp:
		return asset.AssetTypeMobileApp
	case eis.AssetTypeService:
		return asset.AssetTypeService

	// Code / Repository
	case eis.AssetTypeRepository:
		return asset.AssetTypeRepository

	// Cloud
	case eis.AssetTypeCloudAccount:
		return asset.AssetTypeCloudAccount
	case eis.AssetTypeCompute:
		return asset.AssetTypeCompute
	case eis.AssetTypeStorage:
		return asset.AssetTypeStorage
	case eis.AssetTypeDatabase:
		return asset.AssetTypeDatabase
	case eis.AssetTypeServerless:
		return asset.AssetTypeServerless
	case eis.AssetTypeContainerRegistry:
		return asset.AssetTypeContainerRegistry

	// Infrastructure
	case eis.AssetTypeHost:
		return asset.AssetTypeHost
	case eis.AssetTypeServer:
		return asset.AssetTypeServer
	case eis.AssetTypeContainer:
		return asset.AssetTypeContainer
	case eis.AssetTypeKubernetes:
		return asset.AssetTypeKubernetesCluster
	case eis.AssetTypeKubernetesCluster:
		return asset.AssetTypeKubernetesCluster
	case eis.AssetTypeKubernetesNamespace:
		return asset.AssetTypeKubernetesNamespace

	// Network
	case eis.AssetTypeNetwork:
		return asset.AssetTypeNetwork
	case eis.AssetTypeVPC:
		return asset.AssetTypeVPC
	case eis.AssetTypeSubnet:
		return asset.AssetTypeSubnet
	case eis.AssetTypeLoadBalancer:
		return asset.AssetTypeLoadBalancer
	case eis.AssetTypeFirewall:
		return asset.AssetTypeFirewall

	// Identity / IAM
	case eis.AssetTypeIAMUser:
		return asset.AssetTypeIAMUser
	case eis.AssetTypeIAMRole:
		return asset.AssetTypeIAMRole
	case eis.AssetTypeServiceAccount:
		return asset.AssetTypeServiceAccount

	// Recon-discovered
	case eis.AssetTypeHTTPService:
		return asset.AssetTypeHTTPService
	case eis.AssetTypeOpenPort:
		return asset.AssetTypeOpenPort
	case eis.AssetTypeDiscoveredURL:
		return asset.AssetTypeDiscoveredURL

	default:
		return asset.AssetTypeUnclassified
	}
}

// =============================================================================
// Criticality Mapping
// =============================================================================

// mapEISCriticality maps EIS criticality to domain criticality.
func mapEISCriticality(eisCrit eis.Criticality) asset.Criticality {
	switch eisCrit {
	case eis.CriticalityCritical:
		return asset.CriticalityCritical
	case eis.CriticalityHigh:
		return asset.CriticalityHigh
	case eis.CriticalityMedium:
		return asset.CriticalityMedium
	case eis.CriticalityLow:
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

// buildDomainProperties builds properties from EIS DomainTechnical.
func buildDomainProperties(domain *eis.DomainTechnical) map[string]any {
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

// buildIPAddressProperties builds properties from EIS IPAddressTechnical.
func buildIPAddressProperties(ip *eis.IPAddressTechnical) map[string]any {
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

// buildServiceProperties builds properties from EIS ServiceTechnical.
func buildServiceProperties(svc *eis.ServiceTechnical) map[string]any {
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

// buildCertificateProperties builds properties from EIS CertificateTechnical.
func buildCertificateProperties(cert *eis.CertificateTechnical) map[string]any {
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
