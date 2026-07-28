package ingest

import (
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/severity"
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
		return asset.AssetTypeHost
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
// capabilityToSource maps a tool capability to the technique it implies.
//
// Matched on whole tokens, deliberately. This used to use strings.Contains,
// which mis-routed every one of these:
//
//	["java", "sast"]            -> va    ("java" contains "va")
//	["advanced", "dast"]        -> va    ("advanced" contains "va")
//	["privacy", "secret"]       -> va    ("privacy" contains "va")
//	["cloudflare", "iac"]       -> cspm  ("cloudflare" contains "cloud")
//	["reconfiguration", "iac"]  -> easm  ("reconfiguration" contains "recon")
//	["vulnerability-scan"]      -> sca   (ends in "-scan", contains "sca")
//
// The first match short-circuits, so a bogus early token beat the correct later
// one. Capabilities are a free-form array supplied by whoever pushes the report,
// so this is reachable by any third-party producer, not only by ours.
var capabilityToSource = map[string]vulnerability.FindingSource{
	// Emitted by the agent's executors.
	"sast":      vulnerability.FindingSourceSAST,
	"sca":       vulnerability.FindingSourceSCA,
	"dast":      vulnerability.FindingSourceDAST,
	"secret":    vulnerability.FindingSourceSecret,
	"iac":       vulnerability.FindingSourceIaC,
	"container": vulnerability.FindingSourceContainer,

	// Emitted by ctis/sarif.go detectCapabilities.
	"misconfiguration": vulnerability.FindingSourceIaC,
	"web3":             vulnerability.FindingSourceSAST,

	// Recon capabilities from the agent's discovery executor.
	"subdomain":   vulnerability.FindingSourceEASM,
	"dns":         vulnerability.FindingSourceEASM,
	"portscan":    vulnerability.FindingSourceEASM,
	"crawler":     vulnerability.FindingSourceEASM,
	"tech-detect": vulnerability.FindingSourceEASM,

	// Set explicitly by our importers so the mapper does not have to guess.
	"va":       vulnerability.FindingSourceVA,
	"easm":     vulnerability.FindingSourceEASM,
	"cspm":     vulnerability.FindingSourceCSPM,
	"external": vulnerability.FindingSourceExternal,
	"import":   vulnerability.FindingSourceExternal,
}

// toolNameToSource maps a substring of a tool name to its technique.
//
// Substring matching is defensible here in a way it is not for capabilities:
// these are product names, distinctive enough that a coincidental match is
// implausible, and versions and vendor prefixes ("aquasec/trivy:0.50") need to
// still match.
var toolNameToSource = []struct {
	needle string
	source vulnerability.FindingSource
}{
	{"semgrep", vulnerability.FindingSourceSAST},
	{"codeql", vulnerability.FindingSourceSAST},
	{"sonarqube", vulnerability.FindingSourceSAST},
	{"sonarcloud", vulnerability.FindingSourceSAST},
	{"bandit", vulnerability.FindingSourceSAST},
	{"checkmarx", vulnerability.FindingSourceSAST},
	{"veracode", vulnerability.FindingSourceSAST},
	{"fortify", vulnerability.FindingSourceSAST},
	{"slither", vulnerability.FindingSourceSAST},
	{"mythril", vulnerability.FindingSourceSAST},

	{"snyk", vulnerability.FindingSourceSCA},
	{"dependabot", vulnerability.FindingSourceSCA},
	{"govulncheck", vulnerability.FindingSourceSCA},
	{"npm-audit", vulnerability.FindingSourceSCA},
	{"pip-audit", vulnerability.FindingSourceSCA},

	{"nuclei", vulnerability.FindingSourceDAST},
	{"zap", vulnerability.FindingSourceDAST},
	{"burp", vulnerability.FindingSourceDAST},

	{"gitleaks", vulnerability.FindingSourceSecret},
	{"trufflehog", vulnerability.FindingSourceSecret},

	{"trivy", vulnerability.FindingSourceContainer},
	{"grype", vulnerability.FindingSourceContainer},

	{"tfsec", vulnerability.FindingSourceIaC},
	{"checkov", vulnerability.FindingSourceIaC},

	{"nessus", vulnerability.FindingSourceVA},
	{"tenable", vulnerability.FindingSourceVA},
	{"qualys", vulnerability.FindingSourceVA},
	{"openvas", vulnerability.FindingSourceVA},

	{"subfinder", vulnerability.FindingSourceEASM},
	{"httpx", vulnerability.FindingSourceEASM},
	{"naabu", vulnerability.FindingSourceEASM},
	{"masscan", vulnerability.FindingSourceEASM},
	{"amass", vulnerability.FindingSourceEASM},
	{"nmap", vulnerability.FindingSourceEASM},

	{"prowler", vulnerability.FindingSourceCSPM},
	{"scoutsuite", vulnerability.FindingSourceCSPM},
	{"steampipe", vulnerability.FindingSourceCSPM},
}

// detectFindingSource works out which technique produced a finding.
//
// Capabilities win over the tool name: our importers set them explicitly, and
// the tool name is caller-controlled through ?tool=, so name-based inference
// alone can be steered.
//
// Note the tokens deliberately absent from capabilityToSource: "vulnerability"
// and "infra". Both are emitted by real producers and both are too generic to
// decide a technique — "vulnerability" is true of nearly every scanner, and
// ctis emits it for trivy alongside "misconfiguration". Letting them fall
// through to the tool name keeps trivy classified as a container scan rather
// than reclassifying it on a word that means nothing in particular.
// matchCapability resolves one capability string.
//
// The whole value is tried first so multi-word keys like "tech-detect" match,
// then each token, so compound names like "secret_detection",
// "container_scanning" and "iac_analysis" — which real producers emit and which
// the substring version handled by accident — keep working.
//
// Tokenising is what makes this safe where Contains was not: "java" is one
// token and matches nothing, whereas Contains found "va" inside it.
func matchCapability(capability string) (vulnerability.FindingSource, bool) {
	normalized := strings.ToLower(strings.TrimSpace(capability))
	if src, ok := capabilityToSource[normalized]; ok {
		return src, true
	}
	for _, token := range strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == '/' || r == ' ' || r == ':'
	}) {
		if src, ok := capabilityToSource[token]; ok {
			return src, true
		}
	}
	return "", false
}

func detectFindingSource(toolName string, capabilities []string) vulnerability.FindingSource {
	for _, capability := range capabilities {
		if src, ok := matchCapability(capability); ok {
			return src
		}
	}

	toolLower := strings.ToLower(toolName)
	for _, entry := range toolNameToSource {
		if strings.Contains(toolLower, entry.needle) {
			return entry.source
		}
	}

	// Not SAST. An unrecognized tool is unknown provenance, not static code
	// analysis, and guessing a specific technique is worse than admitting
	// ignorance: it is how every Tenable and DefectDojo import came to be filed
	// as source code analysis.
	return vulnerability.FindingSourceExternal
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

	// CPE is the CVE-correlation join key — dropping it (as before) silently
	// degraded vuln matching. Preserve it plus the TLS/cert + state/auth detail
	// the scanner provides.
	if svc.CPE != "" {
		props["cpe"] = svc.CPE
	}
	if svc.TLSVersion != "" {
		props["tls_version"] = svc.TLSVersion
	}
	if svc.TLSCertSubject != "" {
		props["tls_cert_subject"] = svc.TLSCertSubject
	}
	if svc.TLSCertIssuer != "" {
		props["tls_cert_issuer"] = svc.TLSCertIssuer
	}
	if svc.TLSCertExpiry != "" {
		props["tls_cert_expiry"] = svc.TLSCertExpiry
	}
	if svc.State != "" {
		props["state"] = svc.State
	}
	if svc.AuthRequired {
		props["auth_required"] = true
	}
	if len(svc.AuthMethods) > 0 {
		props["auth_methods"] = svc.AuthMethods
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
