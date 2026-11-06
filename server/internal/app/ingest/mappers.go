package ingest

import (
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/severity"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// =============================================================================
// Asset Type Mapping
// =============================================================================

// ctisResolvedType is a CTIS asset's type resolved to what is stored, plus
// the (type, sub_type) its name is normalized with.
type ctisResolvedType struct {
	stored asset.ResolvedType
	// normType/normSubType key the name normalization: the stored type and
	// the sub-type the CTIS type itself implies (an alias's sub-type), as
	// ingest has always normalized, so lookups keep finding existing names.
	// A legacy sub-type that moves the asset to another type keys by the
	// new pair.
	normType    asset.AssetType
	normSubType string
}

// resolveCTISAssetType resolves a CTIS 2.0 asset's wire type to the stored
// (type, sub_type) pair (RFC-042 §6.3.8). The stored model is unchanged by
// CTIS 2.0: the collapsed wire types map onto it (mapCTISAssetType), and the
// accepted input names live in configs/asset-types.yaml (type_inputs).
// Machine input is resolved leniently: an unknown sub-type is kept in
// x_native_sub_type, never refused, and an unknown type is `unclassified`.
// properties carry no meaning in CTIS 2.0, so nothing there moves an asset
// to another type.
func resolveCTISAssetType(ca *ctis.Asset) ctisResolvedType {
	raw, sub := mapCTISAssetType(ca)
	full, err := asset.ResolveInputTypeLenient(string(raw), sub)
	if err != nil {
		full = asset.ResolvedType{Type: asset.AssetTypeUnclassified}
	}
	return ctisResolvedType{stored: full, normType: full.Type, normSubType: full.SubType}
}

// assetNameOf is the name an ingested CTIS asset is stored under: its value,
// which CTIS 2.0 requires in the canonical form of its type. name is a
// display label and never the identity.
func assetNameOf(ca *ctis.Asset) string {
	return strings.TrimSpace(ca.Value)
}

// domainNameStoredType is the stored type of a CTIS domain_name: a
// registrable name (the public-suffix apex plus one label) is a domain,
// anything below it a subdomain. A name the public suffix list cannot place
// stays a domain.
func domainNameStoredType(name string) asset.AssetType {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	etld1, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || etld1 == name {
		return asset.AssetTypeDomain
	}
	return asset.AssetTypeSubdomain
}

// identityKindSubType maps technical.identity.kind to the stored identity
// sub-type. A kind with no stored sub-type is kept as the native sub-type.
func identityKindSubType(ca *ctis.Asset) string {
	if ca.Technical == nil || ca.Technical.Identity == nil {
		return ""
	}
	switch ca.Technical.Identity.Kind {
	case ctis.IdentityUser:
		return "iam_user"
	case ctis.IdentityRole:
		return "iam_role"
	case ctis.IdentityServiceAccount:
		return "service_account"
	default:
		return string(ca.Technical.Identity.Kind)
	}
}

// mapCTISAssetType maps a CTIS 2.0 wire type to the input (type, sub_type)
// the registry resolves to the stored pair (docs/profiles/openctem.md of the
// CTIS module, section 5). Wire names that are not stored types themselves
// are `type_inputs` of configs/asset-types.yaml; the cases here are the ones
// that need the asset (domain apex, identity kind) or a fixed sub-type.
func mapCTISAssetType(ca *ctis.Asset) (asset.AssetType, string) {
	switch ca.Type {
	case ctis.AssetTypeDomainName:
		return domainNameStoredType(ca.Value), ""
	case ctis.AssetTypeService:
		// host:port/transport: the stored open_port service.
		return asset.AssetTypeService, "open_port"
	case ctis.AssetTypeIdentity:
		return asset.AssetTypeIdentity, identityKindSubType(ca)
	case ctis.AssetTypeNetworkDevice:
		return asset.AssetTypeNetwork, networkDeviceSubType(ca)
	case "":
		return asset.AssetTypeUnclassified, ""
	}
	if t, ok := ctisWireTypes[ca.Type]; ok {
		return t.typ, t.sub
	}
	// Stored types (host, ip_address, certificate, repository, ...) and the
	// registry's type_inputs (kubernetes_cluster, web_application, ...). An
	// unknown name resolves to unclassified.
	return asset.AssetType(ca.Type), ""
}

// ctisWireTypes are the CTIS 2.0 wire types that are no stored type and need
// nothing from the asset to place. They live here, not in the registry's
// type_inputs, so the REST API's asset type inputs stay unchanged.
var ctisWireTypes = map[ctis.AssetType]struct {
	typ asset.AssetType
	sub string
}{
	ctis.AssetTypeWebOrigin:          {asset.AssetTypeService, "http"},
	ctis.AssetTypeIPRange:            {asset.AssetTypeNetwork, ""},
	ctis.AssetTypeContainerImage:     {asset.AssetTypeContainer, "image"},
	ctis.AssetTypeKubernetesWorkload: {asset.AssetTypeKubernetes, "workload"},
	ctis.AssetTypeEndpointDevice:     {asset.AssetTypeHost, "workstation"},
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
		// An informational finding is info, not none: none is a CVSS score of
		// zero, and a list filtered on info must show it.
		return vulnerability.SeverityInfo
	default:
		return vulnerability.SeverityMedium
	}
}

// =============================================================================
// Finding Source Detection
// =============================================================================

// techniqueSource maps a CTIS 2.0 detection technique (tool.techniques,
// finding.technique; a closed vocabulary) to the stored finding source.
var techniqueSource = map[ctis.Technique]vulnerability.FindingSource{
	ctis.TechniqueSAST:      vulnerability.FindingSourceSAST,
	ctis.TechniqueSCA:       vulnerability.FindingSourceSCA,
	ctis.TechniqueSecret:    vulnerability.FindingSourceSecret,
	ctis.TechniqueIaC:       vulnerability.FindingSourceIaC,
	ctis.TechniqueContainer: vulnerability.FindingSourceContainer,
	ctis.TechniqueDAST:      vulnerability.FindingSourceDAST,
	ctis.TechniqueVA:        vulnerability.FindingSourceVA,
	ctis.TechniqueEASM:      vulnerability.FindingSourceEASM,
	ctis.TechniqueCSPM:      vulnerability.FindingSourceCSPM,
	ctis.TechniqueBAS:       vulnerability.FindingSourceRedTeam,
	ctis.TechniquePentest:   vulnerability.FindingSourcePentest,
	ctis.TechniqueManual:    vulnerability.FindingSourceManual,
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
	{"opengrep", vulnerability.FindingSourceSAST},
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

	{"betterleaks", vulnerability.FindingSourceSecret},
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

// detectFindingSource works out which technique produced a finding: the
// first technique the table knows (finding.technique before the tool's), then
// the tool name. The techniques win: the tool name is caller-controlled
// through ?tool=, so name-based inference alone can be steered.
func detectFindingSource(toolName string, techniques ...ctis.Technique) vulnerability.FindingSource {
	for _, t := range techniques {
		if src, ok := techniqueSource[t]; ok {
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

	if svc.Version != "" {
		props["version"] = svc.Version
	}
	if svc.Product != "" {
		props["product"] = svc.Product
	}
	if svc.Port != 0 {
		props["port"] = svc.Port
	}
	// The application protocol (IANA service name) is the stored
	// "protocol" attribute; the transport has its own.
	if svc.AppProtocol != "" {
		props["protocol"] = svc.AppProtocol
	}
	// A false TLS is what an unmeasured report sends too, so only a TLS the
	// scanner saw is recorded (has_tls once promoted).
	if svc.IsTLS {
		props["tls"] = true
	}
	if svc.Banner != "" {
		props["banner"] = svc.Banner
	}
	if svc.Transport != "" {
		props["transport"] = string(svc.Transport)
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
		props["tls_version"] = string(svc.TLSVersion)
	}
	// The certificate a service serves is its own asset in CTIS 2.0
	// (serves_certificate), not attributes of the service.
	if svc.State != "" {
		props["state"] = string(svc.State)
	}
	if svc.IsAuthRequired {
		props["auth_required"] = true
	}
	// Only an access the probe saw is recorded: false is also what an
	// unmeasured report sends.
	if svc.HasAnonymousAccess {
		props[asset.PropKeyHasAnonymousAccess] = true
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
	if len(cert.SubjectAltNames) > 0 {
		props["sans"] = cert.SubjectAltNames
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
	if cert.SHA256Fingerprint != "" {
		props["fingerprint"] = cert.SHA256Fingerprint
	}
	props["self_signed"] = cert.IsSelfSigned
	if cert.IsWildcard {
		props["is_wildcard"] = true
	}
	// expired is derived, never reported (CTIS 2.0): from not_after at
	// ingest time.
	if cert.NotAfter != nil {
		props["expired"] = cert.NotAfter.Before(time.Now())
	}

	return props
}

// buildHTTPProperties builds the flat attributes of a stored http service
// from CTIS HTTPTechnical (the security headers become http_posture in
// sanitizeHTTPPosture).
func buildHTTPProperties(h *ctis.HTTPTechnical) map[string]any {
	if h == nil {
		return nil
	}
	props := make(map[string]any)
	if h.StatusCode != 0 {
		props["status_code"] = h.StatusCode
	}
	for k, v := range map[string]string{
		"title": h.Title, propServer: h.WebServer, "content_type": h.ContentType,
		"redirect_url": h.RedirectURL, "cdn": h.CDN, "waf": h.WAF, "jarm": h.JARM,
		"favicon_mmh3": h.FaviconMMH3, "tls_version": string(h.TLSVersion),
	} {
		if v != "" {
			props[k] = v
		}
	}
	return props
}

// networkDeviceSubType maps technical.network_device.kind to the stored
// network sub-type of a device; other or absent is no sub-type.
func networkDeviceSubType(ca *ctis.Asset) string {
	if ca.Technical == nil || ca.Technical.NetworkDevice == nil {
		return ""
	}
	switch k := ca.Technical.NetworkDevice.Kind; k {
	case ctis.NetworkDeviceRouter, ctis.NetworkDeviceSwitch, ctis.NetworkDeviceFirewall,
		ctis.NetworkDeviceLoadBalancer, ctis.NetworkDeviceVPNGateway:
		return string(k)
	case ctis.NetworkDeviceWirelessAccessPoint:
		return "access_point"
	}
	return ""
}
