package asset

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// DomainMetadata contains domain-specific metadata fields for domain assets.
// These fields should be stored in the asset's metadata map.
type DomainMetadata struct {
	// Domain Hierarchy
	RootDomain      string `json:"root_domain"`      // Root/apex domain (e.g., "techviet.vn")
	DomainLevel     int    `json:"domain_level"`     // 1=root, 2=subdomain, 3=sub-subdomain, etc.
	ParentDomain    string `json:"parent_domain"`    // Parent domain (e.g., "api.techviet.vn" -> "techviet.vn")
	IsWildcard      bool   `json:"is_wildcard"`      // Is this a wildcard domain (*.domain.com)
	DiscoverySource string `json:"discovery_source"` // How discovered: dns, cert_transparency, bruteforce, passive, manual

	// DNS Information
	DNSRecordTypes []string `json:"dns_record_types"` // A, AAAA, CNAME, MX, NS, TXT, etc.
	ResolvedIPs    []string `json:"resolved_ips"`     // IP addresses this domain resolves to
	Nameservers    []string `json:"nameservers"`      // NS records
	MXRecords      []string `json:"mx_records"`       // Mail exchange records
	CNAMETarget    string   `json:"cname_target"`     // CNAME target if applicable
	TTL            int      `json:"ttl"`              // DNS TTL in seconds

	// WHOIS Information
	Registrar         string `json:"registrar"`          // Domain registrar
	WhoisOrganization string `json:"whois_organization"` // Organization from WHOIS
	RegistrationDate  string `json:"registration_date"`  // Domain registration date
	ExpiryDate        string `json:"expiry_date"`        // Domain expiry date
	UpdatedDate       string `json:"updated_date"`       // Last WHOIS update

	// Security
	DNSSECEnabled bool   `json:"dnssec_enabled"` // DNSSEC enabled
	CAA           string `json:"caa"`            // CAA record value
	SPF           string `json:"spf"`            // SPF record
	DKIM          string `json:"dkim"`           // DKIM record
	DMARC         string `json:"dmarc"`          // DMARC record

	// Certificate (linked)
	HasCertificate     bool   `json:"has_certificate"`      // Has SSL/TLS certificate
	CertificateAssetID string `json:"certificate_asset_id"` // Link to certificate asset
}

// DiscoverySource constants for domain discovery
const (
	DiscoverySourceDNS              = "dns"
	DiscoverySourceCertTransparency = "cert_transparency"
	DiscoverySourceBruteforce       = "bruteforce"
	DiscoverySourcePassive          = "passive"
	DiscoverySourceManual           = "manual"
	DiscoverySourceAPIDiscovery     = "api_discovery"
	DiscoverySourceWebCrawl         = "web_crawl"
)

// ExtractRootDomain extracts the root domain from a full domain name.
// e.g., "staging.v2.api.techviet.vn" -> "techviet.vn"
func ExtractRootDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	// Use publicsuffix to correctly handle TLDs like .co.uk, .com.vn, etc.
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback: simple extraction (last 2 parts)
		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return domain
	}
	return etld1
}

// CalculateDomainLevel calculates the domain level.
// Level 1 = root domain (e.g., "techviet.vn")
// Level 2 = first subdomain (e.g., "api.techviet.vn")
// Level 3 = sub-subdomain (e.g., "v2.api.techviet.vn")
// etc.
func CalculateDomainLevel(domain string) int {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	rootDomain := ExtractRootDomain(domain)
	if domain == rootDomain {
		return 1
	}

	// Count parts before root domain
	rootParts := len(strings.Split(rootDomain, "."))
	totalParts := len(strings.Split(domain, "."))

	return totalParts - rootParts + 1
}

// ExtractParentDomain extracts the parent domain.
// e.g., "v2.api.techviet.vn" -> "api.techviet.vn"
// Returns empty string if domain is root domain.
func ExtractParentDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	rootDomain := ExtractRootDomain(domain)
	if domain == rootDomain {
		return ""
	}

	// Remove first part
	idx := strings.Index(domain, ".")
	if idx > 0 {
		return domain[idx+1:]
	}
	return ""
}

// IsWildcardDomain checks if the domain is a wildcard domain.
func IsWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

// NormalizeDomain normalizes a domain name to lowercase, trims spaces and trailing dots.
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// BuildDomainMetadata creates domain metadata from a domain name.
// This is a convenience function for creating metadata with hierarchy information.
func BuildDomainMetadata(domain string, discoverySource string) map[string]any {
	normalizedDomain := NormalizeDomain(domain)
	rootDomain := ExtractRootDomain(normalizedDomain)
	level := CalculateDomainLevel(normalizedDomain)
	parentDomain := ExtractParentDomain(normalizedDomain)
	isWildcard := IsWildcardDomain(domain)

	return map[string]any{
		"root_domain":      rootDomain,
		"domain_level":     level,
		"parent_domain":    parentDomain,
		"is_wildcard":      isWildcard,
		"discovery_source": discoverySource,
	}
}
