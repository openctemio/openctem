package asset

import (
	"net"
	"net/url"
	"strings"
	"unicode"
)

// NormalizeName returns the canonical form of an asset name for the given type
// and optional sub_type. This is the single chokepoint for name normalization —
// called from NewAsset constructor and UpdateName.
//
// Design principles:
//   - Idempotent: NormalizeName(NormalizeName(x)) == NormalizeName(x)
//   - Deterministic: same input always produces same output
//   - Never returns empty if input was non-empty (after trim)
//   - Type-aware: each asset type has specific rules
func NormalizeName(name string, assetType AssetType, subType string) string {
	name = commonNormalize(name)
	if name == "" {
		return ""
	}

	switch assetType {
	case AssetTypeDomain, AssetTypeSubdomain:
		return normalizeDNSName(name)
	case AssetTypeIPAddress:
		return normalizeIPAddress(name)
	case AssetTypeHost:
		return normalizeHostName(name)
	case AssetTypeEndpoint:
		// endpoints are user-operated devices. Names arrive as
		// hostname (laptop-uk-0141), FQDN (laptop-uk-0141.corp.example),
		// or agent GUID. Reuse the host-name normalizer — same rules
		// (lowercase, strip trailing dot, DNS label validation).
		return normalizeHostName(name)
	case AssetTypeService, AssetTypeHTTPService, AssetTypeOpenPort, AssetTypeDiscoveredURL:
		return normalizeServiceName(name, subType)
	case AssetTypeApplication, AssetTypeWebsite, AssetTypeWebApplication, AssetTypeAPI:
		return normalizeURL(name)
	case AssetTypeMobileApp:
		return strings.ToLower(name)
	case AssetTypeRepository:
		return normalizeRepoName(name)
	case AssetTypeCertificate:
		return normalizeCertName(name)
	case AssetTypeDatabase, AssetTypeDataStore:
		return normalizeDatabaseName(name)
	case AssetTypeNetwork, AssetTypeSubnet:
		return normalizeNetworkName(name)
	case AssetTypeStorage, AssetTypeS3Bucket, AssetTypeContainerRegistry:
		return normalizeStorageName(name, subType)
	case AssetTypeContainer:
		return strings.ToLower(name)
	case AssetTypeKubernetes, AssetTypeKubernetesCluster, AssetTypeKubernetesNamespace:
		return strings.ToLower(name)
	case AssetTypeCloudAccount:
		return strings.ToLower(name)
	case AssetTypeVPC:
		return strings.ToLower(name)
	case AssetTypeIdentity, AssetTypeIAMUser, AssetTypeIAMRole, AssetTypeServiceAccount:
		// Identity names can be case-sensitive (ARNs), only trim
		return name
	default:
		return name
	}
}

// commonNormalize applies universal cleanup to all asset names.
func commonNormalize(name string) string {
	// Strip null bytes
	name = strings.ReplaceAll(name, "\x00", "")

	// Strip zero-width characters
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if isZeroWidth(r) {
			continue
		}
		// Replace control chars (except space/tab) with space
		if unicode.IsControl(r) && r != ' ' && r != '\t' {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	name = b.String()

	// Collapse multiple spaces
	for strings.Contains(name, "  ") {
		name = strings.ReplaceAll(name, "  ", " ")
	}

	return strings.TrimSpace(name)
}

func isZeroWidth(r rune) bool {
	return r == '\u200B' || // zero-width space
		r == '\u200C' || // zero-width non-joiner
		r == '\u200D' || // zero-width joiner
		r == '\uFEFF' // BOM / zero-width no-break space
}

// ─── DNS Names ────────────────────────────────────────────────────────

// normalizeDNSName normalizes domain and subdomain names.
// DNS is case-insensitive per RFC 4343.
func normalizeDNSName(name string) string {
	// Strip protocol if accidentally included
	name = stripProtocol(name)
	// Strip port if accidentally included
	name = stripPort(name)
	// Strip path if accidentally included
	if idx := strings.Index(name, "/"); idx > 0 {
		name = name[:idx]
	}
	name = strings.ToLower(name)
	name = strings.TrimRight(name, ".")
	name = strings.TrimLeft(name, ".")
	return name
}

// ─── Host Names ───────────────────────────────────────────────────────

// normalizeHostName normalizes host asset names.
// If the name is an IP, normalize as IP. Otherwise treat as DNS name.
func normalizeHostName(name string) string {
	// Strip protocol
	name = stripProtocol(name)
	// Strip port
	name = stripPort(name)

	// Try parsing as IP first
	if ip := net.ParseIP(name); ip != nil {
		// Normalize IPv4-mapped IPv6 to IPv4
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}

	// It's a hostname — normalize as DNS
	return normalizeDNSName(name)
}

// ─── IP Addresses ─────────────────────────────────────────────────────

// normalizeIPAddress normalizes IP address names to canonical form.
func normalizeIPAddress(name string) string {
	// Strip protocol
	name = stripProtocol(name)
	// Handle [IPv6]:port format — use SplitHostPort first
	if strings.HasPrefix(name, "[") {
		if host, _, err := net.SplitHostPort(name); err == nil {
			name = host
		} else {
			// Just brackets, no port: [2001:db8::1]
			name = strings.Trim(name, "[]")
		}
	}
	// Strip port (for IPv4:port)
	name = stripPort(name)
	// Strip /32 or /128 single-host CIDR
	if strings.HasSuffix(name, "/32") || strings.HasSuffix(name, "/128") {
		name = name[:strings.LastIndex(name, "/")]
	}
	// Strip zone ID (%eth0)
	if idx := strings.Index(name, "%"); idx > 0 {
		name = name[:idx]
	}
	// Canonical form
	ip := net.ParseIP(name)
	if ip == nil {
		return strings.TrimSpace(name)
	}
	// Normalize IPv4-mapped IPv6 to IPv4
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// ─── Service Names ────────────────────────────────────────────────────

// normalizeServiceName normalizes service asset names based on sub_type.
func normalizeServiceName(name string, subType string) string {
	switch subType {
	case "http":
		return normalizeURL(name)
	case "discovered_url":
		return normalizeDiscoveredURL(name)
	case "open_port", "":
		return normalizePortIdentifier(name)
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

// normalizePortIdentifier normalizes "host:port/proto" or "host:port:proto" to "host:port:proto".
// Also handles IPv6: "[2001:db8::1]:443:tcp" or "[2001:db8::1]:443/tcp".
func normalizePortIdentifier(name string) string {
	// Handle IPv6 in brackets: [IPv6]:port:proto or [IPv6]:port/proto
	if strings.HasPrefix(name, "[") {
		closeBracket := strings.Index(name, "]")
		if closeBracket > 0 {
			ipv6Host := name[1:closeBracket] // strip brackets
			remainder := name[closeBracket+1:]
			// remainder starts with ":" → ":port:proto" or ":port/proto" or ":port"
			remainder = strings.TrimPrefix(remainder, ":")
			// Replace / with : in remainder
			remainder = strings.ReplaceAll(remainder, "/", ":")
			parts := strings.SplitN(remainder, ":", -1)
			host := normalizeHostName(ipv6Host)
			switch len(parts) {
			case 2:
				// port:proto
				proto := strings.ToLower(parts[1])
				if proto == "" {
					proto = "tcp"
				}
				return host + ":" + parts[0] + ":" + proto
			case 1:
				// port only (default tcp)
				return host + ":" + parts[0] + ":tcp"
			default:
				return strings.ToLower(strings.TrimSpace(name))
			}
		}
	}

	// Replace / separator with :
	name = strings.ReplaceAll(name, "/", ":")

	parts := strings.SplitN(name, ":", -1)
	switch len(parts) {
	case 3:
		// host:port:proto
		host := normalizeHostName(parts[0])
		port := parts[1]
		proto := strings.ToLower(parts[2])
		if proto == "" {
			proto = "tcp"
		}
		return host + ":" + port + ":" + proto
	case 2:
		// host:port (default tcp)
		host := normalizeHostName(parts[0])
		port := parts[1]
		return host + ":" + port + ":tcp"
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

// ─── URLs ─────────────────────────────────────────────────────────────

// normalizeURL normalizes URL-based asset names (application, website, API, http service).
func normalizeURL(name string) string {
	// If no scheme, try adding https:// for parsing
	hasScheme := strings.Contains(name, "://")
	parseInput := name
	if !hasScheme {
		parseInput = "https://" + name
	}

	u, err := url.Parse(parseInput)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(name))
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	// Strip default ports
	if (scheme == "https" && strings.HasSuffix(host, ":443")) ||
		(scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}

	// Path: keep as-is but strip trailing slash
	path := strings.TrimRight(u.Path, "/")

	// Strip query and fragment for identity
	if hasScheme {
		return scheme + "://" + host + path
	}
	// Original had no scheme — return without scheme
	return host + path
}

// normalizeDiscoveredURL is like normalizeURL but strips query params and fragments.
func normalizeDiscoveredURL(name string) string {
	return normalizeURL(name)
}

// ─── Repository Names ─────────────────────────────────────────────────

// normalizeRepoName normalizes repository asset names.
// Host (platform) is part of identity — github.com/org/repo != gitlab.com/org/repo.
func normalizeRepoName(name string) string {
	// Lowercase first so prefix matching works for HTTPS://
	name = strings.ToLower(name)

	// Strip protocol
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimPrefix(name, "http://")

	// Handle SSH format: git@github.com:org/repo → github.com/org/repo
	if strings.HasPrefix(name, "git@") {
		name = strings.TrimPrefix(name, "git@")
		if idx := strings.Index(name, ":"); idx > 0 {
			name = name[:idx] + "/" + name[idx+1:]
		}
	}

	// Strip .git suffix
	name = strings.TrimSuffix(name, ".git")

	// Strip trailing slash
	name = strings.TrimRight(name, "/")

	// Strip Azure DevOps _git segment
	name = strings.Replace(name, "/_git/", "/", 1)

	// Strip branch/commit references
	for _, ref := range []string{"/tree/", "/blob/", "/commit/", "/branches/"} {
		if idx := strings.Index(name, ref); idx > 0 {
			name = name[:idx]
		}
	}

	return name
}

// ─── Certificate Names ────────────────────────────────────────────────

// normalizeCertName normalizes certificate asset names (subject CN or fingerprint).
func normalizeCertName(name string) string {
	name = strings.ToLower(name)
	// Strip trailing dot (DNS name in CN)
	name = strings.TrimRight(name, ".")
	// Normalize fingerprint format: remove colons, spaces
	if isFingerprint(name) {
		name = strings.ReplaceAll(name, ":", "")
		name = strings.ReplaceAll(name, " ", "")
	}
	return name
}

// isFingerprint checks if a name looks like a certificate fingerprint.
func isFingerprint(name string) bool {
	// SHA256: 64 hex chars (possibly with colons: 32 pairs)
	// SHA1: 40 hex chars
	clean := strings.ReplaceAll(strings.ReplaceAll(name, ":", ""), " ", "")
	clean = strings.TrimPrefix(clean, "sha256")
	clean = strings.TrimPrefix(clean, "sha1")
	if len(clean) != 40 && len(clean) != 64 {
		return false
	}
	for _, c := range clean {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ─── Database Names ───────────────────────────────────────────────────

// normalizeDatabaseName normalizes database asset names.
func normalizeDatabaseName(name string) string {
	// Strip protocol (postgres://, mysql://, mongodb://, redis://)
	for _, proto := range []string{
		"postgres://", "postgresql://", "mysql://",
		"mongodb://", "mongodb+srv://", "redis://", "rediss://",
	} {
		if strings.HasPrefix(strings.ToLower(name), proto) {
			name = name[len(proto):]
			break
		}
	}
	// Strip credentials (user:pass@)
	if atIdx := strings.Index(name, "@"); atIdx > 0 {
		name = name[atIdx+1:]
	}
	// Lowercase
	name = strings.ToLower(name)
	// Strip query params
	if qIdx := strings.Index(name, "?"); qIdx > 0 {
		name = name[:qIdx]
	}
	return name
}

// ─── Network Names ────────────────────────────────────────────────────

// normalizeNetworkName normalizes network/subnet names (CIDR or name).
func normalizeNetworkName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// Try parsing as CIDR
	_, network, err := net.ParseCIDR(name)
	if err == nil {
		return network.String() // Canonical CIDR with zeroed host bits
	}
	return name
}

// ─── Storage Names ────────────────────────────────────────────────────

// normalizeStorageName normalizes storage asset names.
func normalizeStorageName(name string, subType string) string {
	switch subType {
	case "s3_bucket":
		name = strings.TrimPrefix(name, "s3://")
		name = strings.TrimPrefix(name, "S3://")
		// Extract bucket from URL: bucket.s3.amazonaws.com → bucket
		if strings.Contains(name, ".s3.") && strings.HasSuffix(name, ".amazonaws.com") {
			name = name[:strings.Index(name, ".s3.")]
		}
		// Extract from path-style: s3.amazonaws.com/bucket/key → bucket (strip object key)
		if strings.HasPrefix(name, "s3.") && strings.Contains(name, "/") {
			parts := strings.SplitN(name, "/", 3)
			if len(parts) >= 2 && parts[1] != "" {
				name = parts[1]
			}
		}
		return strings.ToLower(strings.TrimRight(name, "/"))
	case "container_registry":
		return normalizeURL(name)
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────

// stripProtocol removes common protocol prefixes.
func stripProtocol(name string) string {
	for _, prefix := range []string{"https://", "http://", "ftp://", "ssh://"} {
		if strings.HasPrefix(strings.ToLower(name), prefix) {
			return name[len(prefix):]
		}
	}
	return name
}

// stripPort removes :port from the end of a hostname.
func stripPort(name string) string {
	// Don't strip from IPv6 addresses
	if strings.Count(name, ":") > 1 {
		return name
	}
	if host, _, err := net.SplitHostPort(name); err == nil {
		return host
	}
	return name
}
