package scope

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// =============================================================================
// Target Type
// =============================================================================

// TargetType represents the type of scope target.
type TargetType string

const (
	TargetTypeDomain        TargetType = "domain"
	TargetTypeSubdomain     TargetType = "subdomain"
	TargetTypeIPAddress     TargetType = "ip_address"
	TargetTypeIPRange       TargetType = "ip_range"
	TargetTypeCIDR          TargetType = "cidr"
	TargetTypeURL           TargetType = "url"
	TargetTypeAPI           TargetType = "api"
	TargetTypeWebsite       TargetType = "website"
	TargetTypeRepository    TargetType = "repository"
	TargetTypeProject       TargetType = "project"
	TargetTypeCloudAccount  TargetType = "cloud_account"
	TargetTypeCloudResource TargetType = "cloud_resource"
	TargetTypeContainer     TargetType = "container"
	TargetTypeHost          TargetType = "host"
	TargetTypeDatabase      TargetType = "database"
	TargetTypeNetwork       TargetType = "network"
	TargetTypeCertificate   TargetType = "certificate"
	TargetTypeMobileApp     TargetType = "mobile_app"
	TargetTypeEmailDomain   TargetType = "email_domain"
)

// String returns the string representation of the target type.
func (t TargetType) String() string {
	return string(t)
}

// IsValid returns true if the target type is valid.
func (t TargetType) IsValid() bool {
	switch t {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeIPAddress, TargetTypeIPRange,
		TargetTypeCIDR, TargetTypeURL, TargetTypeAPI, TargetTypeWebsite, TargetTypeRepository,
		TargetTypeProject, TargetTypeCloudAccount, TargetTypeCloudResource, TargetTypeContainer,
		TargetTypeHost, TargetTypeDatabase, TargetTypeNetwork, TargetTypeCertificate,
		TargetTypeMobileApp, TargetTypeEmailDomain:
		return true
	}
	return false
}

// ParseTargetType parses a string into a TargetType.
func ParseTargetType(s string) (TargetType, error) {
	t := TargetType(strings.ToLower(s))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid target type: %s", s)
	}
	return t, nil
}

// AllTargetTypes returns all valid target types.
func AllTargetTypes() []TargetType {
	return []TargetType{
		TargetTypeDomain, TargetTypeSubdomain, TargetTypeIPAddress, TargetTypeIPRange,
		TargetTypeCIDR, TargetTypeURL, TargetTypeAPI, TargetTypeWebsite, TargetTypeRepository,
		TargetTypeProject, TargetTypeCloudAccount, TargetTypeCloudResource, TargetTypeContainer,
		TargetTypeHost, TargetTypeDatabase, TargetTypeNetwork, TargetTypeCertificate,
		TargetTypeMobileApp, TargetTypeEmailDomain,
	}
}

// =============================================================================
// Exclusion Type
// =============================================================================

// ExclusionType represents the type of scope exclusion.
type ExclusionType string

const (
	ExclusionTypeDomain      ExclusionType = "domain"
	ExclusionTypeSubdomain   ExclusionType = "subdomain"
	ExclusionTypeIPAddress   ExclusionType = "ip_address"
	ExclusionTypeIPRange     ExclusionType = "ip_range"
	ExclusionTypeCIDR        ExclusionType = "cidr"
	ExclusionTypeURL         ExclusionType = "url"
	ExclusionTypePath        ExclusionType = "path"
	ExclusionTypeRepository  ExclusionType = "repository"
	ExclusionTypeFindingType ExclusionType = "finding_type"
	ExclusionTypeScanner     ExclusionType = "scanner"
)

// String returns the string representation of the exclusion type.
func (t ExclusionType) String() string {
	return string(t)
}

// IsValid returns true if the exclusion type is valid.
func (t ExclusionType) IsValid() bool {
	switch t {
	case ExclusionTypeDomain, ExclusionTypeSubdomain, ExclusionTypeIPAddress, ExclusionTypeIPRange,
		ExclusionTypeCIDR, ExclusionTypeURL, ExclusionTypePath, ExclusionTypeRepository,
		ExclusionTypeFindingType, ExclusionTypeScanner:
		return true
	}
	return false
}

// ParseExclusionType parses a string into an ExclusionType.
func ParseExclusionType(s string) (ExclusionType, error) {
	t := ExclusionType(strings.ToLower(s))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid exclusion type: %s", s)
	}
	return t, nil
}

// =============================================================================
// Status
// =============================================================================

// Status represents the status of a scope target or exclusion.
type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
	StatusExpired  Status = "expired" // Only for exclusions
	// StatusPending: an exclusion waiting for review. It does not take effect
	// until a holder of attack_surface:scope:exclusions:approve approves it.
	StatusPending Status = "pending" // Only for exclusions
	// StatusRejected: a reviewer declined the exclusion. It never takes effect.
	StatusRejected Status = "rejected" // Only for exclusions
)

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// IsValid returns true if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusExpired, StatusPending, StatusRejected:
		return true
	}
	return false
}

// =============================================================================
// Pattern Validation
// =============================================================================

// ValidatePattern validates a pattern for the given target type.
func ValidatePattern(targetType TargetType, pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	if len(pattern) > 500 {
		return fmt.Errorf("pattern too long (max 500 characters)")
	}

	switch targetType {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		return validateDomainPattern(pattern)
	case TargetTypeIPAddress:
		return validateIPAddress(pattern)
	case TargetTypeIPRange, TargetTypeCIDR:
		return validateCIDR(pattern)
	case TargetTypeRepository, TargetTypeProject:
		return validateRepositoryPattern(pattern)
	case TargetTypeCloudAccount:
		return validateCloudAccountPattern(pattern)
	case TargetTypeURL, TargetTypeAPI, TargetTypeWebsite:
		return validateURLPattern(pattern)
	default:
		// Basic validation for other types
		return nil
	}
}

func validateDomainPattern(pattern string) error {
	// Allow wildcards: *.example.com, **.example.com
	pattern = strings.TrimPrefix(pattern, "*.")
	pattern = strings.TrimPrefix(pattern, "**.")

	// Basic domain validation
	if !regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`).MatchString(pattern) {
		return fmt.Errorf("invalid domain pattern: %s", pattern)
	}
	return nil
}

func validateIPAddress(pattern string) error {
	if net.ParseIP(pattern) == nil {
		return fmt.Errorf("invalid IP address: %s", pattern)
	}
	return nil
}

func validateCIDR(pattern string) error {
	_, _, err := net.ParseCIDR(pattern)
	if err != nil {
		// Try as IP range (e.g., 192.168.1.1-192.168.1.254)
		if strings.Contains(pattern, "-") {
			parts := strings.Split(pattern, "-")
			if len(parts) == 2 {
				if net.ParseIP(strings.TrimSpace(parts[0])) != nil && net.ParseIP(strings.TrimSpace(parts[1])) != nil {
					return nil
				}
			}
		}
		return fmt.Errorf("invalid CIDR or IP range: %s", pattern)
	}
	return nil
}

func validateRepositoryPattern(pattern string) error {
	// Allow: github.com/org/repo, github.com/org/*, gitlab.com/group/project
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+(/[a-zA-Z0-9._*-]+)+$`).MatchString(pattern) {
		return fmt.Errorf("invalid repository pattern: %s", pattern)
	}
	return nil
}

func validateCloudAccountPattern(pattern string) error {
	// Allow: AWS:123456789012, GCP:project-id, Azure:subscription-id
	if !regexp.MustCompile(`^(AWS|GCP|Azure|aws|gcp|azure):[a-zA-Z0-9_-]+$`).MatchString(pattern) {
		return fmt.Errorf("invalid cloud account pattern: %s (expected format: AWS:account-id)", pattern)
	}
	return nil
}

func validateURLPattern(pattern string) error {
	// Allow wildcards in path
	if !strings.HasPrefix(pattern, "http://") && !strings.HasPrefix(pattern, "https://") && !strings.HasPrefix(pattern, "*") {
		return fmt.Errorf("invalid URL pattern: %s (must start with http://, https://, or *)", pattern)
	}
	return nil
}

// =============================================================================
// Pattern Matching
// =============================================================================

// MatchesPattern checks if a value matches a pattern.
func MatchesPattern(targetType TargetType, pattern, value string) bool {
	switch targetType {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		return matchDomain(pattern, value)
	case TargetTypeIPAddress:
		return pattern == value
	case TargetTypeIPRange, TargetTypeCIDR:
		return matchCIDR(pattern, value)
	case TargetTypeRepository, TargetTypeProject:
		return matchWildcard(pattern, value)
	case TargetTypeCloudAccount:
		return matchWildcard(pattern, value)
	default:
		return matchWildcard(pattern, value)
	}
}

// matchDomain is the domain test for scope targets and exclusions alike
// (RFC-054 §4.1, owner decision S1):
//
//   - "example.com" matches only example.com;
//   - "*.example.com" matches example.com itself and every name below it, at
//     any depth. To cover the subdomains without the apex, add an exclusion
//     of exactly "example.com" (the more specific rule wins);
//   - "**.example.com" means the same as "*.example.com".
//
// Root-domain seeds, verified domains and the active-scan gate use the same
// "this domain and everything under it" meaning, so one intent gets one
// answer everywhere.
//
// Both sides are compared case-insensitively, without a trailing dot, and in
// their IDNA ASCII form, so "*.bücher.example" matches
// "shop.xn--bcher-kva.example" and the other way round. A value may itself be
// a wildcard pattern (CheckPatternOverlaps compares patterns): "*.a.x.com" is
// inside "*.x.com", and "*.x.com" is not inside the exact "x.com".
func matchDomain(pattern, domain string) bool {
	pWild, p := splitDomainWildcard(pattern)
	dWild, d := splitDomainWildcard(domain)
	if p == "" || d == "" {
		return false
	}
	if !pWild {
		return !dWild && d == p
	}
	return d == p || strings.HasSuffix(d, "."+p)
}

// domainIDNA converts a name to its ASCII (punycode) form for comparison.
// Lenient on purpose: underscores (_dmarc.example.com) and other non-LDH
// labels stay as they are instead of failing the conversion.
var domainIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false))

// splitDomainWildcard strips a leading "*." or "**." label and normalises the
// rest: trimmed, lowercased, one trailing dot dropped, IDNA ASCII form (the
// lowercased text when the conversion fails).
func splitDomainWildcard(s string) (wildcard bool, name string) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "**."):
		wildcard, s = true, s[3:]
	case strings.HasPrefix(s, "*."):
		wildcard, s = true, s[2:]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return wildcard, ""
	}
	if a, err := domainIDNA.ToASCII(s); err == nil && a != "" {
		s = strings.ToLower(a)
	}
	return wildcard, s
}

// ipSet is a contiguous, inclusive address range of one family: a single
// address, a CIDR (host bits ignored) or an "a-b" range.
type ipSet struct{ lo, hi netip.Addr }

// parseIPSet reads an address, a CIDR or an "a-b" range. IPv4-mapped IPv6
// addresses are treated as IPv4, so "::ffff:10.0.0.5" and "10.0.0.5" are the
// same address.
func parseIPSet(s string) (ipSet, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ipSet{}, false
		}
		p = p.Masked()
		lo := p.Addr()
		if lo.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(lo.Unmap(), p.Bits()-96)
			lo = p.Addr()
		}
		return ipSet{lo: lo, hi: lastAddr(p)}, true
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA != nil || errB != nil {
			return ipSet{}, false
		}
		a, b = a.Unmap(), b.Unmap()
		if a.Is4() != b.Is4() || b.Less(a) {
			return ipSet{}, false
		}
		return ipSet{lo: a, hi: b}, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ipSet{}, false
	}
	a = a.Unmap().WithZone("")
	return ipSet{lo: a, hi: a}, true
}

// lastAddr returns the highest address in a masked prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= byte(0x80) >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func (r ipSet) sameFamily(o ipSet) bool { return r.lo.Is4() == o.lo.Is4() }

// contains reports whether every address of o lies inside r.
func (r ipSet) contains(o ipSet) bool {
	return r.sameFamily(o) && !o.lo.Less(r.lo) && !r.hi.Less(o.hi)
}

// overlaps reports whether r and o share at least one address.
func (r ipSet) overlaps(o ipSet) bool {
	return r.sameFamily(o) && !r.hi.Less(o.lo) && !o.hi.Less(r.lo)
}

// matchCIDR is the TARGET test: value (an address, CIDR or range) is in scope
// of pattern (a CIDR or range) only when all of it lies inside the pattern.
func matchCIDR(pattern, value string) bool {
	p, ok := parseIPSet(pattern)
	if !ok {
		return false
	}
	v, ok := parseIPSet(value)
	if !ok {
		return false
	}
	return p.contains(v)
}

// matchIPExclusion is the EXCLUSION test: value is excluded when it shares ANY
// address with pattern. A scan target is handed to the scanner as written, so a
// target network that merely overlaps an excluded one would scan the excluded
// addresses; the only safe outcome is to skip the whole target (split it to
// scan the rest). A pattern that is not an address set falls back to an exact,
// case-insensitive string match.
func matchIPExclusion(pattern, value string) bool {
	p, ok := parseIPSet(pattern)
	if !ok {
		return strings.EqualFold(strings.TrimSpace(pattern), strings.TrimSpace(value))
	}
	v, ok := parseIPSet(value)
	if !ok {
		return false
	}
	return p.overlaps(v)
}

func matchWildcard(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Exact match
	if pattern == value {
		return true
	}

	// Simple wildcard at end: github.com/org/*
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(value, prefix+"/") || value == prefix
	}

	// Wildcard anywhere: use simple matching
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1])
		}
	}

	return false
}

// MatchesExclusionPattern checks if a value matches an exclusion pattern.
// This handles ExclusionType-specific types (path, finding_type, scanner) that
// don't exist in TargetType, plus shared types (domain, ip_address, etc.).
func MatchesExclusionPattern(exclusionType ExclusionType, pattern, value string) bool {
	switch exclusionType {
	case ExclusionTypeDomain, ExclusionTypeSubdomain:
		return matchDomain(pattern, value)
	case ExclusionTypeIPAddress, ExclusionTypeIPRange, ExclusionTypeCIDR:
		return matchIPExclusion(pattern, value)
	case ExclusionTypeURL:
		return matchWildcard(pattern, value)
	case ExclusionTypeRepository:
		return matchWildcard(pattern, value)
	case ExclusionTypePath:
		// A path exclusion is a web rule (host, path, methods, testing
		// mode): only Exclusion.Matches can apply it, never the pattern
		// alone.
		return false
	case ExclusionTypeFindingType:
		return matchWildcard(pattern, value)
	case ExclusionTypeScanner:
		return matchWildcard(pattern, value)
	default:
		return matchWildcard(pattern, value)
	}
}
