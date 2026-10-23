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

// AuthorizesProbes reports whether an entry of this type can authorize active
// probes. Only types with a proper matcher do: a name, an address, a range, a
// network, a URL origin or a repository namespace. Every other type has no
// matcher, so an entry of it never covers a target (it used to fall back to a
// wildcard match, and the pattern "*" then covered every host and address).
func (t TargetType) AuthorizesProbes() bool {
	switch t {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain,
		TargetTypeIPAddress, TargetTypeIPRange, TargetTypeCIDR,
		TargetTypeURL, TargetTypeAPI, TargetTypeWebsite,
		TargetTypeHost, TargetTypeRepository:
		return true
	}
	return false
}

// Retired reports whether new scope entries of this type are refused. These
// types name no network location a probe could be authorized for; the thing
// to scope is the domain, address or network that serves them. Existing rows
// stay readable but authorize nothing.
func (t TargetType) Retired() bool {
	switch t {
	case TargetTypeCertificate, TargetTypeContainer, TargetTypeDatabase,
		TargetTypeMobileApp, TargetTypeCloudResource, TargetTypeNetwork:
		return true
	}
	return false
}

// ParseTargetType parses a string into a TargetType.
func ParseTargetType(s string) (TargetType, error) {
	t := TargetType(strings.ToLower(s))
	if !t.IsValid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidTargetType, s)
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
		return "", fmt.Errorf("%w: %q", ErrInvalidExclusionType, s)
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
	// StatusExpired: the expiry passed (an exclusion, or an expiring scope
	// entry, RFC-054). It is no longer in effect.
	StatusExpired Status = "expired"
	// StatusPending: an exclusion or a scope entry waiting for review. It does
	// not take effect until enough approvers approve it.
	StatusPending Status = "pending"
	// StatusRejected: a reviewer declined it. It never takes effect.
	StatusRejected Status = "rejected"
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
		return fmt.Errorf("%w: pattern cannot be empty", ErrInvalidPattern)
	}

	if len(pattern) > 500 {
		return fmt.Errorf("%w (max 500 characters)", ErrPatternTooLong)
	}

	switch targetType {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		return validateDomainPattern(pattern)
	case TargetTypeIPAddress:
		return validateIPAddress(pattern)
	case TargetTypeIPRange, TargetTypeCIDR:
		return validateCIDR(pattern)
	case TargetTypeRepository:
		return validateRepositoryPattern(pattern)
	case TargetTypeProject:
		return validateProjectPattern(pattern)
	case TargetTypeCloudAccount:
		return validateCloudAccountPattern(pattern)
	case TargetTypeURL, TargetTypeAPI, TargetTypeWebsite:
		return validateURLPattern(pattern)
	case TargetTypeHost:
		return validateHostPattern(pattern)
	default:
		// Types with no matcher take no wildcard: "*" would otherwise
		// read as "everything" wherever the pattern is compared.
		if strings.Contains(pattern, "*") {
			return ErrWildcardNotAllowed
		}
		return nil
	}
}

// validateHostPattern accepts a host name (or *.name) or one address.
func validateHostPattern(pattern string) error {
	if _, err := netip.ParseAddr(strings.Trim(pattern, "[]")); err == nil {
		return nil
	}
	if _, ok := parseIPSet(pattern); ok || strings.Contains(pattern, "/") {
		return fmt.Errorf("%w: a host is a name or one address; use a CIDR or range entry for a network", ErrInvalidPattern)
	}
	if strings.Contains(strings.TrimPrefix(pattern, "*."), "*") {
		return ErrWildcardNotAllowed
	}
	return validateDomainPattern(pattern)
}

func validateDomainPattern(pattern string) error {
	// Allow wildcards: *.example.com, **.example.com
	pattern = strings.TrimPrefix(pattern, "*.")
	pattern = strings.TrimPrefix(pattern, "**.")

	// Basic domain validation
	if !regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`).MatchString(pattern) {
		return fmt.Errorf("%w: not a domain name or *.domain wildcard", ErrInvalidPattern)
	}
	return nil
}

func validateIPAddress(pattern string) error {
	if net.ParseIP(pattern) == nil {
		return fmt.Errorf("%w: not an IP address", ErrInvalidPattern)
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
		return fmt.Errorf("%w: not a CIDR block or first-last IP range", ErrInvalidPattern)
	}
	return nil
}

func validateProjectPattern(pattern string) error {
	// Allow: github.com/org/project, gitlab.com/group/*
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+(/[a-zA-Z0-9._*-]+)+$`).MatchString(pattern) {
		return fmt.Errorf("%w: not a repository path such as github.com/org/repo", ErrInvalidPattern)
	}
	return nil
}

var (
	cloudAccountPattern = regexp.MustCompile(`^(AWS|GCP|Azure|aws|gcp|azure):[a-zA-Z0-9_-]+$`)
	// awsAccountIDPattern is an AWS account id without its provider prefix.
	awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
)

func validateCloudAccountPattern(pattern string) error {
	// Allow: AWS:123456789012, GCP:project-id, Azure:subscription-id
	if awsAccountIDPattern.MatchString(pattern) {
		return fmt.Errorf("%w: a bare AWS account id is not accepted; write it as AWS:%s", ErrInvalidPattern, pattern)
	}
	if !cloudAccountPattern.MatchString(pattern) {
		return fmt.Errorf("%w: a cloud account is PROVIDER:id with PROVIDER one of AWS, GCP, Azure (for example AWS:123456789012)", ErrInvalidPattern)
	}
	return nil
}

// urlAuthorityWild reports whether the host part of a URL pattern holds a
// "*", or the pattern has no scheme and host at all.
func urlAuthorityWild(pattern string) bool {
	_, rest, ok := strings.Cut(pattern, "://")
	if !ok {
		return strings.Contains(pattern, "*")
	}
	authority, _, _ := strings.Cut(rest, "/")
	return authority == "" || strings.Contains(authority, "*")
}

// validateURLPattern accepts "http(s)://host[:port][/path*]". The host is a
// name or an address: a wildcard host would cover every origin, so only the
// path may end in "*".
func validateURLPattern(pattern string) error {
	lower := strings.ToLower(pattern)
	var rest string
	switch {
	case strings.HasPrefix(lower, "http://"):
		rest = pattern[len("http://"):]
	case strings.HasPrefix(lower, "https://"):
		rest = pattern[len("https://"):]
	case strings.HasPrefix(pattern, "*://"):
		rest = pattern[len("*://"):] // any scheme, one concrete host
	default:
		return fmt.Errorf("%w: a URL must start with http:// or https://", ErrInvalidPattern)
	}
	authority, _, _ := strings.Cut(rest, "/")
	if strings.ContainsAny(authority, "?#@") {
		return fmt.Errorf("%w: a URL entry names a host (and optional port) with no credentials, query or fragment", ErrInvalidPattern)
	}
	if strings.Contains(authority, "*") {
		return ErrWildcardNotAllowed
	}
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return fmt.Errorf("%w: a URL entry needs a host", ErrInvalidPattern)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	return validateDomainPattern(host)
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
	case TargetTypeRepository:
		return matchRepository(pattern, value)
	case TargetTypeProject:
		return matchWildcard(pattern, value)
	case TargetTypeCloudAccount:
		return matchWildcard(pattern, value)
	case TargetTypeURL, TargetTypeAPI, TargetTypeWebsite:
		// A wildcard in the host would cover every origin; stored rows
		// from before validation refused it authorize nothing.
		if urlAuthorityWild(pattern) {
			return false
		}
		// "*://host" means any scheme on that host: the value's own scheme
		// takes the place of "*", so the star cannot swallow a host.
		pattern, ok := bindWildScheme(pattern, value)
		if !ok {
			return false
		}
		return matchWildcard(pattern, value)
	case TargetTypeHost:
		// One address, or a name (*.name). A CIDR or a range belongs to an
		// ip_range or cidr entry: as a host pattern it covers nothing.
		if a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(pattern), "[]")); err == nil {
			return matchCIDR(a.Unmap().String(), value)
		}
		if _, ok := parseIPSet(pattern); ok {
			return false
		}
		return matchDomain(pattern, value)
	default:
		// No matcher: exact text only, never a wildcard.
		return strings.EqualFold(strings.TrimSpace(pattern), strings.TrimSpace(value))
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
// address with pattern. A target is handed to the scanner as written, so a
// target network that merely overlaps an excluded one would scan the excluded
// addresses. The scan target gate first cuts a range target around the
// exclusions (exact subtraction, package ipset), so on that path only pieces
// that hold no excluded address reach this test; everywhere else an overlap
// excludes the whole value. A pattern that is not an address set falls back
// to an exact, case-insensitive string match.
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
		return matchRepository(pattern, value)
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

// bindWildScheme replaces a leading "*://" of a URL pattern with the
// value's own scheme. A value without a plain scheme (letters, digits, "+",
// "-") binds nothing. Patterns without "*://" come back unchanged.
func bindWildScheme(pattern, value string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(pattern)), "*://")
	if !ok {
		return pattern, true
	}
	s, _, found := strings.Cut(strings.ToLower(strings.TrimSpace(value)), "://")
	if !found || s == "" || strings.ContainsAny(s, "/?#@.") {
		return "", false
	}
	return s + "://" + rest, true
}
