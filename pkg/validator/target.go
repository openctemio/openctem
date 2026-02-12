// Package validator provides struct validation utilities with custom validators.
package validator

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// TargetType represents the type of scan target.
type TargetType string

const (
	TargetTypeDomain   TargetType = "domain"
	TargetTypeIPv4     TargetType = "ipv4"
	TargetTypeIPv6     TargetType = "ipv6"
	TargetTypeCIDR     TargetType = "cidr"
	TargetTypeURL      TargetType = "url"
	TargetTypeHostPort TargetType = "host_port"
	TargetTypeUnknown  TargetType = "unknown"

	errLocalhostNotAllowed = "localhost addresses are not allowed"
)

// ValidatedTarget represents a validated and classified target.
type ValidatedTarget struct {
	Original string     `json:"original"`
	Type     TargetType `json:"type"`
	Value    string     `json:"value"`
	Port     int        `json:"port,omitempty"`
	IsValid  bool       `json:"is_valid"`
	Error    string     `json:"error,omitempty"`
}

// TargetValidationResult contains the results of validating multiple targets.
type TargetValidationResult struct {
	Valid      []ValidatedTarget `json:"valid"`
	Invalid    []ValidatedTarget `json:"invalid"`
	TotalCount int               `json:"total_count"`
	ValidCount int               `json:"valid_count"`
	HasErrors  bool              `json:"has_errors"`
	BlockedIPs []string          `json:"blocked_ips,omitempty"`
}

// targetDomainRegex validates domain names for scan targets.
// Matches: example.com, sub.example.com, test-site.co.uk
// Does not match: -example.com, example-.com, .com
var targetDomainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// targetWildcardDomainRegex validates wildcard domain patterns (e.g., *.example.com)
var targetWildcardDomainRegex = regexp.MustCompile(`^\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Host:port regex
var hostPortRegex = regexp.MustCompile(`^(.+):(\d{1,5})$`)

// TargetValidator validates and classifies scan targets.
type TargetValidator struct {
	allowInternalIPs bool
	allowLocalhost   bool
	maxTargets       int
}

// TargetValidatorOption is a functional option for TargetValidator.
type TargetValidatorOption func(*TargetValidator)

// WithAllowInternalIPs allows internal IP addresses (10.x, 172.16.x, 192.168.x).
func WithAllowInternalIPs(allow bool) TargetValidatorOption {
	return func(v *TargetValidator) {
		v.allowInternalIPs = allow
	}
}

// WithAllowLocalhost allows localhost addresses.
func WithAllowLocalhost(allow bool) TargetValidatorOption {
	return func(v *TargetValidator) {
		v.allowLocalhost = allow
	}
}

// WithMaxTargets sets the maximum number of targets allowed.
func WithMaxTargets(max int) TargetValidatorOption {
	return func(v *TargetValidator) {
		v.maxTargets = max
	}
}

// NewTargetValidator creates a new TargetValidator with options.
func NewTargetValidator(opts ...TargetValidatorOption) *TargetValidator {
	v := &TargetValidator{
		allowInternalIPs: false, // Default: block internal IPs (SSRF protection)
		allowLocalhost:   false, // Default: block localhost
		maxTargets:       1000,  // Default: max 1000 targets
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ValidateTargets validates a list of targets and returns classified results.
func (v *TargetValidator) ValidateTargets(targets []string) *TargetValidationResult {
	result := &TargetValidationResult{
		Valid:      make([]ValidatedTarget, 0),
		Invalid:    make([]ValidatedTarget, 0),
		BlockedIPs: make([]string, 0),
		TotalCount: len(targets),
	}

	// Check max targets limit
	if len(targets) > v.maxTargets {
		result.HasErrors = true
		result.Invalid = append(result.Invalid, ValidatedTarget{
			Original: fmt.Sprintf("[%d targets]", len(targets)),
			Type:     TargetTypeUnknown,
			IsValid:  false,
			Error:    fmt.Sprintf("too many targets: %d (max: %d)", len(targets), v.maxTargets),
		})
		return result
	}

	seen := make(map[string]bool)

	for _, target := range targets {
		// Trim and normalize
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Skip duplicates
		normalized := strings.ToLower(target)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true

		// Validate single target
		validated := v.ValidateSingleTarget(target)

		if validated.IsValid {
			result.Valid = append(result.Valid, validated)
		} else {
			result.Invalid = append(result.Invalid, validated)
			result.HasErrors = true

			// Track blocked IPs separately
			if strings.Contains(validated.Error, "internal IP") || strings.Contains(validated.Error, "localhost") {
				result.BlockedIPs = append(result.BlockedIPs, target)
			}
		}
	}

	result.ValidCount = len(result.Valid)
	return result
}

// ValidateSingleTarget validates and classifies a single target.
func (v *TargetValidator) ValidateSingleTarget(target string) ValidatedTarget {
	result := ValidatedTarget{
		Original: target,
		Type:     TargetTypeUnknown,
		Value:    target,
		IsValid:  false,
	}

	// Sanitize input - remove dangerous characters
	if containsDangerousChars(target) {
		result.Error = "contains invalid characters"
		return result
	}

	// 1. Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return v.validateURL(target)
	}

	// 2. Check if it's a CIDR range
	if strings.Contains(target, "/") {
		return v.validateCIDR(target)
	}

	// 3. Check if it's host:port format
	if matches := hostPortRegex.FindStringSubmatch(target); len(matches) == 3 {
		return v.validateHostPort(target, matches[1], matches[2])
	}

	// 4. Check if it's an IP address
	if ip := net.ParseIP(target); ip != nil {
		return v.validateIP(target, ip)
	}

	// 5. Check if it's a domain (including wildcard)
	return v.validateDomain(target)
}

// validateURL validates a URL target.
func (v *TargetValidator) validateURL(target string) ValidatedTarget {
	result := ValidatedTarget{
		Original: target,
		Type:     TargetTypeURL,
		Value:    target,
		IsValid:  false,
	}

	parsed, err := url.Parse(target)
	if err != nil {
		result.Error = "invalid URL format"
		return result
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		result.Error = "only http and https schemes are allowed"
		return result
	}

	// Extract host for IP validation
	host := parsed.Hostname()

	// Check for localhost hostname (not just IP)
	if !v.allowLocalhost && isLocalhostHostname(host) {
		result.Error = errLocalhostNotAllowed
		return result
	}

	if ip := net.ParseIP(host); ip != nil {
		if !v.isIPAllowed(ip) {
			result.Error = v.getIPBlockedReason(ip)
			return result
		}
	}

	result.IsValid = true
	return result
}

// validateCIDR validates a CIDR range target.
func (v *TargetValidator) validateCIDR(target string) ValidatedTarget {
	result := ValidatedTarget{
		Original: target,
		Type:     TargetTypeCIDR,
		Value:    target,
		IsValid:  false,
	}

	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		result.Error = "invalid CIDR format"
		return result
	}

	// Check if CIDR contains internal/localhost addresses
	if !v.allowInternalIPs && isInternalNetwork(ipNet) {
		result.Error = "CIDR range contains internal IP addresses"
		return result
	}

	if !v.allowLocalhost && isLocalhostNetwork(ipNet) {
		result.Error = "CIDR range contains localhost addresses"
		return result
	}

	// Limit CIDR size to prevent abuse
	ones, bits := ipNet.Mask.Size()
	maxHosts := 1 << (bits - ones)
	if maxHosts > 65536 { // /16 for IPv4
		result.Error = fmt.Sprintf("CIDR range too large: %d hosts (max: 65536)", maxHosts)
		return result
	}

	result.IsValid = true
	return result
}

// validateHostPort validates a host:port target.
func (v *TargetValidator) validateHostPort(original, host, portStr string) ValidatedTarget {
	result := ValidatedTarget{
		Original: original,
		Type:     TargetTypeHostPort,
		Value:    host,
		IsValid:  false,
	}

	// Validate port
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
		result.Error = "invalid port number"
		return result
	}
	result.Port = port

	// Check for localhost hostname
	if !v.allowLocalhost && isLocalhostHostname(host) {
		result.Error = errLocalhostNotAllowed
		return result
	}

	// Validate host part (IP or domain)
	if ip := net.ParseIP(host); ip != nil {
		if !v.isIPAllowed(ip) {
			result.Error = v.getIPBlockedReason(ip)
			return result
		}
		if ip.To4() != nil {
			result.Type = TargetTypeIPv4
		} else {
			result.Type = TargetTypeIPv6
		}
	} else if !targetDomainRegex.MatchString(host) {
		result.Error = "invalid host format"
		return result
	}

	result.IsValid = true
	return result
}

// validateIP validates an IP address target.
func (v *TargetValidator) validateIP(target string, ip net.IP) ValidatedTarget {
	result := ValidatedTarget{
		Original: target,
		Value:    target,
		IsValid:  false,
	}

	if ip.To4() != nil {
		result.Type = TargetTypeIPv4
	} else {
		result.Type = TargetTypeIPv6
	}

	if !v.isIPAllowed(ip) {
		result.Error = v.getIPBlockedReason(ip)
		return result
	}

	result.IsValid = true
	return result
}

// validateDomain validates a domain target.
func (v *TargetValidator) validateDomain(target string) ValidatedTarget {
	result := ValidatedTarget{
		Original: target,
		Type:     TargetTypeDomain,
		Value:    target,
		IsValid:  false,
	}

	// Check for wildcard domain
	if strings.HasPrefix(target, "*.") {
		if !targetWildcardDomainRegex.MatchString(target) {
			result.Error = "invalid wildcard domain format"
			return result
		}
		result.IsValid = true
		return result
	}

	// Check standard domain
	if !targetDomainRegex.MatchString(target) {
		result.Error = "invalid domain format"
		return result
	}

	result.IsValid = true
	return result
}

// isIPAllowed checks if an IP address is allowed based on validator settings.
func (v *TargetValidator) isIPAllowed(ip net.IP) bool {
	if !v.allowLocalhost && isLocalhostIP(ip) {
		return false
	}
	if !v.allowInternalIPs && isInternalIP(ip) {
		return false
	}
	return true
}

// getIPBlockedReason returns the reason why an IP is blocked.
func (v *TargetValidator) getIPBlockedReason(ip net.IP) string {
	if isLocalhostIP(ip) {
		return errLocalhostNotAllowed
	}
	if isInternalIP(ip) {
		return "internal IP addresses are not allowed (SSRF protection)"
	}
	return "IP address is not allowed"
}

// isLocalhostIP checks if the IP is a localhost address.
func isLocalhostIP(ip net.IP) bool {
	return ip.IsLoopback()
}

// isLocalhostHostname checks if the hostname is a localhost variant.
func isLocalhostHostname(hostname string) bool {
	hostname = strings.ToLower(hostname)
	return hostname == "localhost" ||
		hostname == "localhost.localdomain" ||
		strings.HasSuffix(hostname, ".localhost")
}

// isInternalIP checks if the IP is a private/internal address.
func isInternalIP(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Check for other special addresses
	if ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	return false
}

// isInternalNetwork checks if a CIDR contains internal addresses.
func isInternalNetwork(ipNet *net.IPNet) bool {
	privateNets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
		"fc00::/7",       // IPv6 private
	}

	for _, cidr := range privateNets {
		_, privateNet, _ := net.ParseCIDR(cidr)
		if privateNet.Contains(ipNet.IP) {
			return true
		}
	}
	return false
}

// isLocalhostNetwork checks if a CIDR contains localhost addresses.
func isLocalhostNetwork(ipNet *net.IPNet) bool {
	localhostNets := []string{
		"127.0.0.0/8",
		"::1/128",
	}

	for _, cidr := range localhostNets {
		_, loNet, _ := net.ParseCIDR(cidr)
		if loNet.Contains(ipNet.IP) {
			return true
		}
	}
	return false
}

// containsDangerousChars checks for characters that could cause injection.
func containsDangerousChars(s string) bool {
	dangerous := []string{
		";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]",
		"<", ">", "\"", "'", "\\", "\n", "\r", "\t", "\x00",
	}
	for _, char := range dangerous {
		if strings.Contains(s, char) {
			return true
		}
	}
	return false
}

// GetValidTargetStrings returns only the valid target strings.
func (r *TargetValidationResult) GetValidTargetStrings() []string {
	result := make([]string, len(r.Valid))
	for i, t := range r.Valid {
		result[i] = t.Original
	}
	return result
}

// GetTargetsByType returns targets filtered by type.
func (r *TargetValidationResult) GetTargetsByType(targetType TargetType) []ValidatedTarget {
	result := make([]ValidatedTarget, 0)
	for _, t := range r.Valid {
		if t.Type == targetType {
			result = append(result, t)
		}
	}
	return result
}
