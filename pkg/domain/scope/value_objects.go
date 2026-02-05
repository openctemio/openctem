package scope

import (
	"fmt"
	"net"
	"regexp"
	"strings"
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
)

// String returns the string representation of the status.
func (s Status) String() string {
	return string(s)
}

// IsValid returns true if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusExpired:
		return true
	}
	return false
}

// =============================================================================
// Scan Type
// =============================================================================

// ScanType represents the type of scan.
type ScanType string

const (
	ScanTypeFull          ScanType = "full"
	ScanTypeIncremental   ScanType = "incremental"
	ScanTypeTargeted      ScanType = "targeted"
	ScanTypeVulnerability ScanType = "vulnerability"
	ScanTypeCompliance    ScanType = "compliance"
	ScanTypeSecret        ScanType = "secret"
	ScanTypeSAST          ScanType = "sast"
	ScanTypeDAST          ScanType = "dast"
	ScanTypeSCA           ScanType = "sca"
)

// String returns the string representation of the scan type.
func (t ScanType) String() string {
	return string(t)
}

// IsValid returns true if the scan type is valid.
func (t ScanType) IsValid() bool {
	switch t {
	case ScanTypeFull, ScanTypeIncremental, ScanTypeTargeted, ScanTypeVulnerability,
		ScanTypeCompliance, ScanTypeSecret, ScanTypeSAST, ScanTypeDAST, ScanTypeSCA:
		return true
	}
	return false
}

// ParseScanType parses a string into a ScanType.
func ParseScanType(s string) (ScanType, error) {
	t := ScanType(strings.ToLower(s))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid scan type: %s", s)
	}
	return t, nil
}

// =============================================================================
// Schedule Type
// =============================================================================

// ScheduleType represents how a scan is scheduled.
type ScheduleType string

const (
	ScheduleTypeCron     ScheduleType = "cron"
	ScheduleTypeInterval ScheduleType = "interval"
	ScheduleTypeManual   ScheduleType = "manual"
)

// String returns the string representation of the schedule type.
func (t ScheduleType) String() string {
	return string(t)
}

// IsValid returns true if the schedule type is valid.
func (t ScheduleType) IsValid() bool {
	switch t {
	case ScheduleTypeCron, ScheduleTypeInterval, ScheduleTypeManual:
		return true
	}
	return false
}

// =============================================================================
// Target Scope
// =============================================================================

// TargetScope defines what targets to include in a scan.
type TargetScope string

const (
	TargetScopeAll      TargetScope = "all"
	TargetScopeSelected TargetScope = "selected"
	TargetScopeTag      TargetScope = "tag"
)

// String returns the string representation of the target scope.
func (t TargetScope) String() string {
	return string(t)
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

func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	// Exact match
	if pattern == domain {
		return true
	}

	// Wildcard match: *.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}

	// Double wildcard: **.example.com (matches any subdomain depth)
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}

	return false
}

func matchCIDR(pattern, ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Try CIDR
	_, network, err := net.ParseCIDR(pattern)
	if err == nil {
		return network.Contains(parsedIP)
	}

	// Try IP range
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			if startIP != nil && endIP != nil {
				return ipInRange(parsedIP, startIP, endIP)
			}
		}
	}

	return false
}

func ipInRange(ip, start, end net.IP) bool {
	ip = ip.To16()
	start = start.To16()
	end = end.To16()

	if ip == nil || start == nil || end == nil {
		return false
	}

	for i := 0; i < 16; i++ {
		if ip[i] < start[i] || ip[i] > end[i] {
			if ip[i] < start[i] {
				return false
			}
			if ip[i] > end[i] {
				return false
			}
		}
	}
	return true
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
