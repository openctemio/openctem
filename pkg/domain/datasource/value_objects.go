package datasource

import (
	"fmt"
	"slices"
	"strings"
)

// =============================================================================
// SourceType - Type of data source
// =============================================================================

// SourceType represents the type of data source.
type SourceType string

const (
	// SourceTypeIntegration represents a pull-based integration (GitHub, AWS, etc.)
	SourceTypeIntegration SourceType = "integration"

	// SourceTypeCollector represents a push-based passive collector (logs, inventory)
	SourceTypeCollector SourceType = "collector"

	// SourceTypeScanner represents a push-based active scanner (vuln scan, port scan)
	SourceTypeScanner SourceType = "scanner"

	// SourceTypeManual represents user-created assets via UI/API
	SourceTypeManual SourceType = "manual"
)

// AllSourceTypes returns all valid source types.
func AllSourceTypes() []SourceType {
	return []SourceType{
		SourceTypeIntegration,
		SourceTypeCollector,
		SourceTypeScanner,
		SourceTypeManual,
	}
}

// String returns the string representation of the source type.
func (t SourceType) String() string {
	return string(t)
}

// IsValid checks if the source type is valid.
func (t SourceType) IsValid() bool {
	return slices.Contains(AllSourceTypes(), t)
}

// IsPush returns true if this source type pushes data to the server.
func (t SourceType) IsPush() bool {
	return t == SourceTypeCollector || t == SourceTypeScanner
}

// IsPull returns true if this source type pulls data from external systems.
func (t SourceType) IsPull() bool {
	return t == SourceTypeIntegration
}

// RequiresAPIKey returns true if this source type requires an API key for authentication.
func (t SourceType) RequiresAPIKey() bool {
	return t == SourceTypeCollector || t == SourceTypeScanner
}

// ParseSourceType parses a string into a SourceType.
func ParseSourceType(s string) (SourceType, error) {
	t := SourceType(strings.ToLower(strings.TrimSpace(s)))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid source type: %s", s)
	}
	return t, nil
}

// =============================================================================
// SourceStatus - Status of a data source
// =============================================================================

// SourceStatus represents the status of a data source.
type SourceStatus string

const (
	// SourceStatusPending indicates the source is registered but not yet active.
	SourceStatusPending SourceStatus = "pending"

	// SourceStatusActive indicates the source is running and reporting data.
	SourceStatusActive SourceStatus = "active"

	// SourceStatusInactive indicates the source has not reported recently.
	SourceStatusInactive SourceStatus = "inactive"

	// SourceStatusError indicates the source has errors.
	SourceStatusError SourceStatus = "error"

	// SourceStatusDisabled indicates the source was manually disabled.
	SourceStatusDisabled SourceStatus = "disabled"
)

// AllSourceStatuses returns all valid source statuses.
func AllSourceStatuses() []SourceStatus {
	return []SourceStatus{
		SourceStatusPending,
		SourceStatusActive,
		SourceStatusInactive,
		SourceStatusError,
		SourceStatusDisabled,
	}
}

// String returns the string representation of the source status.
func (s SourceStatus) String() string {
	return string(s)
}

// IsValid checks if the source status is valid.
func (s SourceStatus) IsValid() bool {
	return slices.Contains(AllSourceStatuses(), s)
}

// IsOperational returns true if the source is in an operational state (pending or active).
func (s SourceStatus) IsOperational() bool {
	return s == SourceStatusPending || s == SourceStatusActive
}

// CanReceiveData returns true if the source can receive data.
func (s SourceStatus) CanReceiveData() bool {
	return s == SourceStatusActive || s == SourceStatusPending
}

// ParseSourceStatus parses a string into a SourceStatus.
func ParseSourceStatus(s string) (SourceStatus, error) {
	status := SourceStatus(strings.ToLower(strings.TrimSpace(s)))
	if !status.IsValid() {
		return "", fmt.Errorf("invalid source status: %s", s)
	}
	return status, nil
}

// =============================================================================
// Capabilities - What a source can collect
// =============================================================================

// Capability represents a capability of a data source.
type Capability string

const (
	// Asset collection capabilities
	CapabilityDomain       Capability = "domain"
	CapabilitySubdomain    Capability = "subdomain"
	CapabilityIPAddress    Capability = "ip_address"
	CapabilityCertificate  Capability = "certificate"
	CapabilityRepository   Capability = "repository"
	CapabilityCloudAccount Capability = "cloud_account"
	CapabilityCompute      Capability = "compute"
	CapabilityStorage      Capability = "storage"
	CapabilityContainer    Capability = "container"
	CapabilityKubernetes   Capability = "kubernetes"
	CapabilityNetwork      Capability = "network"
	CapabilityDatabase     Capability = "database"
	CapabilityService      Capability = "service"

	// Finding/vulnerability capabilities
	CapabilityVulnerability    Capability = "vulnerability"
	CapabilitySecret           Capability = "secret"
	CapabilityMisconfiguration Capability = "misconfiguration"
	CapabilityCompliance       Capability = "compliance"
)

// String returns the string representation of the capability.
func (c Capability) String() string {
	return string(c)
}

// Capabilities is a list of capabilities.
type Capabilities []Capability

// Contains checks if the capabilities list contains a specific capability.
func (c Capabilities) Contains(cap Capability) bool {
	return slices.Contains(c, cap)
}

// Strings returns the capabilities as a string slice.
func (c Capabilities) Strings() []string {
	result := make([]string, len(c))
	for i, v := range c {
		result[i] = v.String()
	}
	return result
}

// ParseCapabilities parses a string slice into Capabilities.
func ParseCapabilities(ss []string) Capabilities {
	result := make(Capabilities, 0, len(ss))
	for _, s := range ss {
		result = append(result, Capability(strings.ToLower(strings.TrimSpace(s))))
	}
	return result
}

// =============================================================================
// APIKeyPrefix - Prefix for API key identification
// =============================================================================

const (
	// APIKeyPrefixLive is the prefix for live/production API keys.
	APIKeyPrefixLive = "oc_live_"

	// APIKeyPrefixTest is the prefix for test/development API keys.
	APIKeyPrefixTest = "oc_test_"
)

// GenerateAPIKeyPrefix generates the visible prefix for an API key.
func GenerateAPIKeyPrefix(key string) string {
	if len(key) < 12 {
		return key
	}
	return key[:12]
}
