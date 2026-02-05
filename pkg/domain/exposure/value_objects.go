package exposure

import (
	"fmt"
	"slices"
	"strings"
)

// EventType represents the type of exposure event.
type EventType string

const (
	EventTypePortOpen            EventType = "port_open"
	EventTypePortClosed          EventType = "port_closed"
	EventTypeServiceDetected     EventType = "service_detected"
	EventTypeServiceChanged      EventType = "service_changed"
	EventTypeSubdomainDiscovered EventType = "subdomain_discovered"
	EventTypeSubdomainRemoved    EventType = "subdomain_removed"
	EventTypeCertificateExpiring EventType = "certificate_expiring"
	EventTypeCertificateExpired  EventType = "certificate_expired"
	EventTypeBucketPublic        EventType = "bucket_public"
	EventTypeBucketPrivate       EventType = "bucket_private"
	EventTypeRepoPublic          EventType = "repo_public"
	EventTypeRepoPrivate         EventType = "repo_private"
	EventTypeAPIExposed          EventType = "api_exposed"
	EventTypeAPIRemoved          EventType = "api_removed"
	EventTypeCredentialLeaked    EventType = "credential_leaked"
	EventTypeSensitiveData       EventType = "sensitive_data_exposed"
	EventTypeMisconfiguration    EventType = "misconfiguration"
	EventTypeDNSChange           EventType = "dns_change"
	EventTypeSSLIssue            EventType = "ssl_issue"
	EventTypeHeaderMissing       EventType = "header_missing"
	EventTypeCustom              EventType = "custom"
)

// AllEventTypes returns all valid event types.
func AllEventTypes() []EventType {
	return []EventType{
		EventTypePortOpen,
		EventTypePortClosed,
		EventTypeServiceDetected,
		EventTypeServiceChanged,
		EventTypeSubdomainDiscovered,
		EventTypeSubdomainRemoved,
		EventTypeCertificateExpiring,
		EventTypeCertificateExpired,
		EventTypeBucketPublic,
		EventTypeBucketPrivate,
		EventTypeRepoPublic,
		EventTypeRepoPrivate,
		EventTypeAPIExposed,
		EventTypeAPIRemoved,
		EventTypeCredentialLeaked,
		EventTypeSensitiveData,
		EventTypeMisconfiguration,
		EventTypeDNSChange,
		EventTypeSSLIssue,
		EventTypeHeaderMissing,
		EventTypeCustom,
	}
}

// IsValid checks if the event type is valid.
func (t EventType) IsValid() bool {
	return slices.Contains(AllEventTypes(), t)
}

// String returns the string representation.
func (t EventType) String() string {
	return string(t)
}

// ParseEventType parses a string into an EventType.
func ParseEventType(s string) (EventType, error) {
	t := EventType(strings.ToLower(strings.TrimSpace(s)))
	if !t.IsValid() {
		return "", fmt.Errorf("invalid event type: %s", s)
	}
	return t, nil
}

// IsPositiveExposure returns true if the event type indicates increased exposure.
func (t EventType) IsPositiveExposure() bool {
	switch t {
	case EventTypePortOpen, EventTypeServiceDetected, EventTypeSubdomainDiscovered,
		EventTypeBucketPublic, EventTypeRepoPublic, EventTypeAPIExposed,
		EventTypeCredentialLeaked, EventTypeSensitiveData, EventTypeMisconfiguration,
		EventTypeSSLIssue, EventTypeHeaderMissing, EventTypeCertificateExpiring,
		EventTypeCertificateExpired:
		return true
	default:
		return false
	}
}

// Severity represents the severity level of an exposure event.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities returns all valid severity levels.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool {
	return slices.Contains(AllSeverities(), s)
}

// String returns the string representation.
func (s Severity) String() string {
	return string(s)
}

// Score returns the numeric score for the severity (0-100).
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	case SeverityInfo:
		return 0
	default:
		return 0
	}
}

// ParseSeverity parses a string into a Severity.
func ParseSeverity(str string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid severity: %s", str)
	}
	return s, nil
}

// State represents the state of an exposure event.
type State string

const (
	StateActive        State = "active"
	StateResolved      State = "resolved"
	StateAccepted      State = "accepted"
	StateFalsePositive State = "false_positive"
)

// AllStates returns all valid states.
func AllStates() []State {
	return []State{
		StateActive,
		StateResolved,
		StateAccepted,
		StateFalsePositive,
	}
}

// IsValid checks if the state is valid.
func (s State) IsValid() bool {
	return slices.Contains(AllStates(), s)
}

// String returns the string representation.
func (s State) String() string {
	return string(s)
}

// ParseState parses a string into a State.
func ParseState(str string) (State, error) {
	s := State(strings.ToLower(strings.TrimSpace(str)))
	if !s.IsValid() {
		return "", fmt.Errorf("invalid state: %s", str)
	}
	return s, nil
}

// IsOpen returns true if the state is active.
func (s State) IsOpen() bool {
	return s == StateActive
}

// IsClosed returns true if the state is not active.
func (s State) IsClosed() bool {
	return s != StateActive
}

// CanTransitionTo checks if a state transition is valid.
func (s State) CanTransitionTo(target State) bool {
	switch s {
	case StateActive:
		return target == StateResolved || target == StateAccepted || target == StateFalsePositive
	case StateResolved:
		return target == StateActive
	case StateAccepted:
		return target == StateActive || target == StateResolved
	case StateFalsePositive:
		return target == StateActive
	default:
		return false
	}
}
