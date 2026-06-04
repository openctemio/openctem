package jira

import (
	"strings"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// MappingConfig holds the configurable severity/status mappings for a ticketing
// integration. The zero value is not useful; build one with DefaultMappingConfig
// (today's hardcoded behaviour) and optionally overlay per-integration overrides
// with ParseMappingConfig.
//
// It is loaded from the integration record's JSONB config under the "ticketing"
// key; see ParseMappingConfig. When a tenant has no overrides, the defaults
// preserve the platform's original behaviour exactly.
type MappingConfig struct {
	// SeverityToPriority maps a finding severity (lower-case) to a Jira priority
	// name, e.g. "critical" -> "Highest".
	SeverityToPriority map[string]string

	// StatusInbound maps a Jira status name (lower-case) to a finding status,
	// e.g. "done" -> "fix_applied". Used by the inbound webhook.
	StatusInbound map[string]vulnerability.FindingStatus

	// DefaultPriority is returned when a severity has no explicit mapping.
	DefaultPriority string

	// DefaultIssueType is the Jira issue type used when a request omits one.
	DefaultIssueType string
}

// DefaultMappingConfig returns the mapping that reproduces the platform's
// original hardcoded behaviour. Customers with non-default Jira workflows
// overlay overrides via ParseMappingConfig.
func DefaultMappingConfig() MappingConfig {
	return MappingConfig{
		SeverityToPriority: map[string]string{
			"critical": "Highest",
			"high":     "High",
			"medium":   "Medium",
			"low":      "Low",
		},
		StatusInbound: map[string]vulnerability.FindingStatus{
			"in progress":    vulnerability.FindingStatusInProgress,
			"in review":      vulnerability.FindingStatusInProgress,
			"in development": vulnerability.FindingStatusInProgress,
			"open":           vulnerability.FindingStatusInProgress,
			"done":           vulnerability.FindingStatusFixApplied,
			"resolved":       vulnerability.FindingStatusFixApplied,
			"closed":         vulnerability.FindingStatusFixApplied,
			"completed":      vulnerability.FindingStatusFixApplied,
			"fixed":          vulnerability.FindingStatusFixApplied,
			"to do":          vulnerability.FindingStatusConfirmed,
			"backlog":        vulnerability.FindingStatusConfirmed,
			"reopened":       vulnerability.FindingStatusConfirmed,
		},
		DefaultPriority:  "Medium",
		DefaultIssueType: "Bug",
	}
}

// PriorityForSeverity returns the Jira priority for a finding severity,
// falling back to DefaultPriority when unmapped.
func (m MappingConfig) PriorityForSeverity(severity string) string {
	if p, ok := m.SeverityToPriority[strings.ToLower(strings.TrimSpace(severity))]; ok && p != "" {
		return p
	}
	if m.DefaultPriority != "" {
		return m.DefaultPriority
	}
	return "Medium"
}

// FindingStatusForJira maps a Jira status name to a finding status. Returns
// (status, true) when a mapping exists and resolves to a valid finding status,
// (_, false) otherwise (the inbound webhook then ignores the transition).
func (m MappingConfig) FindingStatusForJira(jiraStatus string) (vulnerability.FindingStatus, bool) {
	s, ok := m.StatusInbound[strings.ToLower(strings.TrimSpace(jiraStatus))]
	if !ok {
		return "", false
	}
	// Defend against invalid override values reaching the domain.
	if _, err := vulnerability.ParseFindingStatus(string(s)); err != nil {
		return "", false
	}
	return s, true
}

// ParseMappingConfig builds a MappingConfig from an integration's JSONB config.
// It starts from DefaultMappingConfig and overlays any overrides found under
// config["ticketing"], so partial configs only change what they specify.
//
// Expected shape (all optional):
//
//	{ "ticketing": {
//	    "issue_type": "Task",
//	    "default_priority": "P3",
//	    "severity_to_priority": { "critical": "P1", "high": "P2" },
//	    "status_inbound": { "Shipped": "fix_applied", "QA": "in_progress" }
//	}}
//
// Keys are matched case-insensitively (Jira statuses/severities vary by site).
// Status values that are not valid finding statuses are skipped (logged by the
// caller if desired) rather than corrupting the map.
func ParseMappingConfig(config map[string]any) MappingConfig {
	m := DefaultMappingConfig()

	section, ok := config["ticketing"].(map[string]any)
	if !ok {
		return m
	}

	if v, ok := stringValue(section, "issue_type"); ok {
		m.DefaultIssueType = v
	}
	if v, ok := stringValue(section, "default_priority"); ok {
		m.DefaultPriority = v
	}

	if raw, ok := section["severity_to_priority"].(map[string]any); ok {
		for sev, pri := range raw {
			if p, ok := pri.(string); ok && p != "" {
				m.SeverityToPriority[strings.ToLower(strings.TrimSpace(sev))] = p
			}
		}
	}

	if raw, ok := section["status_inbound"].(map[string]any); ok {
		for jiraStatus, target := range raw {
			t, ok := target.(string)
			if !ok || t == "" {
				continue
			}
			fs, err := vulnerability.ParseFindingStatus(t)
			if err != nil {
				continue // skip invalid target, keep the rest
			}
			m.StatusInbound[strings.ToLower(strings.TrimSpace(jiraStatus))] = fs
		}
	}

	return m
}

func stringValue(m map[string]any, key string) (string, bool) {
	v, ok := m[key].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
