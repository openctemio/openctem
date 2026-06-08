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

	// StatusOutbound maps a finding status (lower-case) to a target Jira status
	// NAME, e.g. "resolved" -> "Done". Used by outbound status sync (RFC-006
	// Phase 3) to transition the linked issue. A finding status absent from this
	// map produces no push. Defaults use Jira's stock workflow names; customers
	// with custom workflows override via config.ticketing.status_outbound.
	StatusOutbound map[string]string

	// SyncEnabled is the per-integration master switch for OUTBOUND status sync.
	// Defaults to false so connecting a ticketing integration never silently
	// starts writing back to Jira until the operator opts in.
	SyncEnabled bool

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
		// INBOUND (Jira status name → finding status). Lower-cased keys.
		//
		// Two domain rules shape this map and are intentional, not omissions:
		//   1. false_positive / accepted REQUIRE APPROVAL (RequiresApproval) — a
		//      webhook has no approving actor, so Jira "Won't Do"/"Rejected" is
		//      deliberately NOT auto-applied (it would be rejected by the domain
		//      anyway). The sync layer comments instead (RFC-006 Phase 3c).
		//   2. resolved REQUIRES VERIFY PERMISSION — a webhook can't grant it, so
		//      every Jira "done"-like status maps to fix_applied (NOT resolved);
		//      the post-fix rescan hook then verifies and promotes to resolved.
		StatusInbound: map[string]vulnerability.FindingStatus{
			// Working states → in_progress
			"in progress":    vulnerability.FindingStatusInProgress,
			"in review":      vulnerability.FindingStatusInProgress,
			"in development": vulnerability.FindingStatusInProgress,
			"reviewing":      vulnerability.FindingStatusInProgress,
			// Fixed-claim states → fix_applied (verification still pending)
			"done":      vulnerability.FindingStatusFixApplied,
			"resolved":  vulnerability.FindingStatusFixApplied,
			"closed":    vulnerability.FindingStatusFixApplied,
			"completed": vulnerability.FindingStatusFixApplied,
			"fixed":     vulnerability.FindingStatusFixApplied,
			"verified":  vulnerability.FindingStatusFixApplied,
			// Not-started / backlog / reopen → confirmed. "open" is Jira's classic
			// initial status (unstarted) — it maps to confirmed, NOT in_progress.
			"open":     vulnerability.FindingStatusConfirmed,
			"to do":    vulnerability.FindingStatusConfirmed,
			"backlog":  vulnerability.FindingStatusConfirmed,
			"selected": vulnerability.FindingStatusConfirmed,
			"reopened": vulnerability.FindingStatusConfirmed,
			// Duplicate is a valid webhook-settable terminal (no approval needed).
			"duplicate": vulnerability.FindingStatusDuplicate,
		},
		// OUTBOUND (finding status → Jira status NAME). Stock Jira workflow names
		// ("To Do" / "In Progress" / "Done") so it works out-of-box for default
		// projects; custom workflows override via config.ticketing.status_outbound.
		//
		// LOSSY BY NATURE: OpenCTEM has a richer lifecycle than Jira's 3 stock
		// statuses, so several finding states fold onto "Done" / "In Progress".
		// Deliberately UNMAPPED here (→ no auto-push; sync comments instead):
		//   - false_positive / accepted / accepted_risk — no stock Jira status;
		//     customers map these to their "Won't Do"/"Acknowledged" resolution.
		//   - draft / in_review — internal pentest states, hidden pre-publication.
		//   - duplicate — usually linked, not a board move.
		StatusOutbound: map[string]string{
			"new":         "To Do",
			"confirmed":   "To Do",
			"in_progress": "In Progress",
			"remediation": "In Progress", // pentest: dev fixing
			"retest":      "In Progress", // pentest: awaiting re-verification
			"fix_applied": "Done",
			"resolved":    "Done",
			"verified":    "Done", // pentest resolve
		},
		SyncEnabled:      false,
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

// JiraStatusForFinding maps a finding status to the target Jira status NAME for
// outbound sync. Returns (name, true) when a mapping exists; (_, false) when the
// finding status should not move the issue.
func (m MappingConfig) JiraStatusForFinding(findingStatus string) (string, bool) {
	s, ok := m.StatusOutbound[strings.ToLower(strings.TrimSpace(findingStatus))]
	if !ok || s == "" {
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

	// Outbound: key is a finding status (validated), value is a free-form Jira
	// status name (workflow-specific, not validated server-side).
	if raw, ok := section["status_outbound"].(map[string]any); ok {
		for findingStatus, target := range raw {
			t, ok := target.(string)
			if !ok || t == "" {
				continue
			}
			if _, err := vulnerability.ParseFindingStatus(findingStatus); err != nil {
				continue // skip unknown finding-status keys
			}
			m.StatusOutbound[strings.ToLower(strings.TrimSpace(findingStatus))] = t
		}
	}

	if v, ok := section["sync_enabled"].(bool); ok {
		m.SyncEnabled = v
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
