package jira

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/vulnerability"
)

func TestDefaultMapping_PreservesLegacyBehaviour(t *testing.T) {
	m := DefaultMappingConfig()

	// Severity → priority parity with the original hardcoded switch.
	cases := map[string]string{
		"critical": "Highest",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
		"weird":    "Medium",  // fallback
		"CRITICAL": "Highest", // case-insensitive
	}
	for sev, want := range cases {
		if got := m.PriorityForSeverity(sev); got != want {
			t.Errorf("PriorityForSeverity(%q) = %q, want %q", sev, got, want)
		}
	}

	// Status → finding parity.
	// NOTE: "open" maps to confirmed (Jira's classic *initial/unstarted* status),
	// not in_progress — a correctness fix over the original map.
	statusCases := map[string]vulnerability.FindingStatus{
		"In Progress": vulnerability.FindingStatusInProgress,
		"open":        vulnerability.FindingStatusConfirmed,
		"Done":        vulnerability.FindingStatusFixApplied,
		"RESOLVED":    vulnerability.FindingStatusFixApplied,
		"verified":    vulnerability.FindingStatusFixApplied,
		"Backlog":     vulnerability.FindingStatusConfirmed,
		"reopened":    vulnerability.FindingStatusConfirmed,
		"Duplicate":   vulnerability.FindingStatusDuplicate,
	}
	for js, want := range statusCases {
		got, ok := m.FindingStatusForJira(js)
		if !ok || got != want {
			t.Errorf("FindingStatusForJira(%q) = (%q,%v), want (%q,true)", js, got, ok, want)
		}
	}

	if _, ok := m.FindingStatusForJira("Some Custom State"); ok {
		t.Error("unmapped Jira status should return ok=false")
	}
}

func TestParseMappingConfig_NoSection_ReturnsDefaults(t *testing.T) {
	m := ParseMappingConfig(map[string]any{"other": 1})
	if m.PriorityForSeverity("critical") != "Highest" {
		t.Fatal("missing ticketing section must yield defaults")
	}
}

func TestParseMappingConfig_OverlaysOverrides(t *testing.T) {
	cfg := map[string]any{
		"ticketing": map[string]any{
			"issue_type":       "Task",
			"default_priority": "P3",
			"severity_to_priority": map[string]any{
				"critical": "P1",
				"HIGH":     "P2", // case-insensitive key
			},
			"status_inbound": map[string]any{
				"Shipped": "fix_applied",
				"QA":      "in_progress",
			},
		},
	}
	m := ParseMappingConfig(cfg)

	if m.DefaultIssueType != "Task" {
		t.Errorf("issue_type override not applied: %q", m.DefaultIssueType)
	}
	if got := m.PriorityForSeverity("critical"); got != "P1" {
		t.Errorf("severity override not applied: %q", got)
	}
	if got := m.PriorityForSeverity("high"); got != "P2" {
		t.Errorf("case-insensitive severity override failed: %q", got)
	}
	// Untouched severity keeps default.
	if got := m.PriorityForSeverity("low"); got != "Low" {
		t.Errorf("untouched severity should keep default, got %q", got)
	}
	// Unmapped severity now falls back to overridden default priority.
	if got := m.PriorityForSeverity("none"); got != "P3" {
		t.Errorf("default_priority override not applied: %q", got)
	}

	// Custom inbound statuses map.
	if s, ok := m.FindingStatusForJira("shipped"); !ok || s != vulnerability.FindingStatusFixApplied {
		t.Errorf("custom status 'Shipped' not mapped: (%q,%v)", s, ok)
	}
	if s, ok := m.FindingStatusForJira("QA"); !ok || s != vulnerability.FindingStatusInProgress {
		t.Errorf("custom status 'QA' not mapped: (%q,%v)", s, ok)
	}
	// Default statuses still present.
	if s, ok := m.FindingStatusForJira("Done"); !ok || s != vulnerability.FindingStatusFixApplied {
		t.Errorf("default status 'Done' lost after overlay: (%q,%v)", s, ok)
	}
}

func TestParseMappingConfig_SkipsInvalidStatusTarget(t *testing.T) {
	cfg := map[string]any{
		"ticketing": map[string]any{
			"status_inbound": map[string]any{
				"Bogus":    "not_a_real_status",
				"Deployed": "fix_applied",
			},
		},
	}
	m := ParseMappingConfig(cfg)

	if _, ok := m.FindingStatusForJira("Bogus"); ok {
		t.Error("invalid status target must be skipped")
	}
	if s, ok := m.FindingStatusForJira("Deployed"); !ok || s != vulnerability.FindingStatusFixApplied {
		t.Errorf("valid sibling override should still apply: (%q,%v)", s, ok)
	}
}

func TestParseMappingConfig_ToleratesWrongTypes(t *testing.T) {
	cfg := map[string]any{
		"ticketing": map[string]any{
			"severity_to_priority": "not a map",
			"status_inbound":       42,
			"issue_type":           true,
		},
	}
	m := ParseMappingConfig(cfg) // must not panic
	if m.PriorityForSeverity("critical") != "Highest" {
		t.Error("malformed overrides should leave defaults intact")
	}
}

func TestDefaultMapping_OutboundDefaults(t *testing.T) {
	m := DefaultMappingConfig()
	if m.SyncEnabled {
		t.Error("outbound sync must default to DISABLED")
	}
	if got, ok := m.JiraStatusForFinding("resolved"); !ok || got != "Done" {
		t.Errorf("resolved -> %q,%v; want Done,true", got, ok)
	}
	if got, ok := m.JiraStatusForFinding("in_progress"); !ok || got != "In Progress" {
		t.Errorf("in_progress -> %q,%v; want In Progress,true", got, ok)
	}
	// A finding status with no default mapping must not push.
	if _, ok := m.JiraStatusForFinding("false_positive"); ok {
		t.Error("false_positive should be unmapped by default (no stock Jira status)")
	}
}

func TestParseMappingConfig_OutboundOverlayAndSwitch(t *testing.T) {
	m := ParseMappingConfig(map[string]any{
		"ticketing": map[string]any{
			"sync_enabled": true,
			"status_outbound": map[string]any{
				"false_positive": "Won't Do", // custom workflow status
				"resolved":       "Shipped",  // override default
				"not_a_status":   "Ignored",  // invalid finding-status key -> skipped
				"in_progress":    "",         // empty -> skipped, default kept
			},
		},
	})

	if !m.SyncEnabled {
		t.Error("sync_enabled:true must be parsed")
	}
	if got, _ := m.JiraStatusForFinding("false_positive"); got != "Won't Do" {
		t.Errorf("false_positive -> %q; want Won't Do", got)
	}
	if got, _ := m.JiraStatusForFinding("resolved"); got != "Shipped" {
		t.Errorf("resolved override -> %q; want Shipped", got)
	}
	if _, ok := m.JiraStatusForFinding("not_a_status"); ok {
		t.Error("invalid finding-status key must be skipped")
	}
	// Empty value skipped → default ("In Progress") preserved.
	if got, _ := m.JiraStatusForFinding("in_progress"); got != "In Progress" {
		t.Errorf("in_progress empty override should keep default, got %q", got)
	}
}
