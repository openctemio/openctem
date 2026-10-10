package audit

// Scan approval governance actions (docs/rfcs/RFC-072-scan-approval-governance.md).
// The settings actions are on the organization (tenant).
const (
	// ActionScanGovernanceModeChanged: an owner turned scan approval off,
	// on or strict (step-up, reason).
	ActionScanGovernanceModeChanged Action = "scan_governance.mode_changed"
	// ActionScanGovernanceRulesUpdated: an owner or administrator changed
	// the approval rules (step-up, reason).
	ActionScanGovernanceRulesUpdated Action = "scan_governance.rules_updated"
)

var _ = registerActions("scan_governance", map[Action]Severity{
	ActionScanGovernanceModeChanged:  SeverityHigh,
	ActionScanGovernanceRulesUpdated: SeverityHigh,
})
