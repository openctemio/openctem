package audit

// Scan approval governance actions (docs/rfcs/RFC-072-scan-approval-governance.md).
// The resource of a request action is the scan (scan_config); the settings
// actions are on the organization (tenant).
const (
	// ActionScanGovernanceModeChanged: an owner turned scan approval off,
	// on or strict (step-up, reason).
	ActionScanGovernanceModeChanged Action = "scan_governance.mode_changed"
	// ActionScanGovernanceRulesUpdated: an owner or administrator changed
	// the approval rules (step-up, reason).
	ActionScanGovernanceRulesUpdated Action = "scan_governance.rules_updated"

	ActionScanApprovalRequested  Action = "scan_approval.requested"
	ActionScanApprovalApproved   Action = "scan_approval.approved"
	ActionScanApprovalGranted    Action = "scan_approval.granted"
	ActionScanApprovalRejected   Action = "scan_approval.rejected"
	ActionScanApprovalCanceled   Action = "scan_approval.canceled"
	ActionScanApprovalReminded   Action = "scan_approval.reminded"
	ActionScanApprovalSelfApprov Action = "scan_approval.self_approved"
	// ActionScanEmergencyRun: an owner or administrator ran a scan without
	// its approval, time-boxed, with a reason.
	ActionScanEmergencyRun Action = "scan_approval.emergency_run"
	// ActionScanApprovalRefused: a run refused for a missing approval.
	ActionScanApprovalRefused Action = "scan_approval.run_refused"
	// ActionScanApprovalMonitored: a monitor-mode rule caught a run it
	// would have held.
	ActionScanApprovalMonitored Action = "scan_approval.monitor_match"
)

var _ = registerActions("scan_governance", map[Action]Severity{
	ActionScanGovernanceModeChanged:  SeverityHigh,
	ActionScanGovernanceRulesUpdated: SeverityHigh,
	ActionScanApprovalRequested:      SeverityMedium,
	ActionScanApprovalApproved:       SeverityMedium,
	ActionScanApprovalGranted:        SeverityMedium,
	ActionScanApprovalRejected:       SeverityMedium,
	ActionScanApprovalCanceled:       SeverityLow,
	ActionScanApprovalReminded:       SeverityLow,
	ActionScanApprovalSelfApprov:     SeverityHigh,
	ActionScanEmergencyRun:           SeverityCritical,
	ActionScanApprovalRefused:        SeverityMedium,
	ActionScanApprovalMonitored:      SeverityLow,
})
