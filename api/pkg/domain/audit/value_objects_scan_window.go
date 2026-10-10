package audit

// Scan window policies and overrides (docs/architecture/scan-windows.md).
// Rows written by the former freeze windows keep their scan_freeze_window
// actions.

const (
	ActionScanWindowPolicyCreated Action = "scan_window_policy.created"
	ActionScanWindowPolicyUpdated Action = "scan_window_policy.updated"
	ActionScanWindowPolicyDeleted Action = "scan_window_policy.deleted"
	// ActionScanWindowOverrideStarted records an emergency override of scan
	// windows (fresh authenticator code, reason, time box).
	ActionScanWindowOverrideStarted Action = "scan_window.override_started"
	// ActionScanWindowOverrideRevoked records an override ended early.
	ActionScanWindowOverrideRevoked Action = "scan_window.override_revoked"
	// ActionScanWindowOverrideRefused records an override refused for its
	// second factor.
	ActionScanWindowOverrideRefused Action = "scan_window.override_refused"
	// ActionScanWindowRefused records a run refused because a target's
	// windows never open.
	ActionScanWindowRefused Action = "scan_window.refused"
	// ActionScanWindowDeferred records a scheduled run moved to the next
	// opening because no target could run.
	ActionScanWindowDeferred Action = "scan_window.deferred"
)

// Resource types.
const (
	ResourceTypeScanWindowPolicy   ResourceType = "scan_window_policy"
	ResourceTypeScanWindowOverride ResourceType = "scan_window_override"
)

var _ = registerActions("scan_window", map[Action]Severity{
	ActionScanWindowPolicyCreated:   SeverityMedium,
	ActionScanWindowPolicyUpdated:   SeverityMedium,
	ActionScanWindowPolicyDeleted:   SeverityMedium,
	ActionScanWindowOverrideStarted: SeverityHigh,
	ActionScanWindowOverrideRevoked: SeverityMedium,
	ActionScanWindowOverrideRefused: SeverityHigh,
	ActionScanWindowRefused:         SeverityLow,
	ActionScanWindowDeferred:        SeverityLow,
})

func init() {
	configResourceTypes[ResourceTypeScanWindowPolicy] = struct{}{}
	configResourceTypes[ResourceTypeScanWindowOverride] = struct{}{}
}
