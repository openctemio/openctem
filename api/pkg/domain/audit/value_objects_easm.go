package audit

// EASM actions (docs/rfcs/RFC-036-easm.md).

// ActionScanTargetRefused records an active-scan request the ownership gate
// refused (a rejected, unreviewed or unattributed target). The caller sees a
// generic reason; the audit entry keeps the refusing state for the tenant's
// administrators (research/22 §4.0).
const ActionScanTargetRefused Action = "scan.target_refused"

var _ = registerActions("scan", map[Action]Severity{
	ActionScanTargetRefused: SeverityMedium,
})
