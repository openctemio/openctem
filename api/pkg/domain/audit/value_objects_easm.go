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

// EASM monitoring settings and run-now (research/22 P0-11). Turning
// monitoring off is high: it silences discovery and DNS checks.
const (
	ActionEASMSettingsUpdated Action = "easm_settings.updated"
	ActionEASMSweepRequested  Action = "easm_sweep.requested"
)

var _ = registerActions("easm", map[Action]Severity{
	ActionEASMSettingsUpdated: SeverityHigh,
	ActionEASMSweepRequested:  SeverityMedium,
})
