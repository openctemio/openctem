package audit

// Scan freeze windows (docs/architecture/scan-zones.md, "Freeze windows").

const (
	ActionScanFreezeWindowCreated Action = "scan_freeze_window.created"
	ActionScanFreezeWindowUpdated Action = "scan_freeze_window.updated"
	ActionScanFreezeWindowDeleted Action = "scan_freeze_window.deleted"
	// ActionScanFreezeOverridden records a member starting a scan by hand
	// while a freeze window was active, with scans:freeze:override.
	ActionScanFreezeOverridden Action = "scan_freeze_window.overridden"
	// ActionScanFreezeRefused records a trigger refused by an active window.
	ActionScanFreezeRefused Action = "scan_freeze_window.refused"
	// ActionScanFreezeDeferred records a scheduled run moved to the end of
	// an active window.
	ActionScanFreezeDeferred Action = "scan_freeze_window.deferred"
)

// ResourceTypeScanFreezeWindow is a freeze window.
const ResourceTypeScanFreezeWindow ResourceType = "scan_freeze_window"

var _ = registerActions("scan_freeze_window", map[Action]Severity{
	ActionScanFreezeWindowCreated: SeverityMedium,
	ActionScanFreezeWindowUpdated: SeverityMedium,
	ActionScanFreezeWindowDeleted: SeverityMedium,
	ActionScanFreezeOverridden:    SeverityHigh,
	ActionScanFreezeRefused:       SeverityLow,
	ActionScanFreezeDeferred:      SeverityLow,
})

func init() {
	configResourceTypes[ResourceTypeScanFreezeWindow] = struct{}{}
}
