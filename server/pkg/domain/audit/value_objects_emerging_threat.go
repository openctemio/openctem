package audit

// Emerging-threat alerts (docs/rfcs/RFC-117-emerging-threat-alerts.md): the
// organization's alert policy and every triage decision on an alert are
// recorded (a "not affected" decision suppresses an alert).

const (
	// ActionTenantEmergingThreatsUpdated records a change to the
	// organization's emerging-threat alert policy.
	ActionTenantEmergingThreatsUpdated Action = "tenant.emerging_threats_updated"
	// ActionEmergingThreatStateChanged records a triage decision on an alert.
	ActionEmergingThreatStateChanged Action = "emerging_threat.state_changed"
)

// ResourceTypeEmergingThreat is an emerging-threat alert.
const ResourceTypeEmergingThreat ResourceType = "emerging_threat"

var _ = registerActions("emerging_threat", map[Action]Severity{
	ActionTenantEmergingThreatsUpdated: SeverityMedium,
	ActionEmergingThreatStateChanged:   SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeEmergingThreat] = struct{}{}
}
