package audit

// Compensating controls (api/docs/architecture/priority-explainability.md).
// An effective control lowers the priority (and so the SLA) of every finding
// on the assets it covers, so every change, test and link is recorded.

const (
	ActionCompensatingControlCreated        Action = "compensating_control.created"
	ActionCompensatingControlUpdated        Action = "compensating_control.updated"
	ActionCompensatingControlDeleted        Action = "compensating_control.deleted"
	ActionCompensatingControlTested         Action = "compensating_control.tested"
	ActionCompensatingControlAssetsLinked   Action = "compensating_control.assets_linked"
	ActionCompensatingControlFindingsLinked Action = "compensating_control.findings_linked"
)

// ResourceTypeCompensatingControl is a compensating control.
const ResourceTypeCompensatingControl ResourceType = "compensating_control"

var _ = registerActions("compensating_control", map[Action]Severity{
	ActionCompensatingControlCreated:        SeverityHigh,
	ActionCompensatingControlUpdated:        SeverityHigh,
	ActionCompensatingControlDeleted:        SeverityHigh,
	ActionCompensatingControlTested:         SeverityHigh,
	ActionCompensatingControlAssetsLinked:   SeverityHigh,
	ActionCompensatingControlFindingsLinked: SeverityMedium,
})

func init() {
	configResourceTypes[ResourceTypeCompensatingControl] = struct{}{}
}
