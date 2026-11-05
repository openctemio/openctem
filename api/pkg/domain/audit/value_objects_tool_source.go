package audit

// Organization keys of third-party tool sources (docs/architecture/tool-source-keys.md).
// Values are never in an event: the source, the last four characters and
// the actor only; a delivery names the sensor and the command.

const (
	ActionToolSourceKeySet       Action = "tool_source_key.set"
	ActionToolSourceKeyEnabled   Action = "tool_source_key.enabled"
	ActionToolSourceKeyDisabled  Action = "tool_source_key.disabled"
	ActionToolSourceKeyDeleted   Action = "tool_source_key.deleted"
	ActionToolSourceKeyDelivered Action = "tool_source_key.delivered"
)

// ResourceTypeToolSourceKey is an organization's key of one tool source.
const ResourceTypeToolSourceKey ResourceType = "tool_source_key"

var _ = registerActions("tool_source_key", map[Action]Severity{
	ActionToolSourceKeySet:       SeverityHigh,
	ActionToolSourceKeyEnabled:   SeverityMedium,
	ActionToolSourceKeyDisabled:  SeverityMedium,
	ActionToolSourceKeyDeleted:   SeverityHigh,
	ActionToolSourceKeyDelivered: SeverityLow,
})

func init() {
	configResourceTypes[ResourceTypeToolSourceKey] = struct{}{}
}
