package audit

// Organization keys of third-party tool sources (docs/architecture/task-secrets.md).
// Values are never in an event: the source, the last four characters and
// the actor only. A delivery to a sensor is a secret.delivered event.

const (
	ActionToolSourceKeySet      Action = "tool_source_key.set"
	ActionToolSourceKeyEnabled  Action = "tool_source_key.enabled"
	ActionToolSourceKeyDisabled Action = "tool_source_key.disabled"
	ActionToolSourceKeyDeleted  Action = "tool_source_key.deleted"
)

// ResourceTypeToolSourceKey is an organization's key of one tool source.
const ResourceTypeToolSourceKey ResourceType = "tool_source_key"

var _ = registerActions("tool_source_key", map[Action]Severity{
	ActionToolSourceKeySet:      SeverityHigh,
	ActionToolSourceKeyEnabled:  SeverityMedium,
	ActionToolSourceKeyDisabled: SeverityMedium,
	ActionToolSourceKeyDeleted:  SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeToolSourceKey] = struct{}{}
}
