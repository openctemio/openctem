package audit

// Finding lifecycles: sub-statuses and lifecycle schemes
// (docs/rfcs/RFC-110-tenant-lifecycles.md).

const (
	ActionLifecycleSubStatusCreated  Action = "lifecycle_sub_status.created"
	ActionLifecycleSubStatusUpdated  Action = "lifecycle_sub_status.updated"
	ActionLifecycleSubStatusArchived Action = "lifecycle_sub_status.archived"
	ActionLifecycleCreated           Action = "lifecycle.created"
	ActionLifecycleUpdated           Action = "lifecycle.updated"
	ActionLifecycleArchived          Action = "lifecycle.archived"
	// ActionLifecyclePublished records a lifecycle version put in force
	// (step-up re-authentication; the old and new spec hashes).
	ActionLifecyclePublished Action = "lifecycle.published"
)

// Resource types.
const (
	ResourceTypeLifecycleSubStatus ResourceType = "lifecycle_sub_status"
	ResourceTypeLifecycle          ResourceType = "lifecycle"
)

var _ = registerActions("lifecycle", map[Action]Severity{
	ActionLifecycleSubStatusCreated:  SeverityLow,
	ActionLifecycleSubStatusUpdated:  SeverityLow,
	ActionLifecycleSubStatusArchived: SeverityMedium,
	ActionLifecycleCreated:           SeverityMedium,
	ActionLifecycleUpdated:           SeverityMedium,
	ActionLifecycleArchived:          SeverityHigh,
	ActionLifecyclePublished:         SeverityHigh,
})

func init() {
	configResourceTypes[ResourceTypeLifecycleSubStatus] = struct{}{}
	configResourceTypes[ResourceTypeLifecycle] = struct{}{}
}
