package audit

// Remediation task actions (docs/rfcs/RFC-098-remediation-tasks.md).
const (
	ActionRemediationTaskCreated      Action = "remediation_task.created"
	ActionRemediationTaskUpdated      Action = "remediation_task.updated"
	ActionRemediationTaskMembersAdded Action = "remediation_task.members_added"
	ActionRemediationTaskStateChanged Action = "remediation_task.state_changed"
)

// ResourceTypeRemediationTask is a remediation task (table remediation_tasks).
const ResourceTypeRemediationTask ResourceType = "remediation_task"

var _ = registerActions("remediation_task", map[Action]Severity{
	ActionRemediationTaskCreated:      SeverityLow,
	ActionRemediationTaskUpdated:      SeverityLow,
	ActionRemediationTaskMembersAdded: SeverityLow,
	// Canceling or holding a task stops work on its findings.
	ActionRemediationTaskStateChanged: SeverityMedium,
})
