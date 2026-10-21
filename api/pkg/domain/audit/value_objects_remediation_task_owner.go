package audit

// ActionRemediationTaskOwnerMoved: the owner of a live task moved a finding
// of that task through the task-owner relation (the finding is outside their
// data scope): start work, claim the fix or go back.
const ActionRemediationTaskOwnerMoved Action = "remediation_task.owner_moved_finding"

var _ = registerActions("remediation_task", map[Action]Severity{
	// A status change on a finding the actor reaches only as task owner.
	ActionRemediationTaskOwnerMoved: SeverityMedium,
})
