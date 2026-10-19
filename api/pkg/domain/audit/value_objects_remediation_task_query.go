package audit

// Remediation tasks created from a custom query
// (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query"). The query
// text is stored on each row's metadata, so who selected which findings,
// and how, stays answerable.
const (
	// ActionRemediationTaskCreatedFromQuery: a person created a task from a
	// query (snapshot or auto mode).
	ActionRemediationTaskCreatedFromQuery Action = "remediation_task.created_from_query"
	// ActionRemediationTaskQueryRerun: a person re-ran a task's query and
	// confirmed adding its new matches.
	ActionRemediationTaskQueryRerun Action = "remediation_task.query_rerun"
	// ActionRemediationTaskQueryAutoAdded: auto mode added new matches, as
	// the query's owner.
	ActionRemediationTaskQueryAutoAdded Action = "remediation_task.query_auto_added"
	// ActionRemediationTaskQueryAutoStateChanged: auto mode was paused,
	// resumed or suspended (the owner left or lost access).
	ActionRemediationTaskQueryAutoStateChanged Action = "remediation_task.query_auto_state_changed"
)

var _ = registerActions("remediation_task_query", map[Action]Severity{
	ActionRemediationTaskCreatedFromQuery: SeverityLow,
	ActionRemediationTaskQueryRerun:       SeverityLow,
	// The platform adds findings to a task without a person.
	ActionRemediationTaskQueryAutoAdded:        SeverityMedium,
	ActionRemediationTaskQueryAutoStateChanged: SeverityMedium,
})
