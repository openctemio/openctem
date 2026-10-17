package audit

// Remediation task actions (docs/rfcs/RFC-098-remediation-tasks.md).
const (
	ActionRemediationTaskCreated      Action = "remediation_task.created"
	ActionRemediationTaskUpdated      Action = "remediation_task.updated"
	ActionRemediationTaskMembersAdded Action = "remediation_task.members_added"
	ActionRemediationTaskStateChanged Action = "remediation_task.state_changed"
	ActionRemediationTaskMembersMoved Action = "remediation_task.members_moved"
	ActionRemediationTaskSplit        Action = "remediation_task.split"
	ActionRemediationTaskMerged       Action = "remediation_task.merged"
	// ActionRemediationTaskFixClaimed: a person marked a task fixed.
	ActionRemediationTaskFixClaimed Action = "remediation_task.fix_claimed"
	// ActionRemediationTaskExceptionRequested: a person asked for one
	// exception (accepted risk or false positive) over the task's findings.
	ActionRemediationTaskExceptionRequested Action = "remediation_task.exception_requested"
	// ActionRemediationTaskIssueCreated: a person created the task's tracker
	// issue (the task's title and counts leave the platform).
	ActionRemediationTaskIssueCreated Action = "remediation_task.issue_created"
)

// ResourceTypeRemediationTask is a remediation task (table remediation_tasks).
const ResourceTypeRemediationTask ResourceType = "remediation_task"

var _ = registerActions("remediation_task", map[Action]Severity{
	ActionRemediationTaskCreated:      SeverityLow,
	ActionRemediationTaskUpdated:      SeverityLow,
	ActionRemediationTaskMembersAdded: SeverityLow,
	// Canceling or holding a task stops work on its findings.
	ActionRemediationTaskStateChanged: SeverityMedium,
	ActionRemediationTaskMembersMoved: SeverityLow,
	ActionRemediationTaskSplit:        SeverityLow,
	ActionRemediationTaskMerged:       SeverityLow,
	// A fix claim changes the status of every open finding of the task.
	ActionRemediationTaskFixClaimed: SeverityMedium,
	// One request to hide the risk of every open finding of the task.
	ActionRemediationTaskExceptionRequested: SeverityMedium,
	ActionRemediationTaskIssueCreated:       SeverityLow,
})

// Remediation suggestion decisions (RFC-098 §5). The generator itself writes
// no audit row; a person's refresh, dismissal, snooze or reopen does.
const (
	ActionRemediationSuggestionsRefreshed Action = "remediation_suggestion.refreshed"
	ActionRemediationSuggestionDismissed  Action = "remediation_suggestion.dismissed"
	ActionRemediationSuggestionSnoozed    Action = "remediation_suggestion.snoozed"
	ActionRemediationSuggestionReopened   Action = "remediation_suggestion.reopened"
	ActionRemediationSuggestionAccepted   Action = "remediation_suggestion.accepted"
	// ActionRemediationActionAutoJoinChanged: a person turned an action's
	// auto-join rule on or off.
	ActionRemediationActionAutoJoinChanged Action = "remediation_action.auto_join_changed"
)

// ResourceTypeRemediationAction is a remediation action (what fixes a set of
// findings).
const ResourceTypeRemediationAction ResourceType = "remediation_action"

// ResourceTypeRemediationSuggestion is a remediation suggestion.
const ResourceTypeRemediationSuggestion ResourceType = "remediation_suggestion"

var _ = registerActions("remediation_suggestion", map[Action]Severity{
	ActionRemediationSuggestionsRefreshed: SeverityLow,
	ActionRemediationSuggestionDismissed:  SeverityLow,
	ActionRemediationSuggestionSnoozed:    SeverityLow,
	ActionRemediationSuggestionReopened:   SeverityLow,
	ActionRemediationSuggestionAccepted:   SeverityLow,
})

// Auto-join makes the platform add findings to tasks without a person.
var _ = registerActions("remediation_action", map[Action]Severity{
	ActionRemediationActionAutoJoinChanged: SeverityMedium,
})
