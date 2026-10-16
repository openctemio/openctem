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

// Remediation suggestion decisions (RFC-098 §5). The generator itself writes
// no audit row; a person's refresh, dismissal, snooze or reopen does.
const (
	ActionRemediationSuggestionsRefreshed Action = "remediation_suggestion.refreshed"
	ActionRemediationSuggestionDismissed  Action = "remediation_suggestion.dismissed"
	ActionRemediationSuggestionSnoozed    Action = "remediation_suggestion.snoozed"
	ActionRemediationSuggestionReopened   Action = "remediation_suggestion.reopened"
)

// ResourceTypeRemediationSuggestion is a remediation suggestion.
const ResourceTypeRemediationSuggestion ResourceType = "remediation_suggestion"

var _ = registerActions("remediation_suggestion", map[Action]Severity{
	ActionRemediationSuggestionsRefreshed: SeverityLow,
	ActionRemediationSuggestionDismissed:  SeverityLow,
	ActionRemediationSuggestionSnoozed:    SeverityLow,
	ActionRemediationSuggestionReopened:   SeverityLow,
})
