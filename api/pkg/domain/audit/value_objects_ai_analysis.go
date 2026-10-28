package audit

// AI governance: use-case policy and suggestions (docs/architecture/ai-analysis.md).

const (
	// ActionAIUseCaseUpdated records an administrator changing an AI use
	// case's mode, data class ceiling or limits.
	ActionAIUseCaseUpdated Action = "ai_use_case.updated"
	// ActionAIUseCaseDowngraded records auto-apply falling back to suggest
	// because people overrode too many suggestions.
	ActionAIUseCaseDowngraded Action = "ai_use_case.downgraded"
	// ActionAISuggestionApplied records a person applying a suggestion.
	ActionAISuggestionApplied Action = "ai_suggestion.applied"
	// ActionAISuggestionAutoApplied records the organization's auto-apply
	// policy applying an additive suggestion.
	ActionAISuggestionAutoApplied Action = "ai_suggestion.auto_applied"
	// ActionAISuggestionApprovalRequested records a suggestion becoming an
	// approval request (always the case for risk-lowering changes).
	ActionAISuggestionApprovalRequested Action = "ai_suggestion.approval_requested"
	// ActionAISuggestionDismissed records a person declining a suggestion.
	ActionAISuggestionDismissed Action = "ai_suggestion.dismissed"
	// ActionAISuggestionUndone records a person undoing an applied suggestion.
	ActionAISuggestionUndone Action = "ai_suggestion.undone"
)

// ResourceTypeAIAnalysis is the resource of AI use-case and suggestion audit rows.
const ResourceTypeAIAnalysis ResourceType = "ai_analysis"

var _ = registerActions("ai_analysis", map[Action]Severity{
	ActionAIUseCaseUpdated:              SeverityCritical,
	ActionAIUseCaseDowngraded:           SeverityHigh,
	ActionAISuggestionApplied:           SeverityLow,
	ActionAISuggestionAutoApplied:       SeverityMedium,
	ActionAISuggestionApprovalRequested: SeverityMedium,
	ActionAISuggestionDismissed:         SeverityLow,
	ActionAISuggestionUndone:            SeverityMedium,
})
