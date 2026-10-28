package audit

// AI analysts: service accounts that triage like a person, with accountable
// owners (docs/architecture/ai-analysis.md). Their own actions are audited by
// the command they call, stamped with the AI provenance; these are the
// changes to the analysts themselves.

const (
	ActionAIAnalystCreated       Action = "ai_analyst.created"
	ActionAIAnalystDeleted       Action = "ai_analyst.deleted"
	ActionAIAnalystOwnersChanged Action = "ai_analyst.owners_changed"
	ActionAIAnalystRoleChanged   Action = "ai_analyst.role_changed"
	ActionAIAnalystAttested      Action = "ai_analyst.attested"
	// ActionAIAnalystPaused records a pause by a person or by the platform
	// (no active owner, attestation expired, no permissions left).
	ActionAIAnalystPaused   Action = "ai_analyst.paused"
	ActionAIAnalystResumed  Action = "ai_analyst.resumed"
	ActionAIAnalystDisabled Action = "ai_analyst.disabled"
)

// ResourceTypeAIAnalysis is the resource of AI analyst audit rows.
const ResourceTypeAIAnalysis ResourceType = "ai_analysis"

var _ = registerActions("ai_analysis", map[Action]Severity{
	ActionAIAnalystCreated:       SeverityHigh,
	ActionAIAnalystDeleted:       SeverityHigh,
	ActionAIAnalystOwnersChanged: SeverityHigh,
	ActionAIAnalystRoleChanged:   SeverityCritical,
	ActionAIAnalystAttested:      SeverityMedium,
	ActionAIAnalystPaused:        SeverityHigh,
	ActionAIAnalystResumed:       SeverityHigh,
	ActionAIAnalystDisabled:      SeverityCritical,
})
