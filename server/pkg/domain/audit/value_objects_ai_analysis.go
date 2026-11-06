package audit

// AI agents: service accounts that triage like a person, with accountable
// owners (docs/architecture/ai-analysis.md). Their own actions are audited by
// the command they call, stamped with the AI provenance; these are the
// changes to the AI agents themselves.

const (
	ActionAIAgentCreated       Action = "ai_agent.created"
	ActionAIAgentDeleted       Action = "ai_agent.deleted"
	ActionAIAgentOwnersChanged Action = "ai_agent.owners_changed"
	ActionAIAgentRoleChanged   Action = "ai_agent.role_changed"
	ActionAIAgentAttested      Action = "ai_agent.attested"
	// ActionAIAgentPaused records a pause by a person or by the platform
	// (no active owner, attestation expired, no permissions left).
	ActionAIAgentPaused   Action = "ai_agent.paused"
	ActionAIAgentResumed  Action = "ai_agent.resumed"
	ActionAIAgentDisabled Action = "ai_agent.disabled"
)

// ResourceTypeAIAnalysis is the resource of AI agent audit rows.
const ResourceTypeAIAnalysis ResourceType = "ai_analysis"

var _ = registerActions("ai_analysis", map[Action]Severity{
	ActionAIAgentCreated:       SeverityHigh,
	ActionAIAgentDeleted:       SeverityHigh,
	ActionAIAgentOwnersChanged: SeverityHigh,
	ActionAIAgentRoleChanged:   SeverityCritical,
	ActionAIAgentAttested:      SeverityMedium,
	ActionAIAgentPaused:        SeverityHigh,
	ActionAIAgentResumed:       SeverityHigh,
	ActionAIAgentDisabled:      SeverityCritical,
})
