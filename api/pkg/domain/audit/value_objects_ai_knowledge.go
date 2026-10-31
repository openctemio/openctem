package audit

// Knowledge sources for AI agents (docs/architecture/ai-knowledge.md): who
// added, approved, rejected, disabled or deleted the text AI agents retrieve.

const (
	ActionAIKnowledgeSourceCreated  Action = "ai_knowledge.source_created"
	ActionAIKnowledgeSourceUpdated  Action = "ai_knowledge.source_updated"
	ActionAIKnowledgeSourceApproved Action = "ai_knowledge.source_approved"
	ActionAIKnowledgeSourceRejected Action = "ai_knowledge.source_rejected"
	ActionAIKnowledgeSourceDisabled Action = "ai_knowledge.source_disabled"
	ActionAIKnowledgeSourceDeleted  Action = "ai_knowledge.source_deleted"
	ActionAIKnowledgeDocumentAdded  Action = "ai_knowledge.document_added"
	// ActionAIKnowledgeDocumentDeleted removes every version of a document.
	ActionAIKnowledgeDocumentDeleted Action = "ai_knowledge.document_deleted"
)

// ResourceTypeAIKnowledge is the resource of knowledge source audit rows.
const ResourceTypeAIKnowledge ResourceType = "ai_knowledge"

var _ = registerActions("ai_knowledge", map[Action]Severity{
	ActionAIKnowledgeSourceCreated:   SeverityMedium,
	ActionAIKnowledgeSourceUpdated:   SeverityLow,
	ActionAIKnowledgeSourceApproved:  SeverityHigh,
	ActionAIKnowledgeSourceRejected:  SeverityMedium,
	ActionAIKnowledgeSourceDisabled:  SeverityMedium,
	ActionAIKnowledgeSourceDeleted:   SeverityMedium,
	ActionAIKnowledgeDocumentAdded:   SeverityMedium,
	ActionAIKnowledgeDocumentDeleted: SeverityMedium,
})
