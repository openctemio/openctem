### Added: knowledge sources for AI agents, cited in triage runs

- Organizations can give their AI agents runbooks, conventions and architecture notes (Settings > AI > Knowledge sources). Text or Markdown up to 256 KB per document; a document holding a credential is refused; text that tries to instruct a model is quarantined until a reviewer acknowledges it.
- Nothing reaches an AI agent until a second person approves it (the organization owner may approve their own, recorded as a self-approval). Editing a document creates a pending version; the approved one keeps serving until then. Disabling a source applies at once.
- A source is visible to every AI agent of the organization or only to AI agents in chosen teams, and carries a data class (internal or restricted) checked against each agent's ceiling. Retrieval never crosses organizations.
- Built-in triage, remediation and summary runs retrieve matching excerpts as the AI agent, masked and fenced, and cite them as `kb:<n>`. Knowledge alone never changes a finding: such a suggestion is written as a comment. The AI agent's comment names the cited documents, and the run detail lists what the run saw (`retrieval_mode`, `knowledge`).
- New permissions `ai_knowledge:read` and `ai_knowledge:manage` (owner and administrator roles). Migration 20261031065120.
