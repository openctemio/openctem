### Added: AI triage proposes false positives for a person to decide

- A completed AI triage with a false-positive likelihood of at least 0.9 on a medium or low finding creates a pending false-positive approval request. The request is made by `ai_triage` and carries the model's rationale as its justification. The finding does not change until a person approves.
- Never for critical or high findings. Never auto-approved. Never repeated while a request is pending or after a person rejected an AI proposal. Nothing is proposed when the triage output needed review (coerced fields or prompt-injection markers in the finding).
- An actor-made request counts as requested by nobody: any approver may decide it, and a person always must.
- The approval UI shows "Proposed by AI triage" (en, vi).
- Migration `002126` adds `finding_status_approvals.requested_by_actor` and one pending actor request per finding.
