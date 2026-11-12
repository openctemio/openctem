### Added: per-use-case AI settings (Settings > AI > Use cases)

- For triage, remediation steps and summary an organization sets the mode (off, suggest, auto-apply),
  the most sensitive data class sent (public, internal, restricted) and the minimum confidence to
  apply on its own (0.50 to 0.99, default 0.85). `GET /api/v1/organization/settings/ai/use-cases`
  (settings:read) and `PUT /api/v1/organization/settings/ai/use-cases/{use_case}` (owner or
  administrator with settings:write). Migration `ai_use_cases` adds `tenant_ai_settings.use_cases`
  (no rewrite, no backfill).
- Turning auto-apply on, raising the ceiling above internal, or lowering the minimum confidence while
  auto-applying needs a recent sign-in, is audited `ai_use_case.updated` at critical severity and
  tells every owner and administrator.
- A use case in auto-apply falls back to suggest when people reject 20 percent of the last 50 (at
  least 10) requests its AI filed since auto-apply was turned on (`ai_use_case.downgraded`).

### Behaviour change: AI results wait for a person unless the use case auto-applies

- Every use case starts in suggest mode. Until an owner or administrator turns auto-apply on, an AI
  agent with the triage preset no longer confirms findings or files false-positive and severity
  requests on its own (it comments), and AI triage no longer files false-positive requests on its own.
- A severity is never changed by AI, even in auto-apply: a raise stays a suggestion, a downgrade
  becomes a severity request.
- AI triage sends only the fields within the triage use case's ceiling: the code snippet is
  restricted and no longer sent under the default (internal). A finding with nothing within the
  ceiling fails with `nothing_to_send`; a use case that is off refuses with `AI_USE_CASE_OFF`.
