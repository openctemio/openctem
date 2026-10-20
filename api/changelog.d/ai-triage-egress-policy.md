### Security: AI triage follows the organization's AI data policy for pentest findings

- AI triage (the button, the `trigger_ai_triage` workflow action, auto-triage and bulk) now applies the same AI data policy as the MCP server: a pentest finding whose campaign is above the organization's TLP limit for AI (default amber), whose lead turned AI assistants off, or that has no campaign, is never sent to the model. The request answers `403 AI_POLICY_RESTRICTED`; a job queued earlier fails with `ai_policy_restricted` before the call. One shared policy (`internal/app/aipolicy`) serves both paths.
- A failed triage stores and returns a fixed failure code (`error_code`, for example `provider_rate_limited` or `internal_error`) instead of internal error text; the detail stays in the server log. Activity entries, WebSocket events, workflow events and audit rows carry the code too. The `error_message` field of the triage result is replaced by `error_code`.
- The platform AI provider key set in the console is now in the `rekey` registry, so rotating `APP_ENCRYPTION_KEY` carries it over.

### Behaviour change: an AI verdict no longer lowers a finding's priority

- A high-confidence "likely false positive" verdict used to lower a P2 finding to P3 on the next reclassification. It no longer changes the priority class; it stays a suggestion, and a confident verdict on a medium or low finding still becomes a pending false-positive request for a person.
- **Upgrade note:** findings lowered this way return to their computed class on their next reclassification.

### Fixed: AI triage retries transient provider errors

- A rate limit, timeout or provider outage now puts the triage back to pending and the job queue retries it (up to three times); only the last attempt marks it failed. Before, the first error failed the triage and every retry exited without doing anything.
- AI triage errors no longer read as "You don't have permission": platform AI not set up answers `503 AI_PLATFORM_NOT_CONFIGURED`, AI off for the organization `403 AI_DISABLED`.
