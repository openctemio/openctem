### Security: AI triage sends nothing until an organization administrator turns it on

- Finding content goes to an AI provider only after an owner or administrator of the organization turns AI triage on (`PUT /api/v1/organization/settings/ai`, a recent sign-in, audited as critical `ai_settings.updated`). Turning it off stops jobs already queued.
- Migration 003140 keeps AI triage on for organizations that already have an AI triage result (recorded as `enabled_by: upgrade`, one `ai_settings.opt_in_migrated` audit row each). Every other organization starts off.
- `GET /api/v1/findings/ai-triage/config` now answers `is_enabled` honestly (opted in, a provider available, budget left) with a `reason`: `not_enabled`, `platform_not_configured` or `budget_exhausted`. It also returns the month's platform token use.
- The deprecated bulk route needs `findings:bulk_update` too, and each finding counts toward the AI triage rate limit.

### Behaviour change: platform AI budgets and fair share are on by default

- The monthly platform AI token budget is enforced by default: 2,000,000 tokens per organization and month (`AI_TRIAGE_BUDGET_ENABLED=true`, `AI_TRIAGE_BUDGET_DEFAULT_TOKENS=2000000`). Organizations with their own key are not counted.
- Each organization has its own share of the platform key's rate limit (`AI_RATE_LIMIT_TENANT_RPM`, default 20 per minute) in front of the shared `AI_RATE_LIMIT_RPM`.

### Removed: `AI_TRIAGE_ENABLED`

- A provider key (environment or console) makes platform AI available; each organization then turns AI triage on itself. Startup refuses the old variable.
- **Upgrade note:** remove `AI_TRIAGE_ENABLED` from the environment before upgrading. Tell organization administrators that AI triage is now turned on in Settings > AI (organizations that already used it stay on).
