### Fixed: a module switched off is off on every surface, on every replica

- MCP: the tools and prompts of a module the organization has off (pentest, compliance,
  attack surface) are no longer listed and answer "This module is not enabled for your
  team", as their REST routes do.
- AI triage: `/api/v1/findings/{id}/ai-triage*` and `/api/v1/findings/ai-triage/*` follow the
  `ai_triage` module (403 `MODULE_NOT_ENABLED` when off), and auto-triage does not start.
- Automations: events start no automation for an organization with the `workflows` module
  off. The background remediation progress pass leaves the campaigns of an organization
  with `remediation` off untouched (no counts, no auto-complete, no ticket sync).
- A module toggle reaches every API replica at once through Redis (`modules:changed`);
  before, other replicas kept the old state for up to a minute.
- Console: the sidebar, the route guard and every module check follow a toggle at once,
  in every open tab, without a reload (they read the session bootstrap, which a toggle did
  not refresh).
