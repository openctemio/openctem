### Behaviour change: closing one finding no longer asks for an authenticator code

- Closing a single finding (from the findings list, a single Ready-to-close confirm, or the finding's
  own status change) is now a **routine** action. Routine actions do not ask for re-verification
  unless the organization turns it on. Closing two or more findings still asks.

### Added: re-verification policy per organization

- Owners choose, per tier, how often people confirm their identity again before an action.
  - Tiers: critical, sensitive and routine.
  - Choices: every time, once per 10 minutes, 1 hour, 4 hours, 8 hours, once per sign-in, or never.
  - Where: Settings > Security > Authentication, card "Re-verification", or `step_up` on
    `PATCH /api/v1/tenants/{tenant}/settings/security`.
- Critical actions (roles, sign-in, credentials, secrets, deletion, approving active scanning,
  exports) always ask, every time or once per 10 minutes. The API refuses anything else with 422
  `STEP_UP_POLICY_BELOW_FLOOR`.
- Defaults:
  - Existing organizations keep today's behaviour: critical and sensitive once per 10 minutes.
  - New organizations: critical once per 10 minutes, sensitive once per hour.
  - Routine is off for both.
- Changes are audited as `tenant.step_up_policy_changed`, high when looser. Every audited action
  behind re-verification records the rule that admitted it (metadata `step_up`).
- Migration `20261106030244` adds `sessions.step_up_spent_at`, used by the "every time" rule. It is
  nullable and rewrites no rows.
