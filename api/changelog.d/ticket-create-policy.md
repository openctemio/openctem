### Added: choose which findings become Jira issues automatically

- Each Jira integration has a create policy (Settings → Integrations → Ticketing → **When to create issues**): severity at least, or priority class at least, always for KEV findings, and a daily limit. A workflow's create ticket action holds a finding the policy does not pass (the step reports `held`), and the finding shows "Not sent to Jira" with **Create anyway**. Held findings are created later when they rise above the policy (severity, priority class, KEV), when the policy is loosened, or on the next day for the daily limit, at most the daily limit per day. **Preview** counts what a policy lets through before saving. Migration `ticket_create_policy` adds three empty tables.
- New routes: `GET`/`PUT /api/v1/integrations/{id}/ticket-create-policy`, `POST …/ticket-create-policy/preview` (`integrations:manage`, policy changes audited) and `GET /api/v1/findings/{id}/ticket-holds` (`findings:read`, data scope).
- `POST /api/v1/findings/{id}/create-ticket` answers 409 `TICKET_BELOW_THRESHOLD` for a finding below the policy unless the request sets `confirm_below_threshold: true`; such a create is audited (`ticket.created_below_threshold`).

### Behaviour change: automatic Jira issues skip low and informational findings by default

- Without a stored policy an integration uses the defaults: Medium or above, or priority P2 or above, or in KEV, at most 200 automatic creates per day. Workflows that filed issues for Low or Info findings now hold them; set **Severity at least** to Info and the daily limit to 0 to keep the previous behaviour. Manual creates, campaign tickets and task issues are not limited.
