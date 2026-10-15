### Fixed: inbound Jira webhooks work with stock Jira

- Inbound Jira status sync required a custom signature header and timestamp that Jira never sends, so every real delivery was refused. Each Jira integration now has its own webhook URL, `/hooks/jira-integrations/{integration_id}`, verified with Jira's own `X-Hub-Signature` (HMAC-SHA256 of the body) under that integration's secret.
- Replays are refused by delivery id (`X-Atlassian-Webhook-Identifier`, else the body hash) and by the payload timestamp (at most one hour old); per-IP and per-integration rate limits apply.
- The secret is set in Settings > Integrations > Ticketing > Inbound webhook: generated (shown once) or entered from Jira, stored encrypted, never returned.

### Removed: the tenant-wide Jira webhook route and secret endpoints

- `POST /api/v1/webhooks/incoming/jira?tenant=`, `GET /api/v1/integrations/jira/webhook-secret` and `POST /api/v1/integrations/jira/webhook-secret/rotate` are removed (the secret could be read back at any time). Use `GET /api/v1/integrations/{id}/jira-webhook`, `POST /api/v1/integrations/{id}/jira-webhook/secret/rotate` and `PUT /api/v1/integrations/{id}/jira-webhook/secret`.
- **Upgrade note:** a Jira webhook pointed at the old URL stops being accepted (it was refused before as well); create it again with the new URL and secret.
