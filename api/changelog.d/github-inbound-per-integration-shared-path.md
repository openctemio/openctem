### Security: GitHub inbound webhooks are verified per integration and closed issues follow the shared ticket rules

- Each GitHub integration has its own inbound webhook URL, `POST /hooks/github-integrations/{integration_id}`, verified with that integration's own secret (`X-Hub-Signature-256`). The sender no longer chooses the organization, and one integration's secret no longer authenticates events for another.
- A replay is refused by the body hash as well as by `X-GitHub-Delivery` (a captured body with a new delivery id is ignored). Without the replay store every delivery is refused (503). A failed delivery releases its keys and answers 500, so a redelivery from GitHub is processed.
- A `push` or `issues` event must name its repository; when the integration is bound to a GitHub organization, a repository outside it is refused (403).
- Issue events go through the same finding rules as Jira status changes for every linked finding: closed as completed is a fix claim (proof of fix requested, never a close), closed as not planned opens a pending risk-acceptance request instead of claiming a fix, closed as duplicate changes nothing, reopened is in progress. Pentest and closed findings are not moved; the GitHub sender is recorded in the timeline.
- Rotating an inbound webhook secret (Jira or GitHub) or entering a Jira one is now a Critical audit entry; the secret is never recorded.

### Removed: the per-organization GitHub webhook URL and secret routes

- `POST /api/v1/webhooks/incoming/github?tenant=…`, `GET /api/v1/integrations/github/webhook-secret` and `POST /api/v1/integrations/github/webhook-secret/rotate` are removed. Use `GET /api/v1/integrations/{id}/github-webhook` (URL, whether a secret is set) and `POST /api/v1/integrations/{id}/github-webhook/secret/rotate` (shown once; needs `integrations:manage`, `integrations:scm:write` and step-up).
- **Upgrade note:** in each GitHub repository or organization webhook, replace the URL with the integration's new URL. A secret already generated for the organization's first GitHub integration keeps working on that integration's URL; other GitHub integrations need a secret generated.
