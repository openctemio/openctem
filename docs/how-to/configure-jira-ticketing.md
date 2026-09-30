# How to configure Jira ticketing

Connect a tenant to **Jira Cloud** so findings and remediation campaigns can be
pushed to Jira as issues/epics, with optional **bidirectional status sync**. This
is the integration behind **Create Jira Epic** (remediation) and **Create Jira
Ticket** (a finding). Architecture: [ticketing-integration.md](../architecture/ticketing-integration.md).

> Roles: connecting/configuring an integration needs the **admin** or **owner**
> team role (Settings → Integrations).

## 1. Create an Atlassian API token

In Atlassian (**id.atlassian.com → Security → API tokens**) create a token for the
account OpenCTEM will act as. That account must be able to browse the target
project(s) and create/transition issues in them. Jira Cloud REST auth is **basic
auth = account email + API token**.

## 2. Connect Jira in OpenCTEM

**Settings → Integrations → Ticketing → Add Connection:**

- **Provider:** Jira Cloud.
- **Connection name:** e.g. "Jira Cloud".
- **Jira base URL:** your site, e.g. `https://acme.atlassian.net`.
- **Atlassian account email:** the token's account (required — a missing email
  makes the integration silently skip).
- **Default project key** (optional): e.g. `SEC`.
- **API token:** the token from step 1 (stored encrypted).

Click **Connect**. (There is no separate "Test" button — a successful connect is
the check.)

## 3. Configure mapping & sync

Open **Configure** on the connected card:

- **Default project:** picked from a live list (`GET /integrations/jira/projects`);
  falls back to a manual text field if listing fails (bad creds / non-Cloud).
- **Ticket defaults:** issue type, default priority, and a **Severity → Jira
  priority** grid (defaults: critical→Highest, high→High, medium→Medium, low→Low).
- **Bidirectional status sync:** a switch, **off by default** — connecting never
  writes to Jira until you turn this on. Set the outbound status names if you use
  a custom Jira workflow (defaults: confirmed→To Do, in_progress→In Progress,
  fix_applied/resolved/verified→Done).
- **Inbound status mapping:** map Jira status names → finding status (done/
  resolved/closed/verified→fix_applied; in progress→in_progress; open/to do→
  confirmed; duplicate→duplicate).

Optionally set **Routing** rules (severity / scope / criticality / tag → project)
to fan tickets across projects. Ticket creation is idempotent — a finding already
ticketed in the target project is not re-created.

## 4. (Optional) Inbound webhook for status sync

To have Jira transitions flow back, point a Jira webhook at:

```
POST /api/v1/webhooks/incoming/jira?tenant=<tenant-id>
```

> **Gotcha — inbound HMAC.** The endpoint verifies an HMAC signature in the
> **`X-OpenCTEM-Signature`** header over the raw body and **fails closed** if no
> secret resolves. Stock Jira Cloud webhooks cannot produce that header, and there
> is currently **no UI field to set a per-tenant webhook secret**. In practice you
> must set the platform-wide `WEBHOOKS_JIRA_SECRET` and sign requests via a proxy
> in front of the endpoint, otherwise inbound sync rejects everything. Outbound
> (OpenCTEM → Jira) needs no webhook and works once **status sync** is on.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Integration "connected" but nothing pushes | **Bidirectional status sync** is off (default) — turn it on in Configure. |
| Project picker is empty / shows a text box | Credentials can't list projects (non-Cloud or wrong token) — enter the key manually, or fix the token. |
| Findings never get a ticket automatically | Ticket creation is on-demand (Create Jira Epic/Ticket) or via routing rules — there's no blanket auto-create. |
| Inbound transitions don't reflect | The HMAC gotcha above — inbound rejects unsigned/unknown-secret requests (fails closed). |
| Nothing happens and no error | A misconfigured integration (e.g. missing email) is skipped and logged, not surfaced — check the connection fields. |

> **GitHub Issues** is available as an alternate ticket target (`provider=github`)
> but is off unless explicitly wired — see [github-issue-ticketing.md](../architecture/github-issue-ticketing.md).
> GitHub is otherwise a *source-code* integration (SCM), not a ticketing target.
