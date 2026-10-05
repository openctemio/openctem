# Settings & Integrations

The **Settings** section is where you shape the platform to your organization —
which features are on, how it scores and prioritizes, and how it connects to your
other tools. Access-control settings (members, roles, teams, audit) are covered
separately in [Team & Access](02-team-and-access.md).

## Modules — turn features on and off

**Settings → Modules** (`/settings/modules`, "Module Management") controls which
product areas your team uses. Toggle a feature on or off and **Save Changes**.
Modules have dependencies, so the app will prompt you to **enable required**
modules a feature needs, or offer to **disable them too** when you turn something
off.

> Modules decide what appears in your sidebar. If a page in this guide isn't
> visible for your team, its module is probably disabled here. Core areas (assets,
> findings, scans) can't be turned off.

## Scoring & prioritization

- **Risk Scoring** (`/settings/scoring`) — the weighted formula behind every
  finding's risk score. See
  [Prioritization → Tune how prioritization works](05-prioritization.md#tune-how-prioritization-works).
- **Priority Rules** (`/settings/priority-rules`) — override rules that set a
  finding's priority class when conditions match.
- **SLA Policies** (`/settings/sla-policies`) — remediation deadlines per
  CTEM priority class (P0–P3), with severity windows for findings that have no
  class yet. See [Mobilization → SLA compliance](07-mobilization.md#sla-compliance).

## Notifications

**Settings → Notifications** (`/settings/notifications`) controls in-app alerts.
Toggle **Enable In-App Notifications** and set your per-category preferences, then
**Save Changes**. (Outbound channels like Slack/email/SIEM are configured under
Integrations, below.)

## Integrations

**Settings → Integrations** (`/settings/integrations`) is the hub. It lists
integration categories and recent sync activity, and routes to a page per
integration type. You'll typically start from "No integrations configured yet"
and add what you need:

| Integration | What it connects |
|-------------|------------------|
| **Ticketing** | Jira Cloud — pick a project, map severity → priority, and set bidirectional status sync. This is what powers **Create Jira Epic/Ticket** in [Mobilization](07-mobilization.md). |
| **SCMs** | Source-code hosts (e.g. GitHub) for code/repository context. |
| **Notifications** | Outbound alert channels (e.g. Slack/webhook). |
| **CI/CD** | Pipeline scanning integration. |
| **SIEM** | Send detections out to, and ingest signal from, your SIEM. |
| **SAML SSO** | SAML-based single sign-on. |
| **SCIM Provisioning** | Automated user provisioning/de-provisioning tokens. |
| **Verified Domains** | Prove ownership of email domains (gates SSO auto-join). |
| **AI Access (MCP)** | Read-only Model Context Protocol access for AI assistants, using `oct_` API keys. The same keys can also read the REST API (GET only, within the key's scopes) for scripts and automation. |

> **Ticketing note:** pushing work items to an external tracker is **Jira** today
> (Create Jira Epic on campaigns, Create Jira Ticket on a finding). GitHub is
> available as a source-code integration, not as a ticketing target.

For the operator-side setup of specific integrations, see the architecture and
how-to docs: [SSO](../architecture/sso-authentication.md) ·
[Configure Entra ID](../how-to/configure-entraid.md) ·
[Ticketing](../architecture/ticketing-integration.md) ·
[SIEM ingest](../architecture/siem-ingest.md) ·
[SCIM](../architecture/scim-provisioning.md) ·
[MCP server](../architecture/mcp-server.md).
