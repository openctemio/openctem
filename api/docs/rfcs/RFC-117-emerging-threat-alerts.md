# RFC-117: Emerging-threat alerts

| | |
|---|---|
| Status | In progress (2026-10-19) |
| Scope | API (vulnerability event log, KEV refresh, alert planner, notifications, `/api/v1/emerging-threats`, organization settings), web console (Emerging threats page, settings card) |
| Related | RFC-066 (inventory vulnerability matching), RFC-098 (remediation tasks), `docs/architecture/notification-system.md`, `docs/architecture/emerging-threat-alerts.md` |

## 1. Summary

When a vulnerability becomes urgent (a new CVE with affected ranges, a CISA
KEV addition, an EPSS jump), an organization needs one answer fast: does it
hit us, where, and how urgently. The platform already imports the signed
vulnerability bundle, matches versions and creates findings, but a matched
CVE produced findings and no message, and a KEV addition produced one
escalation message per finding.

This RFC adds:

1. a platform-wide **vulnerability event log** (`vuln_events`): material
   changes only, public facts only;
2. an **emerging-threat alert** per organization and vulnerability (the unit
   of attention; findings stay the unit of remediation), with the affected
   assets in two tiers: *confirmed* (an open finding) and *possibly affected*
   (the product is known on the asset, its version is unknown);
3. a transparent **Emerging Threat Score** (ETS) that routes each alert to
   an *immediate* message, the *daily digest* or *listed only*;
4. delivery through the existing notification channels, in-app notifications
   and the per-user e-mail digest preference;
5. an **Emerging threats** page with triage (new, acknowledged, remediating,
   not affected) and a remediation task from the alert's findings.

## 2. Vulnerability event log

`vuln_events (id, vuln_id, kind, at, source_at, feed_sequence, detail)`, global,
written by the platform only:

| Kind | Emitted when |
|---|---|
| `published` | a CVE published in the last 30 days gets its first affected product |
| `ranges_added` | an older CVE gets its first affected product |
| `ranges_widened` | a CVE gains a product or ranges |
| `severity_up` | the severity band rises, or CVSS crosses 9.0 within the band |
| `kev_added` | the CVE enters the CISA KEV catalog (`detail.ransomware`) |
| `epss_crossed` | the EPSS score rises into a higher band (0.1, 0.5) |
| `rejected` | the CVE record is rejected or withdrawn |

Not material: description and reference edits, a CVSS move inside its band,
narrowed ranges, EPSS moves inside a band.

The emitter compares the current state with `vuln_event_state` (what it saw
last), so each change is reported once and a replay reports nothing. It runs
after every corpus import (records by their sync time, keyset cursor), after
every KEV refresh and after every EPSS refresh. The first run records the
current state and reports nothing. Events are kept two years.

The KEV catalog is refreshed **hourly** with a conditional request
(`If-None-Match`, `If-Modified-Since`; an unchanged catalog costs a 304 and
rewrites nothing). EPSS stays daily (its source publishes daily).

## 3. Alerts

`threat_alerts`: one row per (organization, vulnerability), unique on
`(tenant_id, vuln_id)`. New events update the alert and may escalate it; they
never open a second one. `threat_alert_assets`: the affected assets, with the
tier, the exposure (internet-facing) and the criticality seen at plan time,
and the finding when there is one. Both tables carry `tenant_id` with
composite foreign keys to the organization's assets.

### 3.1 When an alert is planned

- **An event** for a vulnerability queues every organization that has an
  open finding for it or a possibly affected asset.
- **The matcher creates findings** for a vulnerability: that organization is
  queued (matched findings are announced by the alert, not one by one).
- An alert is opened only inside the **active window**: an event in the last
  30 days, or a KEV addition in the last 90 days. Older vulnerabilities on
  new assets become findings and are not alerts.
- **First run in an organization** (and every organization when the feature
  ships): the planner computes the alerts of the active window and sends
  nothing immediate; one baseline digest says how many exploited
  vulnerabilities affect the organization today.
- **Rejection** upstream resolves the organization's alerts with the reason
  `rejected_upstream`.

### 3.2 Emerging Threat Score

```
exploitation = KEV 40 | EPSS >= 0.5 20 | EPSS >= 0.1 10 | none 0   (+5 KEV ransomware use)
severity     = critical 20 | high 12 | medium 5 | low 0             (+5 network, no privileges, no interaction)
exposure     = internet-facing 20 | crown jewel 15 | both 30 | internal 0   (best affected asset)
freshness    = 10 when the triggering event is less than 72 hours old
confidence   = confirmed 1.0 | likely (match below 80% confidence) 0.8 | possibly affected 0.5
ETS          = round((exploitation + severity + exposure + freshness) x confidence), 0..100
```

The breakdown is stored with the alert and shown ("why am I seeing this").

| Level | Rule (defaults; organization-tunable within bounds) |
|---|---|
| Immediate | ETS >= 70 (60-90) **and** exploitation >= 20; possibly affected assets only when the CVE is in KEV and the asset is internet-facing, unless the organization opts in |
| Daily digest | ETS >= 35 (20-60), or the severity reaches the organization's vulnerability matching minimum severity |
| Listed only | everything else that matched |

### 3.3 Fatigue controls

- One immediate message per alert per level transition; a second one only
  when a possibly affected alert becomes confirmed.
- At most **5 immediate messages per organization per hour**; the rest are
  folded into one "N more urgent alerts" message (at most one per hour) and
  stay pending until then.
- **Quiet hours** (organization-local window, default off): immediate alerts
  below the override score (default 90) are held and sent as one bundle when
  the window ends.
- Assets that join an open alert go into the next digest.
- **Not affected** suppresses the alert (reason required) for 180 days. It is
  reopened only by a stronger match (possibly affected to confirmed) or by a
  KEV addition when the reason was not "version not affected" or "wrong
  product".
- When an alert covers a CVE, the per-finding priority-escalation message
  that a KEV addition causes is not sent (one message instead of N).

### 3.4 Delivery

| Channel | Content |
|---|---|
| Notification integrations (outbox), event `emerging_threat` | vulnerability id, product, why now, counts of confirmed / possibly affected / internet-facing assets, a link. Asset names only when the organization turns them on (at most 5) |
| Notification integrations, event `emerging_threat_digest` | counts by level, top 5 vulnerability ids, a link |
| In-app | administrators |
| E-mail | each member whose `email_digest` preference is `daily` (every digest) or `weekly` (Mondays, the last 7 days), counted within their data scope; muting the digest notification type opts out |

The digest goes at 08:00 organization time (`settings.general.timezone`; the
hour is a setting) and is skipped when empty.

## 4. API and permissions

| Route | Gate |
|---|---|
| `GET /api/v1/emerging-threats` | `findings:vulnerabilities:read` |
| `GET /api/v1/emerging-threats/{id}` | `findings:vulnerabilities:read` |
| `POST /api/v1/emerging-threats/{id}/state` | `findings:triage` |
| `GET, PUT /api/v1/organization/settings/emerging-threats` | administrator (audited) |

All routes sit behind the `threat_intel` module. A remediation task is
created with the existing `POST /api/v1/remediation/tasks` (gate
`findings:remediation:write`), from the alert's open findings that are not
in an active task yet.

No new permission. Data scope: a member sees an alert only when at least one
of its assets is in their scope; the counts, the assets and the findings of
the alert are those in scope. Marking an alert *not affected* needs every
asset of the alert in the caller's scope (a member cannot suppress what they
cannot see). Out of scope answers 404.

## 5. Threat model

| Threat | Control |
|---|---|
| Organization inventory leaves the platform | Matching is in the platform only; the event log is global and holds public facts; no callback to the feed. |
| Cross-organization leak | `tenant_id` on every alert row with composite foreign keys; every query filters on the authenticated organization; tests prove another organization's alerts and assets are never returned. |
| Out-of-scope leak | Alert visibility, counts, assets and findings filtered by the caller's data scope; tests prove an out-of-scope asset never appears and its alert answers 404. |
| Existence oracle ("some organization runs X") | No API returns how many organizations an event affects; messages never mention other organizations. |
| Feed poisoning (fake urgency) | Immediate needs exploitation evidence from records (KEV, EPSS); per-organization rate cap; one message per level. |
| Hostile text in messages | Titles built from ids, catalog product names and counts; control characters and channel markup (`<>&@`) stripped; length capped; no CVE description in channel messages. |
| Notification spam | Rate cap, quiet hours, digest by default, the integrations' own filters. |
| Asset names in external channels | Off by default; organization opt-in, at most 5; channels without details enabled still get only a minimal message. |
| Suppression abuse | *Not affected* needs `findings:triage`, a reason, every asset in scope; audited; KEV reopens it. |
| Settings tampering | Administrator only, validated bounds, audited with before and after. |

## 6. Shipped and planned

Shipped by this RFC's pull requests: §2 (event log, hourly KEV), §3, §4.

Planned: exploit and PoC events from the feed (`weaponised`,
`exploit_public`, `detection_available`) and removal of the direct KEV/EPSS
fetch; possibly affected assets from version-less technologies; targeted
confirmation scans; per-asset verdicts; learning from *not affected*;
vendor advisory grouping; signal-based early warnings (opt-in).

## 7. Implementation

- `pkg/domain/vulnevent`, `internal/app/vulnevent`,
  `internal/infra/postgres/vuln_event_repository.go`, migration `vuln_events`.
- `internal/infra/controller/threat_intel_refresh.go` (hourly KEV, daily EPSS).
