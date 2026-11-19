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
exploitation = KEV 40 | card: vendor-confirmed or exploited in the wild 40, weaponised 30,
               public proof of concept 20 | EPSS >= 0.5 20 | EPSS >= 0.1 10 | none 0
               (the strongest one counts; +5 KEV ransomware use)
severity     = critical 20 | high 12 | medium 5 | low 0             (+5 network, no privileges, no interaction)
exposure     = internet-facing 20 | crown jewel 15 | both 30 | internal 0   (best affected asset)
freshness    = 10 when the triggering event is less than 72 hours old
confidence   = confirmed 1.0 | likely (match below 80% confidence) 0.8 | possibly affected 0.5
ETS          = round((exploitation + severity + exposure + freshness) x confidence), 0..100
```

The breakdown is stored with the alert and shown ("why am I seeing this");
`exploitation_basis` names the evidence the exploitation points come from
(`kev`, `vendor_confirmed_exploited`, `exploited_itw`, `weaponised`,
`poc_public`, `epss_high`, `epss`). Card statuses come from reviewed advisory
cards (§3.5), each citing its public sources; a day-0 vulnerability has no KEV
entry and no EPSS score, so a card is what lets its exploitation count.

| Level | Rule (defaults; organization-tunable within bounds) |
|---|---|
| Immediate | ETS >= 70 (60-90) **and** exploitation >= 20; possibly affected assets only when the CVE is in KEV and the asset is internet-facing, unless the organization opts in. One "check needed" exception without the threshold: a critical vulnerability with a public exploit (KEV, or a card at public proof of concept or stronger; EPSS alone never) on a possibly affected asset that is internet-facing **and** of business criticality critical; the recommended action is "confirm", and it is sent once per alert |
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
| Notification integrations (outbox), event `emerging_threat` | vulnerability id, product, why now, counts of confirmed / likely / possibly affected / internet-facing hosts (a host that serves several ports is one; architecture doc, "Counting hosts"), a link. Host names only when the organization turns them on (at most 5) |
| Notification integrations, event `emerging_threat_digest` | counts by level, top 5 vulnerability ids, a link |
| In-app | administrators |
| E-mail | each member whose `email_digest` preference is `daily` (every digest) or `weekly` (Mondays, the last 7 days), counted within their data scope; muting the digest notification type opts out |

The digest goes at 08:00 organization time (`settings.general.timezone`; the
hour is a setting) and is skipped when empty.

### 3.5 Advisory cards

An advisory card is a reviewed, product-level statement from the signed
vulnerability bundle (the `cards` stream of the intel side manifest). It can
exist before a CVE record or a CPE does, and holds: an id (`OCA-YYYY-NNNN`),
a revision, a title and nicknames, the affected products by catalog key, the
affected and fixed versions per branch (or "not published yet"), the
configuration each vulnerability needs (a closed list: `http2_enabled`,
`http3_enabled`, `mail_proxy_auth_http`, `resolver_runtime_dns`,
`kernel_sctp_reachable`, `other`), the exploitation status, links to public
proof-of-concept write-ups (metadata only: the platform never fetches them),
workarounds and what each blocks, detection ideas, the vulnerability ids it
groups, a source citation for every fact, and the review record (author,
reviewer, `two_person` or `single_review`) with a revision history. Format
`openctem.advisory-card/v1`; it grows only by optional fields, so the platform
ignores fields it does not know and reads an unknown condition as `other`.

- **Import.** The bundle importer verifies the side manifest as for KEV and
  EPSS, then validates every card (caps, citations, review record, display
  text without control, bidirectional, zero-width, line or paragraph
  separator characters, markup brackets or links, https links without
  credentials only in url fields) and applies the stream whenever its file
  (SHA-256 from the verified manifest) differs from the last one applied;
  never by data date, since a card reviewed earlier but merged later, or a
  withdrawal without a later timestamp, keeps the stream's date. The date is
  kept for the freshness status. A new card or a higher revision replaces
  the stored card; at an equal revision only a withdrawal of a standing card
  does (a withdrawn card comes back only with a higher revision); every
  revision body is kept and never overwritten; a replay or an older revision
  changes nothing. Each change is a
  `card_published`, `card_updated` or `card_withdrawn` event keyed by the
  card id. A platform without this support skips the stream (it is signed).
- **One alert per organization and card.** The vulnerabilities a reviewed
  card groups are planned as the card: their events, the matcher's findings
  and the baseline queue the card id. The card's alert holds the findings of
  every grouped vulnerability (confirmed or likely), the version-less assets
  of every product they or the card name (possible), and assets of the card's
  products whose version the card places: inside a published range likely
  (confidence 60, no finding is created), versions not published yet
  possible, outside every range left out. When the card's alert is planned,
  the organization's open alerts of the grouped vulnerabilities are resolved
  with the reason `grouped_into_card` and the card id in `grouped_into_card`;
  the person's note and the actor stay, the change is marked for the digest,
  and nothing is deleted. A new card alert starts with the strongest open
  triage state of the alerts it groups (acknowledged or remediating). Its
  severity is the strongest of the card's level and its vulnerabilities'
  records, and its exploitation the strongest a reviewed card states for any
  of them: a card never rates a grouped vulnerability lower.
- **Revision.** A revision that no longer groups a vulnerability (or a card
  that is no longer reviewed) plans that vulnerability on its own again.
- **Reported (fast lane).** A card in the `reported` state has no person's
  review yet; every fact cites a vendor, CNA or CERT source. It is shown as
  "reported, not yet reviewed" (alert titles start with that), and used for
  alerts only: its exploitation status adds no score and opens no "check
  needed", it does not group the alerts of its vulnerabilities, and it
  creates no finding and no scan. A person's review makes it `reviewed` in a
  new revision.
- **Withdrawal.** A withdrawn card resolves its alerts (`card_withdrawn`) and
  the vulnerabilities it grouped are planned on their own again (their
  earlier alerts reopen when still affected).
- **Detail.** `GET /api/v1/emerging-threats/{id}` returns `card` (the
  validated card, plain text) and `exploitation` with
  `exploitation_sources`; the timeline holds the card's events and those of
  its vulnerabilities.

Review is a role, not a person: the card records its author and reviewer, and
a card its own author published says `single_review`, visibly. The producer
accepts a reviewer only from a code-owned allowlist in the card repository.

Planned (P1): a card whose every fact comes from structured, signed or
authoritative machine-readable vendor data (CSAF, OSV or GHSA records with
explicit ranges) may be published as reviewed by rule, recorded as such and
never as a person. Facts taken from free text keep needing a person's
review. The review
queue, the reviewer permission, notifications and review metrics are planned
(§6).

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
| Feed poisoning (fake urgency) | Immediate needs exploitation evidence from signed records (KEV, EPSS, reviewed cards); per-organization rate cap; one message per level. A card is accepted only from the signed manifest built for the applied sequence, only when reported (every fact from a vendor, CNA or CERT source; alerts only, no score), reviewed or withdrawn, and only with every fact cited; a card's severity never lowers a grouped vulnerability's; the "check needed" exception needs a critical vulnerability, a public exploit and an internet-facing crown-jewel asset. |
| Hostile card text | Card text is validated twice (collector and platform): no control, bidirectional or zero-width characters, no markup brackets, per-field caps, at most 64 KiB per card and 2,000 cards; links https only without credentials; returned as plain text; channel messages use the card title through the same markup stripping as product names. |
| Card rollback or silent change | The collector refuses a set that drops a card or changes one without a new revision; the platform keeps the highest revision and every revision it saw. |
| Hostile text in messages | Titles built from ids, catalog product names and counts; control characters and channel markup (`<>&@`) stripped; length capped; no CVE description in channel messages. |
| Notification spam | Rate cap, quiet hours, digest by default, the integrations' own filters. |
| Asset names in external channels | Off by default; organization opt-in, at most 5; channels without details enabled still get only a minimal message. |
| Suppression abuse | *Not affected* needs `findings:triage`, a reason, every asset in scope; audited; KEV reopens it. |
| Settings tampering | Administrator only, validated bounds, audited with before and after. |

## 6. Shipped and planned

Shipped by this RFC's pull requests: §2 (event log, hourly KEV), §3, §4.

Shipped later: exploitation from reviewed advisory cards in the score, the
"check needed" exception, and advisory cards as alert keys (§3.2, §3.5).

Shipped with RFC-066 §12 (2026-11-18): possibly affected assets from
version-less technologies. A technology or `Server` header that names a
curated public product without a version is a software link, so the alert's
possible tier lists those hosts. An urgent vulnerability (in KEV; critical
with a public exploit or EPSS 0.1 or more; an open **immediate** alert of the
organization; or the platform's urgent list) gives them a finding marked
Possible, which the alert counts in its possible tier, never as likely. An
immediate alert therefore also widens what the matcher turns into findings
for that organization.

Planned: the card review queue (a `intel.cards.review` role with step-up and
audit on every publish and withdrawal, two-person review when more than one
reviewer exists, a queue with a time target by severity, reviewer
notifications and escalation, a stale-queue alarm, metrics: time to review,
time to alert, corrections per card); condition evaluation from scan evidence
(HTTP/2, HTTP/3); exploit and PoC events from the feed (`weaponised`,
`exploit_public`, `detection_available`) and removal of the direct KEV/EPSS
fetch; targeted confirmation scans; per-asset verdicts; learning from *not
affected*; vendor advisory grouping; signal-based early warnings (opt-in).

## 7. Implementation

- `pkg/domain/vulnevent`, `internal/app/vulnevent`,
  `internal/infra/postgres/vuln_event_repository.go`, migration `vuln_events`.
- `internal/infra/controller/threat_intel_refresh.go` (hourly KEV, daily EPSS).
- `pkg/domain/threatalert`, `internal/app/threatalert` (planner, delivery,
  API service), `internal/infra/postgres/threat_alert_*.go`, migrations
  `threat_alerts` and `findings_open_cve_index`, controller
  `threat-alert-planner`, `/api/v1/emerging-threats`,
  `/api/v1/organization/settings/emerging-threats`.
- Advisory cards: `pkg/domain/advisory`, `pkg/vulnbundle/cards.go`,
  `internal/app/vulnfeed/intel.go` (cards stream),
  `internal/infra/postgres/advisory_card_repository.go`,
  `internal/infra/postgres/threat_alert_cards.go`, migration `advisory_cards`.
