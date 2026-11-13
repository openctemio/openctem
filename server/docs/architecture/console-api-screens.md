# Console API: screens and their data

Design: [RFC-157](../rfcs/RFC-157-console-api-design.md). Example bodies:
[console-api-examples.md](console-api-examples.md).

This page lists every screen of the redesigned console with the data blocks on it: where each block's data
comes from, when it is loaded, how fresh it must be and who may read it. It is the reference a change to a screen
or an endpoint is checked against: a new block follows the shaping rules of RFC-157 section 3.2, and a screen
stays inside its request budget.

| Part | Status |
|---|---|
| Session bootstrap, page views (finding, asset, dashboard home), list contract base, operation resource, WebSocket | **Shipped** |
| Reference catalog, lean list rows, keyset paging and bounded totals on large lists, findings facets, global search, bulk undo, new live events | Planned |
| New views (scan run, CTEM cycle, sensor, component, pentest campaign, organization detail in the admin console) | Planned |
| Screens and endpoints marked "planned (new)" below | Planned |

## How to read the tables

- **Endpoint**: the route under `/api/v1`, or the bootstrap (`/me/bootstrap`), or "none" for data that is static
  in the web build (navigation, the settings index).
- **Loaded**: `first view` (needed to draw the screen without a click), `tab open`, `on open` (drawer, dialog,
  fold), `hover`, `scroll`, `typing` (search box or picker), `action` (part of a write flow).
- **Freshness** (RFC-157 section 3.9): `static`, `reference`, `working`, `live`, `snapshot`.
- **State**: `shipped` (fits as is), `shipped, change planned` (the route exists; the screen needs a change to
  it), `planned (new)` (the route does not exist yet), `bootstrap`, `view` (a part of the screen's view),
  `reference catalog (planned)`, `no data`.
- Block descriptions use the sample figures the screen was designed with; they show what a block holds, not real
  numbers.
- "(to confirm)" marks a detail to check against the handler when the screen is built.

## Rules every screen follows

1. First view: at most two shell reads on a hard load (bootstrap, reference catalog) and three page reads; moving
   between screens, at most three page reads. A detail page that needs more gets a view.
2. Tabs, drawers, dialogs and folds load on open. Tab counts come from count fields on the object.
3. Figures, strips, sparklines and scores come from precomputed facts with `as_of`.
4. Badges come from the bootstrap and change by WebSocket events. Pages do not poll.
5. People are never preloaded: rows carry `{id, name}`; pickers search.
6. Secrets and personal data arrive masked; showing one is a separate, audited request (step-up for secrets).
7. Every block is read inside the caller's tenant and data scope with its endpoint's own permission and module
   gate, so a block the caller may not read is absent and the rest of the screen still renders.

## Requests at first view: before and after

Before = the request budget enforced by the end-to-end gate today. After = the target once the screen and its
endpoints have moved (hard load; in brackets, moving between screens inside the console).

| Screen | Before | After | How |
|---|---|---|---|
| Finding detail | 4 | 3 (1) | the view holds the first view only; tabs load on open |
| Asset detail | 12 | 3 (1) | the asset view finished the same way |
| Assets | 9 | 5 (3) | lean list, facets, one figure strip from facts |
| Assets needing attention | 9 | 4 (2) | one summary from facts plus the open queue |
| Findings | 4 | 5 (3) | lean list with status counts, facets, quick views |
| Home | 2 | 3 (1) | dashboard home: layout and widget results in one response |
| Inbox | 6 | 4 (2) | Inbox summary plus the open queue |
| Scan run | 5, polled every 10 to 30 s | 4 (2), no polling | run view plus targets list; progress over the WebSocket |
| Sensors | 8 | 4 (2), no polling | fleet with stats in one read; liveness events |
| Members | 8 | 4 (2) | stats ride on the list; invitations and join requests on their tab |

Planned pages that do not exist today start inside the budget.

## Core screens: home, findings, finding detail, assets, scan run, attack paths, SLA, palette, dashboards

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Home (/) | Shell: org switcher (6 orgs, role, expiry), sidebar badges (Inbox 12, KEV exposed 7, Team SLA 72 h 3), pinned views with counts, notification bell count (5), user menu | `GET /api/v1/me/bootstrap` | first view | working | any signed-in | bootstrap |
|  | Dashboard switcher (Mine: Overview default, My assets; Organization: CTEM program, Executive, Surface, Vulnerability program, Triage, Code, Validation) | `GET /api/v1/me/dashboards/home?choice=` | first view | snapshot | `dashboard:read`; org list needs `dashboards:org:view` | shipped |
|  | Five KPI tiles: Actionable 27, Known exploited 7, Within SLA 87%, Median time to fix 11 d, Discovery coverage 92% (value, delta text, tone, drill href) | same `/home` response, `data` (widgets `exposure.priority_open`, `intel.kev_open`, `sla.within`, time-to-fix, `coverage.discovery`) | first view | snapshot | `findings:read`, `assets:read` per metric | shipped |
|  | "Updated 46 min ago, Next in 14 min", Refresh now | `computed_at`, `next_refresh_at`, `stale` in the same response; `POST /api/v1/me/dashboards/{id}/refresh` | first view / action | snapshot | `dashboard:read`, owner | shipped |
|  | Setup, 6 of 7 done (steps: sensor, scope, prove domain, first scan, import, SLA policy, invite teams) | none | first view | reference | admins | planned (new) |
|  | CTEM stages strip (5 stages: figure text, state On track / Needs attention / Not started, href) | `/home` `data` (story widget "CTEM loop", docs "Story widgets") | first view | snapshot | mixed (scoping, assets, findings) | shipped |
|  | Fix next / "What would cut exposure most" (4 levers: title, effect line, href, owner; Create task + Undo) | `/home` `data` (widgets `fix_next`, levers) | first view | snapshot | `findings:read` | shipped |
|  | New and resolved, last 12 weeks (12 buckets new/resolved, totals 214/251) | `/home` `data` (`flow.new_vs_fixed`) | first view | snapshot | `findings:read` | shipped |
|  | SLA due ahead (8 weeks, overdue + P0/P1/P2 stack) | `/home` `data` (SLA due-ahead widget) | first view | snapshot | `findings:read` | shipped |
|  | Coverage in the last 7 days (asset type x check: Ports, Web, Vulnerabilities, TLS, DNS; "does not apply", "never", "no sensor") | `/home` `data` (`coverage.discovery` matrix) | first view | snapshot | `assets:read` | shipped |
|  | Notifications popover (6 latest, Mark all as read) | `GET /api/v1/notifications?per_page=6` | on open | working | self | shipped |
| Findings workbench (/findings) | Rows (see column list below), saved view applied | `GET /api/v1/findings?view=&page=&per_page=&sort=&include=practice_counts` | first view | working | `findings:read`, data scope | shipped, change planned |
|  | Quick views with counts (Actionable 27, Active 418, Needs triage 64, My queue 5, Exploited 7, SLA breached 3, Pending approval 3, Expiring 1, Closed, To verify 4, Run 148 12) | `GET /api/v1/findings/quick-views` | first view | snapshot | `findings:read` | shipped |
|  | Facets behind the filter icon (Assigned to me, Severity, Hide informational, Priority, Threat signals, Status, SLA, Branch, Source: value + count) | `GET /api/v1/findings/facets?<same filters>` | first view / parallel) | snapshot | `findings:read` | planned (new) |
|  | Filter keys help for "Add filter" (groups Exploitation, Asset, Work, Finding ...; asset_type values) | `GET /api/v1/meta/filters/findings` | on open | static | `findings:read` | shipped |
|  | Saved views list (My views, Shared with my groups; pin/delete) | `GET /api/v1/views?type=findings` | on open | reference | `findings:read` | shipped |
|  | Group by (CVE, Rule, Asset, Owner, Severity, Source, Component) with group header (count, fix text) and 14-host expansion | `GET /api/v1/findings/groups?by=` | on open | working | `findings:read` | shipped, change planned |
|  | Drawer (see Drawer below) | `GET /api/v1/findings/{id}` + `GET /api/v1/findings/{id}/priority-explanation` + `GET /api/v1/findings/{id}/activities?per_page=3` | on open | working | `findings:read` | shipped, change planned |
|  | Row status menu ("Allowed from Confirmed, key s") | `GET /api/v1/findings/{id}/transitions` | on open | working | `findings:read` | shipped |
|  | Row owner picker (search members, Assign me, teams) | `GET /api/v1/findings/{id}/assignable` | typing | reference | `findings:write` | shipped |
|  | Approvals count, Fixes awaiting verification 9 | bootstrap badges | first view | live |  | bootstrap |
|  | "Verify" view (fix-applied groups: id, title, state, Verify / Reject) | `GET /api/v1/findings/remediation-groups` and `GET /api/v1/findings/closure/proposals` | tab open | working | `findings:verify` | shipped |
|  | Export | `POST /api/v1/findings/export` (up to 50,000) | action |  | `findings:read` | shipped |
| Finding detail (/findings/{id}) | Header: kind chip, id, CWE, position in list ("2 of 27"), title, status, priority, due; property rail (status with moves, severity with ranges, priority, SLA due + "why this date", assignee, watchers, asset owners, asset, found by, first/last seen, seen in N scans, tickets, tags, id) | `GET /api/v1/findings/{id}/view` (finding + parts) | first view | working | `findings:read`, data scope | view |
|  | Why it matters (exploitation, exposure, business impact, "how this was scored": sub-scores impact/likelihood/exposure, factors, model version) | `GET /api/v1/findings/{id}/priority-explanation` | first view | working | `findings:read` | shipped, change planned |
|  | Waiting on approval banner, approval history | part `/approvals` | first view | working | `findings:read` | view |
|  | Fix: remediation plan, commands, scanner output (fold, 64 KiB cut) | the finding itself (`remediation`, `scanner_output`) | first view / on open | working | `findings:read` | shipped |
|  | Proof of fix (tier, methods: retest, covered scan, checklist; retest check, earlier attempts) | parts `/verification`, `/retest-check`, `/retests` | first view | working | `findings:read` | view |
|  | Task strip ("Tracked in task ... due 14 Nov") | part `remediation/tasks?finding_id=` | first view | working | `remediation:read` | view |
|  | Tickets / holds | parts `/ticket-links`, `/ticket-holds` | first view | working |  | view |
|  | Watchers | part `/participants` | first view | working |  | view |
|  | AI analysis (suggestion, false-positive likelihood, fields) | parts `/ai-triage`, `/findings/ai-triage/config` (config also in bootstrap `ai_config`) | tab open / Details) | working | `ai_triage:read` | view |
|  | Evidence tab: tool evidence (HTTP exchange, raw output; baseline / fix proof / supporting; masked values), compliance controls, notes | `GET /findings/{id}/evidence-items`, `GET /findings/{id}/evidence`, `GET /api/v1/compliance/findings/{findingId}/controls` | tab open | working | `findings:read` | shipped |
|  | Remediation tab: fix available, auto-fixable, effort, complexity, type, estimated time; recommendation; definition of done; steps; references | the finding (`remediation`) + `PATCH /findings/{id}/remediation`, `POST /findings/{id}/remediation/steps` | tab open / no extra read) | working | `findings:write` to edit | shipped |
|  | Related tab: similar findings (AI suggested, match %), same CVE, linked findings, tracking info (occurrences, duplicates, correlation id) | `GET /findings/{id}/duplicate-candidates`, `GET /findings/related-cves/{cveId}`, part `/issue-links` | tab open | working | `findings:read` | shipped |
|  | Details tab: description, scores by source, source record, context, identifiers and scores, why this is one finding, more details, discovery chain, reported by N sources (disagreement table), seen by, import history | parts `/identity`, `/source-records`, `/imports`, `/ai-triage`; `GET /findings/{id}/sightings`; `GET /findings/{id}/detections`; `GET /findings/{id}/story` (discovery chain, inferred) | tab open | working | `findings:read` | view |
|  | Activity tab (all / comments / changes; 11 events), comment composer | parts `/activities?page=1&per_page=20`, `/comments` | tab open | working | `findings:read` | view |
|  | Validation tab: current standing (Exploitable, Blocked by control, Waiting for approval, Expired, Not validated) + history (when/by, method, outcome, control, scope, valid until) | `GET /api/v1/findings/{id}/validation-results` | tab open | working | `findings:read` | planned (new) |
|  | Moves allowed, with gates (needs note / approval / second approver) | `GET /api/v1/findings/{id}/transitions` | on open | working | `findings:read` | shipped |
|  | Approval policy for the Accept risk dialog (Security review, 1 approval, pool, eligible 2) | `GET /api/v1/findings/{id}/approvals/policy` | on open | reference | `findings:read` | shipped |
|  | Mark-duplicate original picker (50 findings on the asset) | `GET /api/v1/assets/{id}/findings?q=` | typing | working | `findings:read` | shipped |
|  |  | finding payload `location` + `GET /findings/{id}/dataflows` (TAB) + `GET /attachments?finding_id=` |  |  |  | planned (new) |
|  |  | finding `check` object; `GET /findings/compliance/benchmarks/{key}/assets` for the hosts; `GET /findings/{id}/compliance-history`; `GET /compliance/findings/{findingId}/controls` |  |  |  | view |
|  |  | finding `component` + `GET /assets/{id}/dependency-paths` |  |  |  | planned (new) |
|  |  | finding `certificate`; `POST /api/v1/exposures/{id}/resolve`; `GET /exposures/stats` |  |  |  | shipped, change planned |
|  |  | finding `resource`; retest `POST /findings/{id}/retests` |  |  |  | shipped |
|  |  | `GET /pentest/findings/{findingId}`, `PUT /pentest/findings/{findingId}`, `PATCH .../status`, `POST /pentest/findings/{id}/request-retest`, `PUT /findings/{id}/bounty-report`, `GET /attachments/{id}/signed-url` |  |  |  | shipped |
|  |  | finding `secret` (always masked; full value never stored so there is no Show) |  |  |  | shipped, change planned |
|  |  | `GET /findings/{id}/evidence-items`, reveal `POST .../reveal`; `GET /assets/{id}/web-evidence/{evidence_id}/screenshot` |  |  |  | shipped |
|  |  | NEW `GET/POST /findings/{id}/validation-results` + preview `POST /findings/{id}/validation-results/preview` |  |  |  | planned (new) |
| Assets list (/assets) | Rows: asset name + short id + sub-line, type + exposure, Risk (score 0-100), open findings count, coverage dots (ports, web, vulnerabilities, TLS ran / did not in 7 d), owner, last seen; hidden columns: findings 12 weeks sparkline, criticality, scope, monitoring, business service, tags and labels, type attributes | `GET /api/v1/assets?page=&per_page=&sort=&view=` | first view | working | `assets:read`, data scope | shipped, change planned |
|  | Type pills with counts (Domain, Host, Web service, Repository, Cloud account ... 17 types, "More") | `GET /api/v1/assets/facets` | first view | snapshot | `assets:read` | shipped |
|  | Header strip: "14 unconfirmed" (needs attention), Needs attention, Groups, Suggestions counts | `GET /api/v1/assets/stats` | first view | snapshot | `assets:read` | shipped |
|  | Filter menu (signals: crown jewels, has findings, scanned in 30 d, stale, not resolving, risk >=, bug bounty, discovered by; fields; system tags) | `GET /api/v1/assets/tags`, `GET /api/v1/assets/technologies` | on open | reference | `assets:read` | shipped |
|  | Saved views and quick views (All, Crown jewels, Internet-facing, No owner, Not scanned 30 d) | `GET /api/v1/views?type=assets` | on open | reference |  | shipped |
|  | Quick view panel (side drawer: type, identity, exposure, criticality, risk score, owner, last seen, scope, top finding row, relationships left/right, "Seen by run 148", owner-set history, first discovered) | `GET /api/v1/assets/{id}` + `GET /api/v1/assets/{id}/findings?per_page=1&sort=-priority` + `GET /api/v1/assets/{id}/neighborhood` | on open | working | `assets:read` | shipped |
|  | Coverage tooltip | `GET /api/v1/assets/{id}/coverage` | hover | working |  | shipped |
| Scan run, live (/scans/runs/{id}) | Header: chip (Partial / Running / Canceled), run id (copy), start line ("Started 02:00 on schedule, sensor edge-sg-1"), deadline text, sentence, KPI cells (new findings 12, new since last run 31, no longer seen 70, all results 124) | `GET /api/v1/scan-runs/{id}` | first view | live | `scans:read` | shipped |
|  | Steps timeline / run map (5 steps: state, took, targets, outputs, flow between steps; "Each bar is a chunk sent to a sensor") | `GET /api/v1/scan-runs/{id}/stages` | first view | live | `scans:read` | shipped |
|  | Task table (38 tasks: status, tool + note, sensor, targets, duration, logs; "Showing N of 38, load more") | `GET /api/v1/scan-runs/{id}/tasks?page=` | first view | live | `scans:read` | shipped |
|  | Task log drawer ("kept 14 days", live lines every few seconds) | `GET /api/v1/scan-runs/{id}/tasks/{task_id}/logs` | on open | live | `scans:read` | shipped |
|  | Scan zones, "Sent with" (user agent, headers, rotating values, ignored settings) | run payload (`zones`, `identification`) | first view | working | `scans:read` | shipped, change planned |
|  | Placement ("why this sensor") | `GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement` | hover | working |  | shipped |
|  | Links: New findings -> `seen_in_run_id`; results -> Assets | list reads of those screens |  |  |  | shipped |
| Attack paths (/attack-paths) | Target picker (Crown jewels, Payments DB, Customer portal DB, Other, Build server) | `GET /api/v1/assets?crown_jewel=true` (lean rows; no `fields=`) | first view | reference | `assets:read` | shipped |
|  | Graph + paths list ("6 of 186", path id, steps, hops, KEV count, likelihood, cut by fixing, withheld path) | `GET /api/v1/attack-surface/attack-paths/{id}` (paths to an asset) and `GET /api/v1/attack-surface/attack-paths` | first view | snapshot | `assets:read` | shipped |
|  | Fix here first (choke points: asset / account, effect "Cuts 4 of 6", action text, owner, findings on it) | same response (`choke_points`) | first view | snapshot | `assets:read` | shipped, change planned |
|  | Node details on select (finding id, severity, KEV) | `GET /api/v1/assets/{id}/findings?per_page=3` | on open | working | `findings:read` | shipped |
|  | Exposure chains | `GET /api/v1/attack-surface/exposure-chains` | tab open | snapshot |  | shipped |
| Remediation and SLA (/sla) | Five tiles: Within SLA 87%, Overdue 3, Due this week 9, Breach rate 6.2% (was 9.8%, target < 5%), Median time to fix 11 d; "Due in the next 8 weeks" (overdue + P0/P1/P2 per week), "Breach rate, last 12 weeks", "Open findings by age" | `GET /api/v1/sla/overview` | first view | snapshot | `findings:read` | planned (new) |
|  | Table "Overdue and due this week, 12" (priority, finding id + title + asset, severity, owner, due, blocked by, action; tabs This week / Escalated; By team grouping; Detected column hidden) | `GET /api/v1/findings?sla_status=overdue,due_7d&sort=due` | first view | working | `findings:read` | shipped |
|  | Export these 12 | `POST /api/v1/findings/export` | action |  |  | shipped |
| Settings home and a settings page (/settings) | Rail and "All settings" index (groups: My account, Organization, Access and security, Findings and assets, Scanning, Tools, Integrations ...), "Search settings" (also finds settings inside pages) | none | first view | static | bootstrap permissions + modules gate which entries show | client catalog |
|  | Finding lifecycle page: Close only after a clean rescan, Reopen when seen again, False positive approval (second member / security lead / nobody), Risk acceptance needs approval, Longest acceptance (90 d / 180 d / 1 year), advanced links | `GET /api/v1/organization/settings/finding-approvals` and `GET /api/v1/organization/settings/closure` | first view | reference | `settings:read` | shipped |
|  | Save | `PATCH /api/v1/organization/settings/finding-approvals`, `PUT /api/v1/organization/settings/closure` | action |  | `settings:write` | shipped |
| Command palette | Results for "openssh": Vulnerability (CVE, affected hosts, EPSS), Findings 14 (id, asset, P0, status, due, owner), Assets (name, type, address), Commands, Remediation tasks, pages | `GET /api/v1/search?q=&types=&limit=` | typing | working | per type: `vulnerabilities:read`, `findings:read`, `assets:read`, `scans:read`, `remediation:read` | planned (new) |
|  | Recent items | none | on open |  |  | client (localstorage) |
|  | Row actions (Assign me, Set status, Task) | same endpoints as the Findings workbench | action |  |  | shipped |
|  | Empty-result fallback ("Search finding text for ...") | `GET /api/v1/findings?q=` | action |  |  | shipped |
| Dashboards | Layout (widget list with position and size 1x1..4x3, template, title) | `GET /api/v1/me/dashboards/{id}` (personal) or `GET /api/v1/organization/dashboards/{id}` | first view | reference | `dashboard:read`; org: `dashboards:org:view` | shipped |
|  | Widget results (one per widget: state ready / not_measured / building / unsupported / error, shape payload, polarity, target met, `drill`, `previous`) | `GET /api/v1/me/dashboards/{id}/data`, `GET /api/v1/organization/dashboards/{id}/data` | first view | snapshot | per-metric permission | shipped |
|  | Range control (7 days, 30 days, 90 days, 12 months; "Compared with the previous period") | `?range=7d/30d/90d/12m` on `/data` and `/home` | action | snapshot |  | shipped, change planned |
|  | Refresh now | `POST /api/v1/me/dashboards/{id}/refresh`, `POST /api/v1/organization/dashboards/{id}/refresh` | action |  |  | shipped |
|  | "Your scope: every asset you can see" | `scope` in `/data` (to confirm) | first view | snapshot |  | shipped, change planned |
|  | Widget catalog (27 widgets, 8 groups: CTEM, Exposure, Attack surface, Remediation, Threat intel, Validation, Code) | `GET /api/v1/me/dashboards/widget-catalog` | on open / editor / gallery) | static | any member | shipped |
|  | Widget preview with my data (editor) | `POST /api/v1/me/dashboards/widget-preview` | typing / action | working | `dashboard:read` | shipped |
|  | Dashboard list ("Manage dashboards", set default, duplicate, delete) | `GET /api/v1/me/dashboards`, `GET /api/v1/organization/dashboards` | on open | reference |  | shipped |
|  | More actions: share link, download PDF, email every Monday | `POST /me/dashboards/{id}/share`, `PUT /me/dashboards/{id}/schedule`; PDF: NEW `GET /api/v1/me/dashboards/{id}/export?format=pdf` | action |  |  | planned (new) |


### Finding detail: blocks per finding kind

| Kind | Extra blocks and fields | Endpoint or source | State |
|---|---|---|---|
| Code | Code location (file, line range, branch, commit, 18 lines of source with the finding range marked), Affected code, Stack traces (frames: file:line:col, layer), Related locations (file:line, note, snippet), Attachments, Data flow (4 steps; counts by role Sources / Propagation / Sanitizers / Sinks; path steps), Branches table (branch, default, state Present / Not seen, first commit + author + date, last commit, CI run), Same issue in other tools (finding, tool and rule, where, state, "why linked"), Auto-fix code, regex fix pattern, "Branch only" chip, Scan main now | Overview (code location), Evidence tab (affected code, stack, related), Details/Related (branches, other tools) | finding payload `location` + `get /findings/{id}/dataflows` (tab) + `get /attachments?finding_id=` |
| Compliance | Configuration check (host, address, benchmark, profile, control, audit file, expected value, actual value, result Passed / Failed / Error), "Why the check did not run" (error text, check credential link), "Not scanned in 30 days" (sensor silent), Mapped controls (5 frameworks), Hosts in this group (14 hosts: name, result, last checked), shell commands, Run again (one host / all 11) | Overview (check), Evidence (controls) | finding `check` object; `get /findings/compliance/benchmarks/{key}/assets` for the hosts; `get /findings/{id}/compliance-history`; `get /compliance/findings/{findingid}/controls` |
| Component | Affected package (name@version, fixed in, other fixed lines, ecosystem, dependency direct / transitive via file:line, image, lock-file line, dependency tree), Why this finding (what the scan reported), VEX statement (status, by, statement, date), Same CVE list (2), Accept risk with a control | Overview, Details | finding `component` + `get /assets/{id}/dependency-paths` |
| Exposure | Certificate (subject, SAN, issuer, not before/after, serial, key, signature, fingerprint, expired x days ago), Chain (leaf, intermediate, root; OCSP stapling), "How a renewal closes it", asset liveness, Move to exposures (closes finding), watched certificates count, "3 more expire within 30 days" | Overview | finding `certificate`; `post /api/v1/exposures/{id}/resolve`; `get /exposures/stats` |
| Misconfig | Misconfigured resource (live cloud resource vs IaC; resource id, policy id + title, cloud account/region and connector, file + lines, cause, expected value, Terraform snippet), Code location (IaC), scanner output, Re-read the bucket settings now | Overview | finding `resource`; retest `post /findings/{id}/retests` |
| Pentest | Targets (asset refs + path), Uploaded evidence (5 files, flagged file download confirm), report block (OWASP class, Steps to reproduce 5, Business impact, Technical impact, Proof of concept, HTTP request/response, Affected targets, Remediation guidance, References 2, Evidence 3), Bounty report (11 fields: report state, reported severity, reward status, disclosure), "Not published", "Retest pending", Request a retest from the tester (tester, ask only when live), CVSS vector | Overview + Evidence + Details | `get /pentest/findings/{findingid}`, `put /pentest/findings/{findingid}`, `patch .../status`, `post /pentest/findings/{id}/request-retest`, `put /findings/{id}/bounty-report`, `get /attachments/{id}/signed-url` |
| Secret | Exposed credential (type, service, validity Active/Revoked + checked at, masked value first 4 + last 4, age, in history N commits + still in files, expires, rotation due, scopes, HMAC fingerprint, entropy), Rotation proof checklist (revoked and replaced, evidence attached, use since exposure checked), Re-check validity, Code location, Same issue in other tools | Overview | finding `secret` (always masked; full value never stored so there is no show) |
| Web | Affected endpoint (method, URL, parameter, also on), Tool evidence 3 (proof next to baseline, HTTP exchange, screenshot, authenticator code to reveal), server-rule snippet, Same issue in other tools (linked F-20419) | Overview + Evidence | `get /findings/{id}/evidence-items`, reveal `post .../reveal`; `get /assets/{id}/web-evidence/{evidence_id}/screenshot` |
| Validation | Tab with current standing and history; Record dialog (method, control, tested by, valid until, files, "What changes" preview of priority and deadline) | Validation tab | planned (new) |

## Inbox, triage, scoping and discovery

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Inbox (/inbox) | Assigned |  |  |  |  | no data |
|  | My team |  |  |  |  | no data |
|  | Approvals |  |  |  |  | no data |
|  | Expiring |  |  |  |  | no data |
|  | My tasks |  |  |  |  | no data |
|  | To close |  |  |  |  | no data |
|  | Queue counts (tab badges, "Inbox 12") | `GET /api/v1/me/inbox/summary` | first view | live | any member; counts are caller-scoped | shipped |
|  | Assigned / My team rows | `GET /api/v1/me/inbox/items?queue=assigned\/team` | first view / tab open | working | findings:read, data scope | planned (new) |
|  | Approvals rows | `GET /api/v1/approvals` | tab open | working | approvals read | shipped, change planned |
|  | Expiring rows | `GET /api/v1/suppressions?ends_within=30d&mine=true` | tab open | working | suppressions read | shipped, change planned |
|  | My tasks rows | `GET /api/v1/remediation/tasks?assignee=me` | tab open | working | remediation read | shipped, change planned |
|  | To close rows | `GET /api/v1/findings/closure/proposals` | tab open | working | findings:write on closure | shipped |
|  | Auto-closed lens | `GET /api/v1/findings/closure/auto-closed` | on open | working | findings:read | shipped |
|  | Reading pane facts | rows already carry them; justification text | on open | working | as the row | shipped |
| Triage mode (/triage) | Selected view chips (Needs triage, My queue, Exploited, SLA breached) | `GET /api/v1/views` | first view | reference | findings:read | shipped |
|  | Queue (ordered rows, "and 19 more") | `GET /api/v1/findings/triage-queue?view=` | first view | working | findings:read, data scope | planned (new) |
|  | Current finding card (asset, owner, due, EPSS, exploitation, found by, seen, evidence) | `GET /api/v1/findings/{id}/view` | first view | working | findings:read | shipped |
|  | AI suggestion | `GET /api/v1/findings/{id}/ai-triage` | first view | working | findings:read + AI module | shipped |
|  | Concurrent change banner | WebSocket `triage:{finding_id}` and `finding:{id}` | first view | live | as finding | shipped |
|  | Decided-in-its-own-workflow lock | `GET /api/v1/findings/{id}/approvals` | first view | working | findings:read | shipped |
| Home first run (/) | Dashboard selector + widgets | `GET /api/v1/me/dashboards/home` then `GET /api/v1/me/dashboards/{id}/data` | first view | snapshot | member | shipped |
|  | Setup checklist (SLA policy set, pair a sensor, add scope, prove domain, first scan, invite owners; "n of 6") | `GET /api/v1/organization/setup-progress` | first view | reference | owner or admin | planned (new) |
|  | Pair a sensor code ("works for 1 hour") | `POST /api/v1/sensor-pairings/enrollment-tokens` | on open | working | sensors:write | shipped |
|  | Add scope inline | `POST /api/v1/scope/targets` | action | n/a | scope:write | shipped |
|  | Prove domain | `POST /api/v1/easm/verified-domains` and `.../{id}/verify` | action | n/a | scope:write | shipped |
|  | Scoping readiness "0 of 9" | `GET /api/v1/scoping/summary` | first view | snapshot | scoping read | shipped |
| Scoping overview (/scoping) | Active cycle card (name, dates, day n of m, assets in scope of total, charter counts) + readiness list "7 of 12 ready", People and data access, "Feeds Discovery" line | `GET /api/v1/scoping/summary` | first view | snapshot | scoping read | shipped, change planned |
| Cycles (/cycles) | Timeline + table (name, dates, assets in scope, outcome "1 of 4 on track") | `GET /api/v1/ctem-cycles` | first view | working | ctem cycles read | shipped, change planned |
|  | Cycle policy toggle (validation coverage SLO to close) | `GET /api/v1/organization/settings/cycles` | first view | reference | owner/admin | shipped |
|  | Operating rhythm and lessons from last closed cycle | rides on list: `lessons` field of the latest closed cycle | first view | working | read | shipped, change planned |
|  | Compare outcomes (3 selected) | `GET /api/v1/ctem-cycles/{id}/metrics` x3 or `GET /api/v1/ctem-cycles/metrics/trend` | on open | snapshot | read | shipped |
| Cycle detail and report (/cycles/[id]) | Header, stepper (Planning, Active, Review, Closed), charter (objectives, priorities, services, risk appetite, escalation, roles, exclusions) | `GET /api/v1/ctem-cycles/{id}` | first view | working | read | shipped |
|  | Success criteria outcome table (metric, target, now, outcome) and KPI tiles | `GET /api/v1/ctem-cycles/{id}/metrics` | first view | snapshot | read | shipped |
|  | Assets in scope, exclusions | `GET /api/v1/ctem-cycles/{id}/scope` | first view | working | read | shipped |
|  | Attacker profiles | `GET /api/v1/ctem-cycles/{id}/profiles` | tab open | working | read | shipped |
|  | Cycle report (audience Sponsor, Leadership, Program team; period; sections) | `GET /api/v1/ctem-cycles/{id}/report?audience=&period=` | on open | snapshot | read | planned (new) |
| Business context (/scoping/business-context) | Figure strip (12 crown jewels, 4 internet-exposed, 2 without owner, 3 without threat model; services 5, units 7) | `GET /api/v1/business-context/summary` | first view | snapshot | assets read | planned (new) |
|  | Crown jewel table (asset, risk, business impact of 100, exposure, open findings with critical count, owner) | `GET /api/v1/assets?crown_jewel=true` | first view | working | assets:read | shipped, change planned |
|  | Services tab | `GET /api/v1/business-services` | tab open | working | read | shipped |
|  | Units tab | `GET /api/v1/business-units` | tab open | working | read | shipped |
| Scope (/scope) | Figure strip (In scope 1,204, Excluded 38, Pending proof 3, Found but unknown 57) | `GET /api/v1/scope/stats` | first view | snapshot | scope read | shipped |
|  | Domain proof tab | `GET /api/v1/easm/verified-domains` | first view | working | read | shipped |
|  | Networks tab | `GET /api/v1/easm/network-seeds` | tab open | working | read | shipped |
|  | Programs tab | `GET /api/v1/programs` | tab open | working | read | shipped |
|  | Letters tab | `GET /api/v1/scope/letters` | tab open | working | read | shipped |
|  | Targets (entries) and Exclusions | `GET /api/v1/scope/targets`, `GET /api/v1/scope/exclusions` | tab open | working | read | shipped |
|  | Check target (per-target allowed or refused with reason) | `POST /api/v1/scope/check` | action | n/a | read | shipped |
|  | Intrusive entries to confirm | `GET /api/v1/scope/targets?intrusive_pending=true` | first view | working | read | shipped, change planned |
| Threat model (/scoping/threat-model) | Crown jewel picker "3 without a model" | `GET /api/v1/threat-models` | first view | working | read | shipped |
|  | Model (technique coverage, threats, status Open/Mitigated/Compensated/Theoretical) | `GET /api/v1/threat-models/{id}` | first view | working | read | shipped |
|  | Coverage figure (61%, 11 of 18) | `GET /api/v1/threat-models/{id}/coverage` | first view | snapshot | read | shipped |
|  | Attacker profiles | `GET /api/v1/attacker-profiles` | on open | reference | read | shipped |
| Programs (/programs/[id]) | Program header, targets, exclusions, rules, terms | `GET /api/v1/programs/{id}` | first view | working | read | shipped |
|  | Suggested targets | `GET /api/v1/programs/{id}/pending` | first view | working | read | shipped |
|  | Notifications (channels) | `GET /api/v1/programs/{id}/delivery` | tab open | working | read | shipped |
|  | Import wizard (follow public program, file) | `GET /api/v1/programs/catalog`, `POST /api/v1/programs/preview`, `POST /api/v1/programs` | on open | working | scope:write | shipped |
| Scans (/scans) | Tabs counts (Scans 24, Runs 1,268, Workflows 9, CI/CD 14, Approvals 1) | `GET /api/v1/scans/overview-stats` | first view | snapshot | scans read | shipped |
|  | Scan list | `GET /api/v1/scans` | first view | working | scans read | shipped |
|  | Scan window freeze banner | `GET /api/v1/scan-window-overrides` | first view | reference | read | shipped |
|  | Quick scan | `POST /api/v1/scans/quick/preview`, `POST /api/v1/scans/quick` | action | n/a | scans write | shipped |
|  | Facets | `GET /api/v1/scans/facets` | first view | snapshot | read | planned (new) |
| Scan detail (/scans/[id]) | Header, owner state ("no active owner"), missed runs, schedule | `GET /api/v1/scans/{id}` | first view | working | read | shipped |
|  | Runs table | `GET /api/v1/scans/{id}/runs` | first view | working | read | shipped |
|  | Run drawer (tasks, results "124: 31 new, 70 no longer seen", scope snapshot) | `GET /api/v1/scan-runs/{id}`, `/tasks`, `/scope-snapshot` | on open | live | read | shipped |
|  | Approval state | `GET /api/v1/scans/{id}/approval` | first view | working | read | shipped |
| Scan approvals | (see screen description) | `GET /api/v1/scan-approvals` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/scan-approvals/{id}/approve/reject` | action |  |  | shipped |
| Workflows and CI trust (/scans/workflows, /scans/workflows/[id]) | (see screen description) | `GET /api/v1/scan-workflows` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/ci/trust-configs` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/ci/trust-refusals` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/ci/runs` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/scan-workflows/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/workflows/catalog` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/tools` | first view or on open |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/scan-workflows/{id}/draft` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/scan-workflows/verify` | action |  |  | shipped |
| Sensors (/sensors, /sensors/[id]) | Fleet figures + 24 h availability strip | `GET /api/v1/sensors/stats` | first view | snapshot | sensors read | shipped, change planned |
|  | Sensor list with per-sensor 24 h strip, needs-attention reasons | `GET /api/v1/sensors` | first view | live | read | shipped, change planned |
|  | First-run block (guided install, API key) | `POST /api/v1/sensor-pairings/enrollment-tokens` | on open | working | write | shipped |
|  | Detail: header, keys | `GET /api/v1/sensors/{id}`, `/keys` | first view | live | read | shipped |
|  | Detail: heartbeat, activity, readiness, config report | `/heartbeat-history`, `/activity`, `/readiness`, `/config-report` | tab open | working | read | shipped |
| Attack surface (/attack-surface) | Figures (internet-facing 412, 38 newly exposed in 7 days, open exposures, waiting decisions) | `GET /api/v1/attack-surface/stats` | first view | snapshot | assets read | shipped |
|  | Easm summary banner and review count | `GET /api/v1/easm/summary` | first view | snapshot | read | shipped |
|  | Fix first list | `GET /api/v1/attack-surface/exposures` | first view | working | read | shipped |
|  | Posture B 78 of 100, "Computed 10 Nov 04:00" | `GET /api/v1/attack-surface/posture` | tab open | snapshot | read | shipped |
|  | Changes tab (appeared, gone, exposure changes, shadow IT) | `GET /api/v1/state-history/counts` and `/appearances`, `/disappearances`, `/exposure-changes`, `/newly-exposed`, `/shadow-it` | tab open | working | read | shipped |
|  | Lookalikes, Page changes | `GET /api/v1/easm/lookalikes/watches`, `GET /api/v1/easm/page-monitoring/changes` | tab open | working | read | shipped |
|  | Discovery tab | `GET /api/v1/attack-surface/discovery` | tab open | live | read | shipped |
|  | Technologies, Certificates | `GET /api/v1/attack-surface/technologies`, `/certificates` | tab open | working | read | shipped |
|  | Endpoints (web) | `GET /api/v1/web-endpoints` | tab open | working | read | shipped |
|  | Review (found but unknown) | `GET /api/v1/easm/candidates`, `GET /api/v1/easm/suggestions` | tab open | working | read | shipped |
| Assets: needs attention, categories, groups (/assets/attention, /assets/categories, /assets/groups) | Needs attention counts (Validate primary 3, Decide scope, No owner, Criticality not set, Not scanned in 30 days, Relationships, Possible duplicates; "225 to clear, 18 cleared this week") | `GET /api/v1/assets/attention` | first view | snapshot | assets read, caller scope | planned (new) |
|  | Queue rows | `GET /api/v1/assets?attention=<queue>` | first view | working | assets read | shipped, change planned |
|  | Relationship suggestions | `GET /api/v1/relationships/suggestions`, `/count` | tab open | working | read | shipped |
|  | Possible duplicates | `GET /api/v1/assets/dedup/reviews` | tab open | working | read | shipped |
|  | Categories table (assets, types, worst open, internet-facing, crown jewels, new this week, unowned) | `GET /api/v1/assets/categories` | first view | snapshot | read | planned (new) |
|  | Groups list and strip (unowned 2, critical 3, in no group 248, open findings 391) | `GET /api/v1/asset-groups` and `GET /api/v1/asset-groups/stats` | first view | work/snap | read | shipped |
| Asset detail and forms (/assets/[id]) | Header, summary (open findings, risk, attack-path count, coverage 7 d) | `GET /api/v1/assets/{id}/view` | first view | working | assets read, data scope | shipped, change planned |
|  | Findings tab | `GET /api/v1/assets/{id}/findings` | tab open | working | findings read | shipped |
|  | Relationships tab | `GET /api/v1/assets/{id}/relationships` | tab open | working | read | shipped |
|  | Ports, technologies, web, services | `GET /api/v1/assets/{id}/resolved-ports`, `/technologies`, `/web-endpoints`, `/services` | tab open | working | read | shipped |
|  | Owners and access | `GET /api/v1/assets/{id}/owners`, `/access-grants` | tab open | reference | assets:manage | shipped |
|  | Activity | `GET /api/v1/assets/{id}/changes`, `/state-history` | tab open | working | read | shipped |
| Asset relationships and map | (see screen description) | `GET /api/v1/assets/{id}/neighborhood?hops=&direction=` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/assets/{id}/relationships` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/assets/{id}/relationships/groups` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/assets/{id}/relationships` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/relationships/suggestions` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/assets/map?level=0` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/assets/map/clusters/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/attack-surface/attack-paths` | first view or on open |  |  | shipped |
| Components (/assets/components, /components/[id]) | (see screen description) | `GET /api/v1/components/summary` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/components` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/components/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/components/import` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/vex-statements/import` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/components/sbom` | first view or on open |  |  | shipped |
| Repository detail (/assets/[id]) | (see screen description) | `GET /api/v1/assets/{id}/repository` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/repositories/{repositoryId}/branches` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/ci/code-scanning/repositories/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/assets/{id}/findings` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/assets/{id}/sync` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/assets/{id}/scan` | action |  |  | shipped |
| Exposures and credential leaks | (see screen description) | `GET /api/v1/exposures/stats` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/exposures` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/exposures/facets` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/credentials` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/credentials/{id}/reveal` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/exposures/bulk/{verb}` | action |  |  | shipped |
| Vulnerabilities and detail (/vulnerabilities, /vulnerabilities/[cve]) | (see screen description) | `GET /api/v1/vulnerability-exposures` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/vulnerabilities` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/vulnerability-exposures/{vuln_id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/vulnerabilities/cve/{cveId}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/vulnerabilities/cve/{cveId}/affected-assets` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/vulnerability-exposures/exception/preview` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/vulnerability-exposures/retests` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/remediation/tasks` | action |  |  | shipped |
| Compliance (/compliance) | (see screen description) | `GET /api/v1/compliance/frameworks` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/compliance/stats` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/compliance/frameworks/{id}/controls` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/compliance/controls/{id}/assess` | action |  |  | shipped |
| Imports (/findings/imports) | (see screen description) | `GET /api/v1/findings/imports` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/findings/imports` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/assets/import/csv` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/findings/imports/formats` | first view or on open |  |  | shipped |

## Prioritization, validation, mobilization and insights

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Attack paths and exposure chains (/attack-paths) | Header figures (entry points 38, targets at risk 1) | `GET /api/v1/attack-surface/stats` | first view | snapshot | assets read | shipped |
|  | Paths tab (graph or table, target filter, "6 paths computed 2 h ago") | `GET /api/v1/attack-surface/attack-paths` | first view | snapshot | read | shipped |
|  | Chains tab (ranked by urgency, score, "Act now", per-step proof Proven, Blocked by a control, Not tested) | `GET /api/v1/attack-surface/exposure-chains` | tab open | snapshot | read | shipped, change planned |
|  | Choke points | `GET /api/v1/attack-surface/attack-paths?view=choke_points` | tab open | snapshot | read | planned (new) |
|  | Exploration tab (leads, lead type, tier T0 to T2, origin Rule, AI proposed, User, System) | `GET /api/v1/exploration/leads`, `GET /api/v1/exploration/summary` | tab open | working | read | shipped |
| Threat intel and emerging threats (/threat-intel, /emerging-threats/[id]) | Figures (KEV on assets 7, past due 1, added in 30 days 14, ransomware 2, EPSS >= 10% 46) | `GET /api/v1/threat-intel/stats` | first view | snapshot | threat intel read | shipped, change planned |
|  | Sources table (EPSS, KEV, actor feed: on, state, last and next sync, records) | `GET /api/v1/threat-intel/sync` | first view | working | read | shipped |
|  | Emerging threats list ("Review 3") | `GET /api/v1/emerging-threats` | first view | working | read | shipped |
|  | Detail (affected assets, product, version, finding, task) | `GET /api/v1/emerging-threats/{id}` | first view | working | read | shipped |
| Business impact (/business-impact) | (see screen description) | `GET /api/v1/dashboard/business-impact?group_by=&period=` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/business-services` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/business-units` | first view or on open |  |  | shipped |
| Priority rules and compensating controls (/priority-rules) | (see screen description) | `GET /api/v1/priority-rules` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/priority-rules` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/priority-rules/dry-run` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/compensating-controls` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/compensating-controls/{id}/test` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/compensating-controls/{id}/assets` | action |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/priority-rules/order` | action |  |  | planned (new) |
| Detection content (/detection-content) | Figures (computed every 15 min) + Needs you + Noisiest rules | `GET /api/v1/content/summary` | first view | snapshot | content read | planned (new) |
|  | Rules list | `GET /api/v1/content-rules` | first view | working | read | shipped |
|  | Sources (6) | `GET /api/v1/content-sources` | tab open | working | read | shipped |
|  | Hub browse and install requests | `GET /api/v1/content/packages`, `GET /api/v1/content/requests` | tab open | working | read | shipped |
|  | Rule detail (content, history, usage) | `GET /api/v1/content-rules/{id}` | first view | working | read | shipped |
|  | Override editor (4 steps: choose, edit, test, review and publish) | `POST /api/v1/content-rules/test` (test), `POST /api/v1/content-rules` (draft), `PATCH /api/v1/content-rules/{id}` | action | n/a | content:write | shipped |
| Validation overview (/validation) | (see screen description) | `GET /api/v1/validation/coverage` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/validation/waiting` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/me/inbox/summary` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/control-tests/stats` | first view or on open |  |  | shipped |
| Pentest (/pentest/campaigns, /pentest/campaigns/[id], /pentest/findings/[id]/edit) | Campaign list + tab counts (planning 1, testing 2, reporting 1, remediation 2) | `GET /api/v1/pentest/campaigns` | first view | working | pentest read, member only | shipped, change planned |
|  | Campaign header, stage stepper, tiles (findings 14, critical and high 5, done 60% checklist 72 of 120, average CVSS, deadline) | `GET /api/v1/pentest/campaigns/{id}` and `/stats` | first view | working | read | shipped |
|  | Findings tab | `GET /api/v1/pentest/campaigns/{id}/findings` | tab open | working | read | shipped |
|  | Retests tab | `GET /api/v1/pentest/findings/{findingId}/retests` | tab open | working | read | shipped |
|  | Checklist (66 pass, 3 fail, 48 not tested; sections) | `GET /api/v1/pentest/campaigns/{id}/checklists` | tab open | working | read | shipped |
|  | Reports tab | `GET /api/v1/pentest/campaigns/{id}/reports` | tab open | working | read | shipped |
|  | Scope, team, rules tabs | `GET /api/v1/pentest/campaigns/{id}/members`, `/secrets`, `/completion` | tab open | working | read | shipped |
|  | Finding editor | `GET /api/v1/pentest/findings/{findingId}` | first view | working | read | shipped |
| Simulations (/simulations) | (see screen description) | `GET /api/v1/simulations` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/simulations/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/simulations/{id}/run` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/simulations/{id}/runs/{run}/approve` | action |  |  | shipped |
| Retests (/retests) | (see screen description) | `GET /api/v1/retests?state=due/overdue&severity=&campaign=` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/findings/{id}/retests` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/pentest/findings/{findingId}/retests` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/findings/{id}/retests` | action |  |  | shipped |
| Remediation: ranked fixes and board (/remediation) | Fixes ranked by risk removed (task or suggestion, closes n findings on m assets, owner, progress, risk points) | `GET /api/v1/remediation/tasks` and `GET /api/v1/remediation/suggestions` | first view | working | remediation read | shipped, change planned |
|  | Review count ("Review 3") | `GET /api/v1/remediation/suggestions/stats` | first view | snapshot | read | shipped |
|  | Board (columns by state) | `GET /api/v1/remediation/tasks?view=board` | tab open | working | read | shipped, change planned |
|  | Facets | `GET /api/v1/remediation/tasks/facets` | first view | working | read | planned (new) |
| Remediation task (/remediation/tasks/[id]) | (see screen description) | `GET /api/v1/remediation/tasks/{task_id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/remediation/tasks/{task_id}/members` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/remediation/tasks/{task_id}/timeline` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/scans/quick` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/remediation/moves` | action |  |  | shipped |
| Remediation campaign (/remediation/campaigns/[id]) | (see screen description) | `GET /api/v1/remediation/campaigns/{id}` | first view or on open |  |  | shipped |
| SLA (/sla) | (see screen description) | `GET /api/v1/sla/summary` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/sla-policies` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/sla/escalations` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/sla/escalations/remind` | action |  |  | planned (new) |
| Exceptions (/exceptions) | (see screen description) | `GET /api/v1/suppressions` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/suppressions/{id}/approve/reject` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/suppressions/{id}/reviewed` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/suppressions/{id}/preview` | first view or on open |  |  | shipped |
| Automations (/automations) | (see screen description) | `GET /api/v1/workflows` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/workflow-runs` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/workflows/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/workflows/{id}/graph` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/workflow-runs/{id}/cancel/approve` | action |  |  | shipped |
| Dashboards and editor (/dashboards) | (see screen description) | `GET /api/v1/me/dashboards` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/organization/dashboards` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/me/dashboards/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/me/dashboards/widget-catalog` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/me/dashboards/widget-preview` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/me/dashboards` | action |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/organization/dashboards/{id}/audience` | action |  |  | shipped |
| Program health and executive summary (/insights/program-health, /insights/executive) | (see screen description) | `GET /api/v1/dashboard/program-metrics` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/dashboard/program-health?period=` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/dashboard/executive-summary` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/dashboard/executive-summary/export` | first view or on open |  |  | shipped |
| Reports (/reports) | (see screen description) | `GET /api/v1/reports/schedules` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/reports/schedules` | action |  |  | shipped |
|  | (see screen description) | `PATCH /api/v1/reports/schedules/{id}/toggle` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/ctem-cycles/{id}/report` | first view or on open |  |  | shipped |
| Compliance, assign | (see screen description) | `GET /api/v1/compliance/frameworks` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/compliance/frameworks/{id}/controls` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/compliance/controls/assign` | action |  |  | shipped |
| Account settings (/account) | (see screen description) | `GET /api/v1/users/me` | first view or on open |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/users/me` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/users/me/2fa` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/users/me/2fa/setup/enable/disable/recovery-codes` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/me/2fa/replacement/start/complete` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/users/me/change-password` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/users/me/sessions` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/me/sign-in-methods` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/me/sso-links` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/api-keys` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/mcp-access/my-connections` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/audit-logs/user/{id}` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/users/me/account/view` | first view or on open |  |  | planned (new) |
| Notifications (/notifications) | (see screen description) | `GET /api/v1/notifications` | first view or on open |  |  | shipped |
|  | (see screen description) | `PATCH /api/v1/notifications/{id}/read` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/notifications/read-all` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/notifications/unread-count` | first view or on open |  |  | shipped |
| Sign in (/login) | (see screen description) | `POST /api/v1/auth/login` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/auth/mfa/verify` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/auth/discover` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/auth/providers` | first view or on open |  |  | shipped |
|  | (see screen description) | `GET /api/v1/auth/sso/...` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/auth/forgot-password` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/auth/register` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/auth/access-requests` | action |  |  | shipped |

## Sign-in, sign-up and entry

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Sign in (/login) | Sign-in methods (social buttons, org SSO list, CAPTCHA site key, sign-up on/off, request-access on/off) | GET /api/v1/auth/info | first view | static | public | shipped, change planned |
|  | Org SSO list for `?org=` | GET /api/v1/auth/sso/providers | first view / only with `?org=`) | static | public | shipped |
|  | Work-email SSO lookup ("Single sign-on" card) | POST /api/v1/auth/discover | typing / action | working | public, rate limited | shipped |
|  | Link a provider (account_exists) | POST /api/v1/me/pending-sign-in-link/describe, `.../complete`, `.../cancel` | on open | working | session of the pending link | shipped |
|  | Cancel scheduled organization deletion | POST /api/v1/auth/organization-deletion/cancel | action | working | owner, code | shipped |
|  | (code entry) | POST /api/v1/auth/mfa/verify |  |  |  | shipped |
|  | (required enrolment at sign-in) | POST /api/v1/auth/mfa/enroll/start, `/confirm`, `/session` |  |  |  | shipped |
|  | (enrolment when the rule turns on while signed in) | POST /api/v1/users/me/2fa/setup, `/enable`; GET /api/v1/users/me/2fa |  |  |  | shipped |
|  | (recovery codes, shown once) | POST /api/v1/users/me/2fa/recovery-codes |  |  |  | shipped |
|  |  | GET /api/v1/users/me/tenants, POST /api/v1/auth/token |  |  |  | shipped |
|  |  | POST /api/v1/auth/forgot-password, POST /api/v1/auth/reset-password |  |  |  | shipped |
|  |  | POST /api/v1/auth/register; states from `GET /api/v1/auth/info` (sign-up off, SSO-required domain) |  |  |  | shipped |
|  |  | POST /api/v1/auth/verify-email, POST /api/v1/auth/resend-verification |  |  |  | shipped |
|  |  | POST /api/v1/auth/access-requests, POST /api/v1/auth/access-requests/confirm |  |  |  | shipped |
|  |  | GET /api/v1/auth/info |  |  |  | shipped |
| Invitations (/invite/..., /ownership-invitations) | Invitation card (org, inviter, role, expiry, matches signed-in address?) | POST /api/v1/invitations/lookup | first view | working | token in body | shipped |
|  | Ownership invitations list | GET /api/v1/me/ownership-invitations | first view | working | signed-in account | shipped |
| Welcome and Onboarding | Options (join by invitation, create organization, none) | POST /api/v1/auth/onboarding/options | first view | working | account token | shipped |
|  | Account home links | GET /api/v1/users/me | first view | working | account | shipped |
|  | Ownership invitations waiting | GET /api/v1/me/ownership-invitations | first view | working | account | shipped |
| Approve a sensor (/activate) | Find sensor by code | POST /api/v1/sensor-pairings/lookup | action | working | sensors:pair | shipped |
|  | Pending requests (empty state shortcut) | GET /api/v1/sensor-pairings/pending | on open | working | sensors:pair | shipped |
|  | Scan zone choice | GET /api/v1/scan-zones | on open / step 3) | reference | scans:read (to confirm) | shipped |
| GitHub App installation (/ci-cd/github-app/callback) | Result of the install redirect (org, repository count, installed by, what it posts) | POST /api/v1/ci/scm-apps/github/installations | first view | working | ci:write (to confirm) | shipped |
| Connect an application (/mcp/confirm/[id]) | Pending change confirmation (action, finding, reason, who decides) | GET /api/v1/mcp-access/confirmations/{id} | first view | working | owner of the connection | shipped |
|  | Terminal/device request ("The terminal is connected") | GET /api/v1/oauth/requests/{id} | first view | working | signed-in user | shipped |
| Notifications (/notifications) | List with severity filter, read filter, pages (25/50/100) | GET /api/v1/notifications | first view | working | own notifications | shipped, change planned |
|  | Unread badge | GET /api/v1/me/bootstrap (badges), `LIVE` user channel | first view | live | own | bootstrap |
| Legal, About, System states | Legal pages, contact, links | GET /api/v1/legal | first view | static |  | shipped |
|  | Open-source licenses (search is client-side, full list) | GET /api/v1/licenses | first view | static |  | shipped |
|  | About: version | GET /api/v1/version | first view | static |  | shipped |
|  | System states (500, offline, maintenance, support-access banner) | GET /api/v1/me/bootstrap (announcements, support access) | first view | live |  | bootstrap |

## Organization settings

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Settings overview (/settings) | Page tiles by group, "Pages you cannot open are not listed", "Soon" | none: static page registry in the web build, filtered by bootstrap permissions and modules | first view | static | bootstrap | bootstrap |
|  | Search settings (pages, tabs, individual settings, old names that moved) | none: client-side index over the registry (title, group, keywords, old names, i18n en and vi) | typing | static | bootstrap | bootstrap |
|  | "Check" results in search ("Owners and admins without two-factor") | GET /api/v1/organization/security-overview | on open / first keystroke) | snapshot | owners and admins | shipped, change planned |
|  | Security overview card (score 82, 1 risk, 3 warnings) | GET /api/v1/organization/security-overview | first view | snapshot | owners and admins | shipped, change planned |
|  | "What moved" notes | none | first view | static |  | no data |
| General (/settings/general) | Name, slug, timezone, branding, security snapshot | GET /api/v1/tenants/{tenant}/settings | first view | reference | settings:read | shipped |
|  | File storage config | GET /api/v1/attachments/storage-config | first view | reference | admin | shipped |
|  | Dashboard data status | GET /api/v1/dashboard-data | on open / Dashboard data card) | snapshot | admin | shipped |
|  | Ownership transfer state (owner only) | GET /api/v1/organization/ownership-transfer | first view / owner only) | working | team:read | shipped |
| Create organization | (see screen description) | `POST /api/v1/tenants` | action |  |  | shipped |
| Modules | Module list with state, locks, reasons | GET /api/v1/tenants/{tenant}/settings/modules | first view | reference | settings:read | shipped |
|  | Dependency graph (for "needs Scope" lock lines) | GET /api/v1/tenants/{tenant}/settings/modules/graph | first view | static | settings:read | shipped |
|  | Presets | GET /api/v1/tenants/{tenant}/settings/modules/presets | on open | static | settings:read | shipped |
| Members (/settings/members) | Member list (role, teams, 2FA, last sign-in) with filters | GET /api/v1/tenants/{tenant}/members | first view | working | members:read | shipped, change planned |
|  | Stats strip (counts by state) | GET /api/v1/tenants/{tenant}/members/stats | first view | snapshot | members:read | shipped |
|  | Pending invitations | GET /api/v1/tenants/{tenant}/invitations | tab open | working | members:read | shipped |
|  | Requests to join (2) | GET /api/v1/organization/join-requests | first view / only when the count in bootstrap is nonzero) | working | members:read | shipped |
|  | Ownership transfer banner | GET /api/v1/organization/ownership-transfer | first view / owner only) | working | team:read | shipped |
|  | Member detail: roles, teams, grants, access report | GET /api/v1/users/{userId}/roles, GET /api/v1/users/{userId}/team-access, GET /api/v1/organization/members/{member_id}/access-report | on open / detail page / 3 parallel) | working | members:read | shipped |
| Teams | (see screen description) | `PUT /api/v1/groups/{groupId}/access` | action |  |  | shipped |
| Roles | (see screen description) | `GET /api/v1/roles/{roleId}/members` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/roles/{roleId}/members/bulk` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/roles/{roleId}/impact` | first view or on open |  |  | shipped |
| Service accounts | Service accounts list | GET /api/v1/service-accounts | first view | working | members:read | shipped |
|  | Keys of one account | GET /api/v1/service-accounts/{id}/api-keys | on open | working | members:read + api-keys:read | shipped |
|  | Max key lifetime | GET /api/v1/organization/settings/api-keys | first view | reference | api-keys:read/write, settings:read | shipped |
|  | Keys list (status, owner filters, export) | GET /api/v1/api-keys | first view | working | api-keys:read | shipped |
| AI assistants | (see screen description) | `PUT /api/v1/mcp-access/settings` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/mcp-access/clients` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/api-keys` | action |  |  | shipped |
| Sign-in | 2FA, re-verification tiers, new accounts, IP allowlist, who can be invited, allowed domains, personal accounts | GET /api/v1/tenants/{tenant}/settings | first view | reference | settings:read (owner edits) | shipped |
|  | "Last changed by a member, 3 days ago" | GET /api/v1/audit-logs/resource/{type}/{id} | first view | working | audit:read | shipped |
|  | "Who is affected" (41 of 62 password sign-in, 17 without authenticator) | GET /api/v1/tenants/{tenant}/members/stats | on open | snapshot | members:read | shipped, change planned |
|  | IP allowlist lockout check ("23 members used other addresses in 30 days") | POST /api/v1/tenants/{tenant}/settings/security/preview | action | working | owner | planned (new) |
|  | Verified domains with join policy | GET /api/v1/organization/settings/domains | tab open / Joining) | reference | settings:read | shipped |
|  | Trusted organizations (both directions) | GET /api/v1/organization/trusts | tab open / Joining) | reference | members:read | shipped |
|  | Pending SSO changes (SSO approvals) | GET /api/v1/tenants/{tenant}/settings/sso/changes | tab open / Joining) | working | owner | shipped |
|  | SSO exceptions (members allowed without SSO until a date) | none found | tab open / Joining) | reference | owner | planned (new) |
| Directory sync | (see screen description) | `POST /api/v1/scim-tokens` | action |  |  | shipped |
| Security overview | Security overview (grouped checks: sign-in, people, credentials, organization, scanning) | GET /api/v1/organization/security-overview | first view | snapshot |  | shipped, change planned |
|  | Audit log list (result, severity, period, hide system, search) | GET /api/v1/audit-logs | first view | working |  | shipped, change planned |
|  | Audit stats strip | GET /api/v1/audit-logs/stats | first view | snapshot |  | shipped |
|  | Entry detail drawer | GET /api/v1/audit-logs/{id} | on open | working |  | shipped |
|  | Export | GET /api/v1/audit-logs/export | action | working |  | shipped |
|  | Chain verify | GET /api/v1/audit-logs/verify | on open | working |  | shipped |
|  | Support access: active, history | GET /api/v1/organization/support-access/active, GET /api/v1/organization/support-access/grants | first view | working |  | shipped |
| Finding lifecycle | Closing policy + pending change ("takes effect on 12 Nov") | GET /api/v1/organization/settings/closure | first view | reference | (none in grep: gap) | shipped |
|  | Sub-statuses by status | GET /api/v1/lifecycle-sub-statuses | first view | reference | findings:read | shipped |
|  | Lifecycles and versions | GET /api/v1/lifecycles, `/{id}`, `/{id}/versions` | tab open / on open | reference | findings:read | shipped |
|  | Approval policy, tiers, pool, limits | GET /api/v1/organization/settings/finding-approvals | tab open | reference | findings:read | shipped |
|  | Security pool needs groups | GET /api/v1/groups | on open | reference | groups:read (screen text: "You need permission to view groups") | shipped |
|  | "Affected now: 61 people hold the approve permission; 312 open critical/high" | none | first view | snapshot | Add `affected` counts to the finding-approvals GET (CHANGE, S) | planned (new) |
| Leaked credentials | (see screen description) | `POST /api/v1/organization/settings/license-policy/preview` | action |  |  | shipped |
|  | (see screen description) | `GET /api/v1/credentials/{id}` | first view or on open |  |  | shipped |
| Risk scoring | Risk scoring |  |  |  |  | no data |
|  | Emerging threats |  |  |  |  | no data |
|  | Asset lifecycle |  |  |  |  | no data |
|  | Asset sources (source precedence, preview of changed values) |  |  |  |  | no data |
| Pentest methodology | (see screen description) | `POST /api/v1/pentest/report-templates/verify` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/pentest/templates/bulk/delete` | action |  |  | shipped |
| Scope policy | Whole page: summary table + each policy card | GET /api/v1/organization/settings/approvals/view | first view | reference | per part | planned (new) |
|  | Waiting-now counts | GET /api/v1/approvals?status=pending&per_page=1 (findings), GET /api/v1/scan-approvals?status=pending (scans), GET /api/v1/content/requests (content), GET /api/v1/scanner-templates?status=pending | first view | working | per part | shipped |
|  | Scan approval: rules evaluated on existing scans ("6 of 200 would wait") | POST /api/v1/organization/settings/scan-governance/test | action | working | scans:write | shipped |
| Scan windows | (see screen description) | `POST /api/v1/scan-window-policies/preview` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/scan-windows/preview` | action |  |  | shipped |
|  | (see screen description) | `POST /api/v1/scan-window-overrides` | action |  |  | shipped |
| Sensor job safety | Sensor job safety: scan jobs flags (saved together) + sensor keys and shared sensors (each switch applies at once) | GET /api/v1/sensors/identity-policy, GET /api/v1/organization/settings/shared-sensors |  |  |  | shipped |
|  | Scan identification (User-Agent and headers) | GET /api/v1/tenants/{tenant}/settings (security block carries `platform_scan_identification`) |  |  |  | shipped, change planned |
| Tools | Tools reported by this org's sensors, update available, sensor versions | GET /api/v1/tools | first view | working | tools:read | shipped |
|  | Tool defaults (order: tool, org defaults, sensor override) with "needs attention" and "sensors refusing" | GET /api/v1/sensors/tool-defaults | tab open | reference | sensors:read | shipped |
|  | Capabilities (table or cards, All 42, Platform 39, Custom 3) | GET /api/v1/capabilities (+`/categories`) | tab open | static | tools:read | shipped |
| Sensor products | (see screen description) | `PUT /api/v1/proxy-pools/assignments/{sensor_id}` | action |  |  | shipped |
| Content | Content policy: refresh schedule, max age per kind, pinned version | GET /api/v1/sensors/content-policy | first view | reference | sensors:read | shipped |
|  | Custom content policy (allow code-class templates, review defaults) | GET /api/v1/content/settings | first view | reference | content:read | shipped |
|  | Source credentials | GET /api/v1/secret-store | tab open | reference | secret-store:read | shipped |
|  | Tool source keys | GET /api/v1/tool-sources | tab open | reference | secret-store:read | shipped |
|  | Catalog (52 packages, 14 installed, 1 request) | GET /api/v1/content/packages, GET /api/v1/content/installs, GET /api/v1/content/requests | FP tab counts via `include` / CHANGE) | working | content:read | shipped |
|  | Scanner templates | GET /api/v1/scanner-templates, `/usage` | first view | working | scanner-templates:read | shipped |
|  | Detection rules (platform rules + yours, 200 max) | GET /api/v1/content-rules, GET /api/v1/platform-content-packs | first view | working | content-packs:read | shipped |
|  | Wordlists (+ preview for a domain) | GET /api/v1/wordlists, `GET /api/v1/wordlists/preview` | first view | working | content-packs:read | shipped |
| Integrations overview, Source control, Scanners, Ticketing | All integrations by category, "Needs attention" | GET /api/v1/integrations | first view | working | integrations:read | shipped |
|  | Source control connections, repo sync list | GET /api/v1/integrations/scm, GET /api/v1/integrations/{id}/repositories | first view / on open | working | integrations:read | shipped |
|  | Ticketing connection detail | GET /api/v1/integrations/{id}, `/ticket-create-policy`, GET /api/v1/integrations/jira/projects, `/{id}/jira/issue-types`, `/jira/metadata` | on open | working | integrations:read | shipped |
|  | Inbound webhook (secret) | GET /api/v1/integrations/{id}/jira-webhook, `/github-webhook` | on open | working | integrations:manage | shipped |
|  | Field mappings list and editor | GET /api/v1/integrations/ticket-mappings (+`/catalog`), `/{mapping_id}`, `/versions`, `/diff` | first view / tab open | working | integrations:read | shipped |
|  | Import mappings | GET /api/v1/import-mappings, `/templates` | first view | working | (none in grep) | shipped |
| Notification channels, history, queue | Channels (chat, e-mail, webhook kinds) | GET /api/v1/integrations/notifications | first view | reference | integrations:read | shipped |
|  | Event type catalog for the form | GET /api/v1/me/event-types | on open | static |  | shipped |
|  | Sent events (history) | GET /api/v1/integrations/{id}/notification-events | tab open | working | integrations:read | shipped |
|  | Queue (outbox) + stats | GET /api/v1/notification-outbox, `/stats` | tab open | working | notifications:read + integrations:manage | shipped |
|  | Signing secret (webhook) | GET /api/v1/integrations/{id}/signing-secret | on open | working | integrations:manage | shipped |

## Platform admin console

| Screen | Block | Endpoint | Loaded | Freshness | Permission and scope | State |
|---|---|---|---|---|---|---|
| Console sign-in | Sign-in method (password, IdP, break-glass) | GET /api/v1/admin/auth/factors, GET /api/v1/admin/auth/idp | first view | static | public | shipped |
|  | Password, code, recovery, keys | POST /api/v1/admin/auth/login, `/mfa`, `/password`, `/recovery`, `/webauthn/session/options` + `/webauthn/session`, `/idp/start` + `/idp/callback` | action | working | rate limited | shipped |
|  | My keys and codes | GET /api/v1/admin/auth/factors | first view | working | own | shipped |
| Console shell | (see screen description) | `GET /api/v1/admin/version-check` | first view or on open |  |  | shipped |
| Console overview | "Needs you" attention queue (orgs without owner, break-glass sign-ins 7d, failed admin actions 24h, break-glass tests overdue, offline platform sensors, access requests pending, schema drift, stuck commands, scan runs past deadline, failed/dead outbox) | GET /api/v1/admin/overview | first view | snapshot | any admin role | shipped, change planned |
|  | Recent administrator activity | GET /api/v1/admin/audit-logs?kind=changes&per_page=8 | first view | working | audit reader | shipped |
|  | Banner: security release | GET /api/v1/admin/version-check | first view / shell) | snapshot | any admin | shipped |
| Software updates and licences | (see screen description) | `GET /api/v1/admin/edition` | first view or on open |  |  | shipped |
|  | (see screen description) | `POST /api/v1/admin/version-check/import` | action |  |  | shipped |
|  | (see screen description) | `PUT /api/v1/admin/version-check/enabled` | action |  |  | shipped |
| Admin activity | List (administrator, action, resource, result, IP; filters admin, action, resource type, success, from/to, search, `kind=changes`) | GET /api/v1/admin/audit-logs | first view | working |  | shipped, change planned |
|  | Stats strip | GET /api/v1/admin/audit-logs/stats | first view | snapshot |  | shipped |
|  | Chain status ("could not be checked") | GET /api/v1/admin/audit-logs/chain | first view | snapshot |  | shipped |
|  | Entry drawer (request body, secrets redacted) | GET /api/v1/admin/audit-logs/{id} | on open | working |  | shipped |
| Organizations list | List (name, owner, status, limits, SSO) | GET /api/v1/admin/tenants | first view | working | admin | shipped, change planned |
|  | Filter counts (without owner, suspended, pending deletion) | GET /api/v1/admin/tenants/facets | first view | snapshot | admin | planned (new) |
| Organization detail (/organizations/{id}) | Overview tab: facts, support access, dashboard data, recent admin actions, first 5 users, deletion banner | GET /api/v1/admin/tenants/{tenantId}/view | first view | working | admin | planned (new) |
|  | Limits tab (used, allowed, set by) and modules deny list | GET /api/v1/admin/tenants/{tenantId}/limits, GET /api/v1/admin/tenants/{tenantId}/modules | tab open | working | admin | shipped |
|  | Sign-in tab: providers, policy, verified domains, SAML | GET /api/v1/admin/tenants/{tenantId}/sso/identity-providers, `/sso/enforcement`, `/sso/saml`, `/sso/verified-domains`, `/sso/changes` | tab open | working | admin | shipped |
|  | Scope, activity and audit chain tab | GET /api/v1/admin/tenants/{tenantId}/scan-approval-policy, GET /api/v1/admin/tenants/{tenantId}/audit-chain, GET /api/v1/admin/audit-logs?resource_id= | tab open | working | admin | shipped |
| Users | Users list (account, signs in with, organizations; filter states all, active, unverified, locked, blocked, mfa_off, platform_admins; search needs 3+ characters) | GET /api/v1/admin/platform-users | first view | working |  | shipped, change planned |
|  | User detail (sessions, account facts, organizations, linked identities, admin actions) | GET /api/v1/admin/platform-users/{user_id} | first view | working |  | shipped |
|  | Administrators + role holders | GET /api/v1/admin/users, GET /api/v1/admin/platform-roles, GET /api/v1/admin/platform-roles/assignments | first view | working |  | shipped |
|  | Sessions | GET /api/v1/admin/console-sessions | first view | live-ish |  | shipped |
| Approvals | (see screen description) | `POST /api/v1/admin/approvals` | action |  |  | shipped |
| Access requests and Sign-ups | (see screen description) | `GET /api/v1/admin/signup-events/daily` | first view or on open |  |  | shipped |
| Announcements | (see screen description) | `POST /api/v1/admin/announcements` | action |  |  | shipped |
| Support access | (see screen description) | `POST /api/v1/admin/support/grants/{grant_id}/sessions` | action |  |  | shipped |
|  | (see screen description) | `DELETE /api/v1/admin/support/sessions/{session_id}` | action |  |  | shipped |
| Settings (platform) | screen data | GET /api/v1/admin/configuration (all settings, secrets only "is set"), GET /api/v1/admin/settings/region |  |  |  | no data |
|  | screen data | GET /api/v1/admin/settings/signup |  |  |  | no data |
|  | screen data | GET /social-login-providers, GET /captcha |  |  |  | no data |
|  | screen data | GET /api/v1/admin/settings/console-mfa, GET /api/v1/admin/platform-idp |  |  |  | no data |
|  | screen data | GET /email, /email-relay, /alerts |  |  |  | no data |
|  | screen data | GET /limits, /auth-mfa, /storage-quota, /leaked-secret-storage |  |  |  | no data |
|  | screen data | GET /scan-approval-policy, /scan-identification |  |  |  | no data |
|  | screen data | GET /ai |  |  |  | no data |
|  | screen data | GET /legal |  |  |  | no data |
|  | screen data | GET /platform-sensor-proof, /shared-sensors, /shared-sensors/egress, /shared-sensor-internal-zones, /shared-sensor-anomaly; GET /api/v1/admin/shared-sensors/queue, `/jobs` |  |  |  | no data |
| Platform sensors, fleet ( `-Sensors-Token`) | screen data | GET /api/v1/admin/shared-sensors | first view | working |  | shipped |
| Instance scan zones | screen data | GET /api/v1/admin/instance-scan-zones | first view | reference |  | shipped |
| Enroll a shared sensor | screen data | POST /api/v1/admin/shared-sensors/enrollment-tokens | action | working |  | shipped |
| Pause, retire | screen data | POST /api/v1/admin/shared-sensors/{sensor_id}/disable, `/enable`, `/revoke` | action | working |  | shipped |
| Content catalog | screen data | GET /api/v1/admin/content-catalog, `/packages`, `/packages/{namespace}/{name}/versions` | first view | reference |  | shipped |
| Content packs ( `-ContentPacks-Pack`) | screen data | GET /api/v1/admin/content-packs, `/channels`, `/signing-key`, `/{id}` | first view | reference |  | shipped |
| Threat intelligence | screen data | GET /api/v1/admin/threat-intel/sync | first view | snapshot |  | shipped |
| Target mappings | screen data | GET /api/v1/admin/target-mappings, `/registry`, `/types`, `/stats` | first view | reference |  | shipped |
| AI applications | screen data | GET /api/v1/admin/mcp-clients | first view | working |  | shipped |

## Phone layout

The phone layout uses the same endpoints as the desktop screen it mirrors, with the same lean rows and a smaller
page size. No endpoint exists for the phone only.

| Phone screen | Desktop screen reused | Endpoints (first view, then on demand) | Differences |
|---|---|---|---|
| Sign in and two-factor | Sign-in | `POST /api/v1/auth/login`, `POST /api/v1/auth/mfa/verify` (6-digit code and recovery code), `GET /api/v1/auth/providers` (Google, SSO buttons), `GET /api/v1/auth/info` | Same as desktop; "Required by the organization" comes from the mfa step response. Org list after sign-in is the switcher read |
| Phone home | Home | `GET /api/v1/me/dashboards/home?choice=` (1 read) | One column: summary sentence, 5 key figures, CTEM stages, Fix next (3 levers), setup card; same widget results as desktop, no coverage matrix; "Refresh now" = `POST /me/dashboards/{id}/refresh`. Inbox total comes from bootstrap (core flag: CHANGE) |
| Navigation | App shell | bootstrap only (badges, pins with counts, modules, permissions) | Inbox 12, Findings 418, Notifications 3, pinned views with counts: all `BOOT`. No extra request |
| Organization switcher | Shell org switcher | bootstrap `tenants` (name, role, asset count, expiry) | Fields: name, role, assets count; switching = `POST /api/v1/auth/token` (select organization) then reload bootstrap. Asset count per org is not in the membership today (CHANGE S, inferred) |
| Notifications | Notifications page | `GET /api/v1/notifications?severity=&status=&page=` -> `PATCH /api/v1/notifications/{id}/read`, `POST /api/v1/notifications/read-all`; prefs `GET /api/v1/notifications/preferences` | Card: title, line, severity, time. Tabs All / Unread / Read, severity filter, paging "Page 1 of 4 (22 total)". Mark 3 as read has an Undo |
| Inbox | Inbox | `GET /api/v1/me/inbox/summary` (queue counts: assigned 5, to review 3, my requests 2, expiring 1, tasks 1) + the active queue: `GET /api/v1/findings?assigned_to=me&status=open&sort=due` or `GET /api/v1/approvals` | Row: priority, title, asset, KEV, EPSS, status, due; actions Set status / Open / Triage. Queue list reuses the Findings list or approvals list. 1 summary + 1 list |
| Findings list | Findings workbench | `GET /api/v1/findings?view=&per_page=10` + `GET /api/v1/findings/quick-views` + `GET /api/v1/findings/facets` (on opening Filters, not at first paint) | Card: priority, title, asset (+ extra hosts), id, severity, signals, status, due. Lenses Findings / By CVE (`/vulnerabilities`) / Imports (`/findings/imports`). Bulk bar: Assign, Status, Add to task, More. Approvals 4 and Fixes awaiting verification 9 from bootstrap badges |
| Finding quick actions | Findings row menu | `GET /api/v1/findings/{id}/transitions` (OPEN), `POST /findings/{id}/assign`, `PATCH /findings/{id}/status`, `POST /findings/{id}/create-ticket`, `POST /remediation/tasks` | Sheet on long press or dots. False positive and Accept risk route to the status flow (approval needed) |
| Filters and views | Findings filter menu + saved views | `GET /api/v1/findings/facets` (counts: practice 233 / 61 / 48 ..., priority P0 9 / P1 18, severity), `GET /api/v1/views`, `PUT /api/v1/me/pins`, `POST /api/v1/views` (save, visible to me / org) | Same facets as desktop in a full-screen sheet; practice counts = `include=practice_counts` on the list |
| Triage (card by card) | Triage ( not in this area) | queue: `GET /api/v1/findings?status=new&priority_class=P0,P1&sort=-priority` (card data from the list item + `GET /findings/{id}/priority-explanation` for "why" and `GET /findings/{id}/evidence-items?per_page=1`), suggestion: `GET /findings/{id}/ai-triage` | Fields: priority, id, severity, title, why, asset, owner, due, exploitation, found by, seen, one evidence, assisted suggestion. Actions: Confirm `PATCH /findings/{id}/status`, Skip (client), assign, task, retest, FP / risk accept request. Prefetch the next card on HOVER-equivalent (after the current card is shown). Summary "You decided 4" is client-side |
| Vulnerabilities by CVE | Vulnerabilities lens ( list; Findings "By CVE") | `GET /api/v1/vulnerabilities?sort=-risk&per_page=5&status=open` + stat strip: `GET /api/v1/threat-intel/stats` (exploited 7, past SLA 3, top 3 fixes close 64) | Card: priority, CVE, title, severity + CVSS, KEV, exploit maturity, EPSS, assets count and internet-facing, open count and next due, fix version, "in tasks". The "affected assets" and "in tasks" counts are list fields (CHANGE S, inferred: `GET /vulnerabilities/{id}/affected-assets` is per CVE) |
| Finding detail | Finding detail | `GET /api/v1/findings/{id}/view` (1 read; use the Overview parts only) | Smaller: header chips, sentence, lifecycle strip, sections (What to do, Why it matters, Properties, Evidence, Related, Details, Activity). Tabs open lazily with `view?tab=` (core CHANGE). Data flow and Pentest details tabs only for code and pentest findings (`GET /findings/{id}/dataflows`, `GET /pentest/findings/{findingId}`). Notes: kind blocks of core apply with the same endpoints |
| Change status | Finding detail dialogs | `GET /api/v1/findings/{id}/transitions` (OPEN), `PATCH /findings/{id}/status`, `POST /findings/actions/fix-applied`, `POST /findings/{id}/approvals` (risk accept: reason, end date 14 / 30 / 90 days or date, approver, step-up code), `POST /findings/{id}/duplicates` | Steps: pick state -> note form -> confirm. Approver list: `GET /findings/{id}/approvals/policy`. Policy maximum (90 days) from the same policy |
| Assets list | Assets | `GET /api/v1/assets?per_page=10` + `GET /api/v1/assets/facets` (type pills) + `GET /api/v1/assets/stats` (header sentence: 1,284 assets, 312 internet-facing, 41 need attention) | Card: name, kind, owner, criticality, open findings, 12-week trend, coverage dots, last seen. Bulk bar: select, "Select all 9". Add via |
| Asset categories | Assets category view | `GET /api/v1/assets/overview` | Five tiles: type, count, internet-facing, open findings, need attention |
| Asset detail | Asset detail ( other area) | `GET /api/v1/assets/{id}/view` (1 read) | Header (type, exposure, criticality, risk), sections Overview / Findings (top 3 + "All 6") / Relationships / Activity; Identity, attribution, lineage, freshness, coverage, ports, web evidence, scan window folded in "More about this asset" (these are the view parts) |
| Add asset | Asset forms | `POST /api/v1/assets` (type, name, owner, criticality; advanced: description, tags, environment, unit, classification) | Pickers: owners `GET /assets/{id}/owners`-style TYPE search via `GET /tenants/{tenant}/members?q=`. Scope check message "waits for a scope decision" = response status |
| Asset relationships | Relationships | `GET /api/v1/assets/{id}/relationships/groups` (list first: Resolves to, Exposes, Aliases, Part of) + `GET /api/v1/assets/{id}/neighborhood` (graph fold, TAB) | Row: name, type, source, last seen, low-confidence flag; "1 related asset you can't access" count comes from the groups response (CHANGE S, inferred). Add: `POST /api/v1/assets/{id}/relationships` |
| Exposures | Exposures | `GET /api/v1/exposures/stats` (needs attention 41, closed 212, total 253, waiting for approver 3, categories) + `GET /api/v1/exposures?per_page=5` | Card: severity, title, category, state. Category bars and "by severity and lifecycle" from `stats`. Filters = same facet keys |
| Scans and runs | Scans list | `GET /api/v1/scans?per_page=10` + `GET /api/v1/scans/stats` (state counts All 14, Enabled 11, paused 2, disabled 1) | Card: name, type, schedule, badge, last run + status, last 5 runs squares, Run now. Run status tab: `GET /api/v1/scan-runs?status=` |
| Scan detail | Scan detail | `GET /api/v1/scans/{id}` + `GET /api/v1/scans/{id}/runs?per_page=5` (+ `GET /scans/{id}/approval`) | Summary, last run card, next run, success rate, approval note, targets, execution; tabs lazy. Run now `POST /scans/{id}/trigger`; Cancel run: NEW `POST /scan-runs/{id}/cancel` (core flag) |
| Scan run | Scan run | `GET /api/v1/scan-runs/{id}` + `GET /api/v1/scan-runs/{id}/stages` (2 reads) -> tasks and logs on demand | Smaller: key cells, Needs attention, scrollable timeline, results chips (New 31, Gone 70, Unchanged 23) and a short list; tap a bar to open the task log (`GET /scan-runs/{id}/tasks/{task_id}/logs`) |
| Sensors | Sensors | `GET /api/v1/sensors/stats` (fleet health 6 of 7, jobs 14 of 40, zone coverage, updates 2, needs attention 3) + `GET /api/v1/sensors?per_page=10` | Card: name, state, address, heartbeat, role, zone, version, slots, key expiry, 24-hour lane (24 cells: NEW field, inferred: `activity_24h` per sensor, S). LIVE via heartbeat events |
| Attack paths | Attack paths | `GET /api/v1/attack-surface/attack-paths/{id}` (target Payments DB) | List form first: Fix here first (3 choke points), paths as chains of names with KEV flags; graph is a link out. Create task `POST /remediation/tasks` |
| Remediation tasks | Remediation | `GET /api/v1/remediation/suggestions/stats` (risk left 3,140, open tasks 23, suggestions 12) + `GET /api/v1/remediation/suggestions?sort=-risk_removed&per_page=5` | Card: fix title, risk points, state (Task open / Suggested), confidence, counts, owner. Accept: `PATCH /remediation/suggestions/{id}`/task create; "Why?" opens the suggestion `GET /remediation/suggestions/{id}`. Tabs Fix plan, Tasks (`GET /remediation/tasks`), Campaigns (`GET /remediation/campaigns`), SLA, Exceptions |
| Remediation task | Task detail | `GET /api/v1/remediation/tasks/{task_id}` + `GET /remediation/tasks/{task_id}/query` or findings list `?task_id=` (31 findings, grouped by asset, SCROLL) | Header, progress bar by state, fix steps, findings rows (asset, address, CVE, status, due), selection bar: Move / Split / Detach (`POST /remediation/tasks/{task_id}/splits`, `.../merges`; moving asks to confirm). `GET /remediation/tasks/{task_id}/timeline` lazy |
| SLA | SLA | `GET /api/v1/sla/overview` (NEW, core) + `GET /api/v1/findings?sla_status=overdue,due_7d&per_page=10` | Four tiles, due-ahead chart, breach rate chart, past-due by severity and age; table becomes cards. Tabs Fix plan / Tasks / Campaigns / SLA / Exceptions share the remediation shell |
| Search and commands | Command palette | `GET /api/v1/search?q=&types=` (NEW, core), scope chips All / Findings / CVEs / Tasks / Commands | Same groups: Vulnerability, Findings 14, Assets, Remediation tasks, Pages and settings, Recent. Row actions Assign me / Change status / Scan now; "Assign me" on all 14 opens the bulk preview first |
| Settings index | Settings home | none (client catalog, gated by bootstrap permissions + modules) | 6 groups with the pages and in-page settings; search finds settings inside pages. Counts "6 pages" client-side |
| A settings page (Finding lifecycle) | Finding lifecycle settings | `GET /api/v1/organization/settings/finding-approvals`, `GET /api/v1/organization/settings/closure` -> `PATCH /organization/settings/finding-approvals`, `PUT /organization/settings/closure` | Same fields; Danger zone "Reset to safe defaults" asks for authenticator code: NEW `POST /organization/settings/finding-approvals/reset` (S, inferred; or `PATCH` with defaults); turn-off-approval confirm with reason + code |
| My account | Account | `GET /api/v1/users/me`, `GET /api/v1/users/me/2fa`, `GET /api/v1/users/me/sessions`, `GET /api/v1/me/sign-in-methods` (4 reads: lazy by section; first paint = profile only) | Sections: profile (name, email verified, phone, user id), Password (`POST /users/me/change-password`), Two-factor (replace `POST /me/2fa/replacement/start/complete`, recovery codes `POST /users/me/2fa/recovery-codes`), Sign-in methods (link / unlink `POST /me/sign-in-method-links/{provider}/start`), Sessions (`DELETE /users/me/sessions/{sessionId}`), Delete account (`DELETE /me/account`, blocked while only owner: `GET /me/account/deletion`), Preferences (`PUT /users/me/preferences`) |
| States | Shared states | Same endpoints as the page it shows: empty org (no data: "Not measured, never 0"), no match, loading, load error (shows request id, status, diagnostics), 504 | Error body must carry `request_id` (exists in `apierror.Response`, inferred) |
| Members and roles | Members | `GET /api/v1/tenants/{tenant}/members?per_page=10` + `GET /api/v1/tenants/{tenant}/members/stats` (62 members, 58 active, 3 disabled, 4 invitations, 2 requests) | Card: name, email, role, two-factor, last seen; invitations `GET /tenants/{tenant}/invitations` (lazy), join requests (SSO approvals); roles `GET /api/v1/roles` (lazy). Mutations: `PATCH /tenants/{tenant}/members/{userId}`, `POST /tenants/{tenant}/invitations/{invitationId}/resend/link`, suspend / reactivate |
| Detection content | Rules library | `GET /api/v1/content/packages?per_page=10` (+ stats) and `GET /api/v1/content/installs` | Card: rule name, state, id, source, severity, ran on N assets in 30 d, matches, flags (noisy, failed to load, upstream changed). The 30-day ran / matches / noisy counters and the per-rule usage are NEW fields (to confirm); sources `GET /content/trust`. Upload / New rule: desktop only (link out) |
| New scan | Scan create | `POST /api/v1/scans/quick/preview` then `POST /api/v1/scans/quick` (preview yes, targets, workflow, schedule, intensity); catalogs `GET /api/v1/scans/capabilities`, `GET /api/v1/scans/stages`; schedule preview `POST /api/v1/scans/schedule-preview`; sensors `GET /api/v1/sensors` (advanced, lazy) | Fields: name, targets, what to run, schedule, advanced fold (intensity, sensor, targets per job, duration, retries, pass or fail, tags); intrusive needs 1 approval (`POST /scans/{id}/approval`) |

## Key files

- Bootstrap: `server/internal/infra/http/handler/bootstrap_handler.go`
- Views: `server/internal/infra/http/handler/view_parts.go`, `finding_view_handler.go`, `asset_view_handler.go`
- Lists: `server/pkg/filterspec`, `server/pkg/pagination`, `server/internal/infra/http/handler/finding_search_handler.go`
- Dashboards: `server/internal/infra/http/handler/dashboard_home_handler.go`, [dashboards.md](dashboards.md)
- Inbox: `server/internal/infra/http/handler/inbox_handler.go`, [my-work.md](my-work.md)
- Live: `server/internal/infra/websocket/hub.go`, `bridge.go`
- Request budgets: `web/e2e/request-budget.json`, [page-views.md](page-views.md)
