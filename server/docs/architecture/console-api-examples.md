# Console API: example bodies

Design: [RFC-157](../rfcs/RFC-157-console-api-design.md). Screens: [console-api-screens.md](console-api-screens.md).

Example request and response bodies for the most important console reads. Ids are shortened for reading
(`0193...a1`); real ids are full lowercase UUIDs. "shipped" and "planned" refer to the route; a field marked
`// planned` is not sent yet. The organization, people and hosts are made-up sample data (`example.com`).

## 1. Shell bootstrap: `GET /api/v1/me/bootstrap` (shipped; changes planned)

One per hard load. `Cache-Control: private, no-store`. Sizes: target under 15 KB gzip.

```json
{
  "user": { "id": "0193...u1", "name": "Linh Tran", "email": "linh.tran@example.com", "locale": "en",
            "timezone": "Asia/Ho_Chi_Minh", "two_factor": true },
  "tenants": [
    { "id": "0193...t1", "slug": "example-corp", "name": "Example Corp", "role": "owner" },
    { "id": "0193...t2", "slug": "example-labs", "name": "Example Labs", "role": "admin" },
    { "id": "0193...t4", "slug": "example-partner", "name": "Example Partner", "role": "member",
      "external": true, "access_ends_at": "2026-11-30T00:00:00Z" }
  ],
  "tenant": { "id": "0193...t1", "slug": "example-corp", "name": "Example Corp" },
  "permissions": { "list": ["assets:read", "findings:read", "findings:triage", "..."], "version": 41 },
  "modules": { "module_ids": ["assets", "findings", "scans", "pentest", "ai_triage"],
               "beta_module_ids": ["simulations"], "read_only_modules": {} },
  "badges": { "unread_notifications": 4, "inbox_total": 12, "easm_review": 6,
              "pending_approvals": 3, "ready_to_close": 2 },
  "pins": { "data": [
      { "kind": "quick_view", "ref": "kev_exposed", "count": 7 },
      { "kind": "saved_view", "ref": "0193...v9", "name": "Team SLA 72 h", "count": 3 } ], "max": 10 },
  "announcements": [],
  "ownership_invitations": { "data": [] },
  "support_access": null,
  "ai_config": { "mode": "byok", "available": true, "provider": "configured" },
  "limits_apply": false,
  "reference_version": "r-7f3a9c",            // planned
  "realtime": { "channels": ["user:0193...t1:0193...u1", "tenant:0193...t1"] },   // planned
  "server_time": "2026-11-11T09:12:03Z"      // planned
}
```

Moved out (to the reference catalog): `risk_levels`, `sla`. Never here: lists, other people, secrets, counts
computed over big tables per request (`badges` come from per-user counters, `badge.changed` events update them).

## 2. Reference catalog: `GET /api/v1/reference` (planned)

`ETag: "r-7f3a9c"`, `Cache-Control: private, no-cache`. The console asks with `If-None-Match` and usually gets
`304`. Target under 40 KB gzip. Sections the caller may not read are absent.

```json
{
  "version": "r-7f3a9c",
  "finding_statuses": [
    { "key": "new", "group": "open", "label_key": "status.new" },
    { "key": "confirmed", "group": "open", "label_key": "status.confirmed" },
    { "key": "in_progress", "group": "open", "label_key": "status.in_progress" },
    { "key": "fix_applied", "group": "open", "label_key": "status.fix_applied" },
    { "key": "resolved", "group": "closed", "label_key": "status.resolved" },
    { "key": "accepted", "group": "closed", "label_key": "status.accepted" },
    { "key": "false_positive", "group": "closed", "label_key": "status.false_positive" }
  ],
  "sub_statuses": [ { "id": "0193...s1", "status": "in_progress", "name": "Waiting on vendor" } ],
  "priority_classes": [
    { "key": "P0", "sla_hours": 72, "label_key": "priority.p0" },
    { "key": "P1", "sla_hours": 168 }, { "key": "P2", "sla_hours": 720 }, { "key": "P3", "sla_hours": 2160 } ],
  "severities": ["critical", "high", "medium", "low", "info"],
  "risk_levels": { "critical": 90, "high": 70, "medium": 40, "low": 10 },
  "sla": { "by_priority": { "P0": 72, "P1": 168, "P2": 720, "P3": 2160 },
           "by_criticality": { "critical": 0.5, "high": 1.0 }, "assets_with_own_policy": true },
  "asset_types": [ { "key": "domain", "category": "external" }, { "key": "host", "category": "infrastructure" },
                   { "key": "web_service", "category": "external" }, { "key": "repository", "category": "code" } ],
  "finding_kinds": ["vulnerability", "misconfiguration", "secret", "code", "component", "web", "compliance", "pentest"],
  "teams": [ { "id": "0193...g1", "name": "Network team" }, { "id": "0193...g2", "name": "API team" } ],
  "tags": { "data": ["pci", "internet-facing", "crown-jewel"], "complete": true },
  "event_types": [ { "key": "finding.created", "category": "findings" } ],
  "sources": [ { "id": "0193...k1", "name": "Port scanner", "kind": "sensor_tool" } ]
}
```

## 3. Findings list: `GET /api/v1/findings?state=open&sort=-priority&per_page=50&include=status_counts` (changes planned)

Planned: lean rows (today every row is the full finding), keyset
cursor, bounded total, `status_counts`, `filters_applied`.

```json
{
  "data": [
    {
      "id": "0193...f1",
      "display_title": "Citrix ADC session token leak",
      "ref": "CVE-2023-4966",
      "kind": "vulnerability",
      "priority_class": "P0",
      "severity": "critical",
      "status": "confirmed",
      "sub_status": null,
      "sla": { "deadline": "2026-11-08T00:00:00Z", "status": "overdue" },
      "asset": { "id": "0193...a1", "name": "vpn.example.com", "type": "domain", "address": "198.51.100.20" },
      "assignee": { "id": "0193...u3", "name": "Sam Rivera" },
      "team": { "id": "0193...g1", "name": "Network team" },
      "signals": { "kev": true, "epss": 0.97, "exploit": "public", "reachable": true, "internet": true },
      "first_detected_at": "2026-10-02T08:00:00Z",
      "last_seen_at": "2026-11-11T03:10:00Z",
      "source_count": 2,
      "comments_count": 4,
      "row_version": 17
    }
  ],
  "next_cursor": "eyJrIjpbIlAwIiwiMDE5My4uLmYxIl0sInMiOiItcHJpb3JpdHkiLCJ0IjoiLi4uIn0.sig",
  "total": 418,
  "total_is_estimate": false,
  "status_counts": { "open": 418, "in_progress": 61, "fix_applied": 9, "closed_30d": 121 },
  "filters_applied": true,
  "per_page": 50
}
```

Phone uses the same row with `per_page=20`.

## 4. Findings facets: `GET /api/v1/findings/facets?state=open&facet=priority_class,status,asset_type,team,source,signals` (planned)

Fired in parallel with the list. Same filters, same scope. Top 10 per facet; counts capped at 10,000.

```json
{
  "facets": {
    "priority_class": { "values": [ {"value":"P0","count":5}, {"value":"P1","count":22},
                                    {"value":"P2","count":141}, {"value":"P3","count":250} ], "other_count": 0 },
    "status": { "values": [ {"value":"new","count":203}, {"value":"confirmed","count":145},
                            {"value":"in_progress","count":61}, {"value":"fix_applied","count":9} ] },
    "team": { "values": [ {"value":"0193...g1","label":"Network team","count":88} ], "other_count": 12 },
    "signals": { "values": [ {"value":"kev","count":7}, {"value":"exploit","count":19}, {"value":"internet","count":133} ] }
  },
  "capped": false,
  "as_of": "2026-11-11T09:11:40Z",
  "errors": []
}
```

## 5. Saved views and quick views

`GET /api/v1/findings/quick-views` (shipped): built-in views with counts in the caller's scope.

```json
{ "views": [ { "key": "kev_exposed", "count": 7, "params": "is_in_kev=true&state=open" },
             { "key": "sla_overdue", "count": 3, "params": "sla_status=overdue&state=open" },
             { "key": "assigned_to_me", "count": 5, "params": "assignee=me&state=open" } ],
  "include_informational": false, "as_of": "2026-11-11T09:11:40Z" }
```

`GET /api/v1/views?page=findings` (shipped): the caller's and shared saved views. A saved view stores the filter
AST (the URL params are a rendering of it), the sort and the visible columns.

```json
{ "data": [ { "id": "0193...v9", "page": "findings", "name": "Team SLA 72 h", "shared": true,
              "owner": { "id": "0193...u1", "name": "Linh Tran" },
              "filter": { "and": [ { "field": "team", "op": "in", "value": ["0193...g1"] },
                                   { "field": "sla_due_in", "op": "lte", "value": "PT72H" } ] },
              "sort": "-priority", "columns": ["priority", "title", "asset", "sla", "assignee"] } ] }
```

## 6. Finding detail: `GET /api/v1/findings/{id}/view` (shipped; changes planned)

The finding is read first; each part is its endpoint's answer for this caller. Planned: tab-only parts leave the
view (evidence lists, comments, imports) and their counts move onto the finding (`*_count`), so the view holds
what the first screen shows: overview, why it matters, signals, owner and SLA, retest state, approvals,
remediation, ticket links, source records.

```json
{
  "parts": {
    "/api/v1/findings/0193...f1": { "status": 200, "body": {
        "id": "0193...f1", "display_title": "Citrix ADC session token leak", "kind": "vulnerability",
        "cve_id": "CVE-2023-4966", "priority_class": "P0", "priority_class_reason": "kev_internet_exposed",
        "severity": "critical", "status": "confirmed", "sla_deadline": "2026-11-08T00:00:00Z", "sla_status": "overdue",
        "asset": { "id": "0193...a1", "name": "vpn.example.com" }, "assigned_to_user": { "id": "0193...u3", "name": "Sam Rivera" },
        "epss_score": 0.97, "is_in_kev": true, "is_internet_accessible": true,
        "description": "...", "recommendation": "...", "row_version": 17,
        "comments_count": 4, "evidence_count": 3, "sources_count": 2, "activity_count": 23, "related_count": 1 } },
    "/api/v1/findings/0193...f1/verification": { "status": 200, "body": { "plan": "retest_scan", "ready": true } },
    "/api/v1/findings/0193...f1/retest-check": { "status": 200, "body": { "can_retest": true } },
    "/api/v1/findings/0193...f1/approvals": { "status": 200, "body": { "data": [] } },
    "/api/v1/remediation/tasks?sort=updated&finding_id=0193...f1&page=1&per_page=3": { "status": 200, "body": { "data": [], "total": 0 } },
    "/api/v1/findings/0193...f1/ticket-links": { "status": 200, "body": { "data": [ { "system": "jira", "key": "NET-412", "state": "open" } ] } },
    "/api/v1/findings/0193...f1/source-records": { "status": 200, "body": { "data": [ { "source": "Port scanner" }, { "source": "Imported scan file" } ] } },
    "/api/v1/findings/0193...f1/participants": { "status": 200, "body": { "data": [] } },
    "/api/v1/findings/0193...f1/ai-triage": { "status": 403, "body": { "code": "MODULE_NOT_ENABLED", "message": "...", "request_id": "..." } }
  }
}
```

Tabs read their own endpoint on open: Evidence `GET /findings/{id}/evidence-items` (shipped), Activity
`GET /findings/{id}/activities?cursor=` (planned: cursor), Comments `GET /findings/{id}/comments?cursor=`
(planned: pagination and tenant predicate), Sources `GET /findings/{id}/sightings`,
Story `GET /findings/{id}/story`, Related `GET /findings/{id}/duplicate-candidates`. Example, Activity on open:

```json
{ "data": [ { "id": "0193...e1", "type": "status_changed", "actor": { "id": "0193...u3", "name": "Sam Rivera" },
              "from": "new", "to": "confirmed", "at": "2026-11-03T10:02:00Z" } ],
  "next_cursor": "...", "total": 23 }
```

## 7. Inbox: `GET /api/v1/me/inbox/summary` (shipped) + the open queue

```json
{ "queues": { "assigned": 5, "review": 3, "requested": 2, "expiring": 1, "tasks": 1,
              "team": 14, "due_soon": 4, "ready_to_close": 2 },
  "total": 12, "as_of": "2026-11-11T09:11:40Z" }
```

A queue the caller cannot read is absent (`inbox_handler.go`). Planned: `as_of`. The Assigned and My team queues
read the Findings list with a caller-relative filter (`GET /findings?inbox=assigned&sort=sla_deadline`), which
also hides items the caller marked Done or snoozed (a new per-person table; the finding itself stays open), so the
Inbox needs no collection of its own and its rows are the lean rows of example 3. Approvals, Expiring, My tasks
and To close read `GET /approvals?scope=waiting_for_me`, `GET /suppressions?ends_within=30d&mine=true`,
`GET /remediation/tasks?assignee=me` and `GET /findings/closure/proposals` (all exist; the first three need the
filters named). Done and Snooze: `POST /me/inbox/dismiss`, `POST /me/inbox/snooze` (planned).

## 8. Assets list: `GET /api/v1/assets?type=domain&sort=-risk&per_page=50&include=type_counts` (changes planned) + `GET /api/v1/assets/facets` (shipped; planned: read engine and cap) + strip `GET /api/v1/assets/overview` (shipped; planned: from facts)

```json
{
  "data": [
    { "id": "0193...a1", "name": "vpn.example.com", "type": "domain", "category": "external",
      "criticality": "high", "risk_score": 92, "crown_jewel": false,
      "open_findings": { "P0": 1, "P1": 0, "total": 3 },
      "owner": { "id": "0193...g1", "name": "Network team" },
      "tags": ["internet-facing"], "sources": 3, "coverage": "scanned",
      "last_seen_at": "2026-11-11T02:00:00Z", "first_seen_at": "2025-03-14T00:00:00Z", "row_version": 9 }
  ],
  "next_cursor": "...",
  "total": 212,
  "type_counts": { "domain": 212, "host": 640, "web_service": 301, "repository": 88, "cloud": 43 },
  "filters_applied": true
}
```

Strip (SNAP):

```json
{ "total": 1284, "internet_facing": 301, "without_owner": 57, "not_scanned_30d": 41,
  "new_7d": 12, "as_of": "2026-11-11T09:00:00Z" }
```

## 9. Asset detail: `GET /api/v1/assets/{id}/view` (shipped; changes planned)

Same shape as example 6. First-screen parts: the asset, attribution, freshness, coverage, identifiers, top open
findings for the asset (`/findings?asset_id=...&per_page=5&sort=-priority`), owners, relationships summary
(`/assets/{id}/neighborhood?depth=1&limit=20`). Lazy on tab: changes, state history, web evidence, components,
ports, certificates, full relationship map, attribute sources.

```json
{ "parts": {
    "/api/v1/assets/0193...a1": { "status": 200, "body": { "id": "0193...a1", "name": "vpn.example.com", "type": "domain",
        "criticality": "high", "risk_score": 92, "open_findings_count": 3, "relationships_count": 7,
        "changes_count": 14, "ports_count": 3, "row_version": 9 } },
    "/api/v1/assets/0193...a1/coverage": { "status": 200, "body": { "capabilities": [ { "key": "ports", "last_success_at": "2026-11-10T22:00:00Z" } ] } },
    "/api/v1/findings?asset_id=0193...a1&state=open&sort=-priority&per_page=5": { "status": 200, "body": { "data": [ "...lean rows..." ], "total": 3 } }
} }
```

## 10. Dashboard home: `GET /api/v1/me/dashboards/home?choice=org:0193...d1` (shipped; planned: range)

```json
{
  "personal": [ { "id": "0193...d7", "name": "My week" } ],
  "organization": [ { "id": "0193...d1", "name": "CTEM program", "default": true } ],
  "landing": { "kind": "org", "id": "0193...d1" },
  "data": {
    "dashboard_id": "0193...d1", "as_of": "2026-11-11T09:00:00Z", "next_refresh_at": "2026-11-11T09:15:00Z",
    "range": { "key": "30d", "from": "2026-10-12", "to": "2026-11-11" },          // planned
    "layout": [ { "widget_id": "w1", "x": 0, "y": 0, "w": 6, "h": 4 } ],
    "widgets": {
      "w1": { "state": "ready", "kind": "ring", "metric": "findings.open_by_priority",
              "value": { "P0": 5, "P1": 22, "P2": 141, "P3": 250 }, "total": 418,
              "drill": "/findings?state=open" },
      "w2": { "state": "ready", "kind": "kpi", "metric": "sla.within", "value": 0.87, "previous": 0.84,
              "target": 0.90, "met": false, "polarity": "higher_is_better",
              "sparkline": [0.82, 0.83, 0.85, 0.84, 0.87] },
      "w3": { "state": "not_measured", "reason": "too_few_fixed" },
      "w4": { "state": "unsupported", "reason": "forbidden" }
    }
  }
}
```

One widget refresh: `GET /api/v1/me/dashboards/{id}/data?widget=w2&range=90d` (planned) returns
`{ "widgets": { "w2": {...} }, "as_of": ... }`. "Refresh now": `POST /me/dashboards/{id}/refresh` (shipped), then
the `dashboard.refreshed` event.

## 11. Scan run: `GET /api/v1/scan-runs/{id}/view` (planned view over shipped parts) + live

Parts: `/scan-runs/{id}` (shipped), `/scan-runs/{id}/stages` (shipped), `/scan-runs/{id}/events?per_page=20`
(shipped), `/scan-runs/{id}/outputs?summary=true` (shipped; planned: summary counts). The targets table is its own
list (`/scan-runs/{id}/tasks?cursor=`), and the run map is a tab (`/scan-runs/{id}/map`).

```json
{ "parts": {
    "/api/v1/scan-runs/0193...r148": { "status": 200, "body": {
        "id": "0193...r148", "scan": { "id": "0193...s3", "name": "Weekly external" }, "number": 148,
        "state": "running", "outcome": null, "started_at": "2026-11-11T08:30:00Z",
        "counts": { "targets": 1240, "done": 980, "skipped_by_policy": 375, "unreachable": 1,
                    "results": 124, "new": 31, "no_longer_seen": 70, "new_findings": 12 },
        "sensor": { "id": "0193...n1", "name": "edge-sg-1" } } },
    "/api/v1/scan-runs/0193...r148/stages": { "status": 200, "body": { "data": [
        { "key": "discover", "state": "done" }, { "key": "ports", "state": "running", "done": 812, "total": 1240 } ] } }
} }
```

Event on `scan:0193...s3` (extended):

```json
{ "type": "scan_run.progress", "channel": "scan:0193...s3",
  "data": { "run_id": "0193...r148", "state": "running",
            "stages": [ { "key": "ports", "done": 845, "total": 1240 } ],
            "counts": { "results": 131, "new_findings": 13 }, "at": "2026-11-11T09:12:30Z" } }
```

## 12. Settings home: static registry + `GET /api/v1/organization/security-overview` (shipped; planned: snapshot)

The tiles and the settings search need no request: they come from the static page registry in the web build
(the same registry as the menu), filtered by the bootstrap's permissions and modules. Per-area status is not
built (the screen shows none; it would be 20+ reads for little value). The one figure card is the security
overview, served today per request (`no-store`) and changed to a per-tenant snapshot with `as_of`, refreshed on
settings and member events and nightly. Owners and admins only.

```json
{
  "as_of": "2026-11-11T08:00:00Z",
  "score": 82,
  "items": [
    { "key": "admins_without_two_factor", "level": "risk", "count": 1, "href": "/settings/members?two_factor=off&role=admin" },
    { "key": "api_keys_expiring_30d", "level": "warning", "count": 2, "href": "/settings/api-keys" },
    { "key": "sso_not_enforced", "level": "warning", "href": "/settings/authentication" },
    { "key": "integration_failing", "level": "warning", "count": 1, "href": "/settings/integrations" }
  ]
}
```

## 13. Console overview: `GET /api/v1/admin/overview` (shipped; planned: from precomputed rows)

Platform admin plane only (account in no organization). No organization's data content, only counts and health.

```json
{
  "as_of": "2026-11-11T09:00:00Z",
  "organizations": { "total": 1840, "active_30d": 1210, "suspended": 4, "new_7d": 37 },
  "users": { "total": 21430, "active_30d": 9820 },
  "sign_up_requests": { "pending": 6 },
  "sensors": { "platform": 12, "healthy": 11, "silent": 1 },
  "queues": { "ingest_lag_seconds": 4, "dead_letters": 0, "stalled_controllers": 0 },
  "updates": { "current": "0.21.0", "available": "0.21.1" },
  "errors": []
}
```

## 14. Palette search: `GET /api/v1/search?q=vpn&types=finding,asset,cve,scan&limit=5` (planned)

```json
{
  "results": {
    "asset": [ { "id": "0193...a1", "label": "vpn.example.com", "sub": "domain, Network team", "href": "/assets/0193...a1" } ],
    "finding": [ { "id": "0193...f1", "label": "Citrix ADC session token leak", "sub": "P0, vpn.example.com", "href": "/findings/0193...f1" } ],
    "cve": [ { "id": "CVE-2023-4966", "label": "CVE-2023-4966", "sub": "Known exploited", "href": "/vulnerabilities/CVE-2023-4966" } ]
  },
  "errors": []
}
```

A type the caller cannot read is absent (not empty), and no count is given for it.

## 15. Bulk change: preview, apply, operation, undo

```
POST /api/v1/findings/bulk/by-filter/status/preview      (planned as a separate route)
{ "selection": { "filter": { "and": [ { "field": "team", "op": "in", "value": ["0193...g1"] } ] } },
  "args": { "status": "accepted", "reason": "compensating control", "expires_at": "2027-02-11" } }
```

```json
{ "count": 88, "by_status": { "new": 40, "confirmed": 48 }, "warnings": [ { "code": "NEEDS_APPROVAL", "count": 12 } ],
  "sample": [ "...5 lean rows..." ], "preview_token": "pv_...", "expires_at": "2026-11-11T09:22:00Z" }
```

```
POST /api/v1/findings/bulk/by-filter/status        Idempotency-Key: 6f1c...  { "preview_token": "pv_..." }
-> 202 Accepted, Location: /api/v1/operations/0193...o5
```

```json
{ "operation": { "id": "0193...o5", "kind": "findings.bulk_status", "state": "running",
                 "progress": 0.4, "counts": { "succeeded": 35, "failed": 0, "skipped": 0, "total": 88 },
                 "undo_until": "2026-11-12T09:12:00Z" } }
```

`POST /api/v1/operations/0193...o5/undo` (planned) answers another operation that restores each item's prior state;
items changed again since are reported as `skipped`.

## 16. Partial failure inside an aggregate (non-view)

Aggregates that are not views report failed parts by name and still answer 200:

```json
{ "areas": [ "..." ], "errors": [ { "part": "integrations", "code": "UPSTREAM_TIMEOUT", "request_id": "req-8c1..." } ] }
```

The screen shows "Could not load Integrations" on that card only.
