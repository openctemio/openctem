# Change detection: what changed in the attack surface

CTEM Discovery is continuous, so the question operators ask most is not "what
do we have" but "what changed". This document covers the three pieces that
answer it: the state-history record, the `asset_discovered` / `scan_completed`
workflow triggers, and the throttled new-internet-facing-asset notification.

## 1. The record: `asset_state_history`

Append-only (UPDATE is blocked, DELETE of rows under 30 days is blocked). The
"What changed" UI page (Discovery > What changed, `/assets/changes`) reads it
through the `/api/v1/state-history/*` endpoints.

| View | Endpoint | Rows | Written by |
|---|---|---|---|
| Appeared | `/appearances` | `appeared` | ingest, for every asset it inserts (report assets, auto-created root domains, DNS-resolved IPs); manual create |
| Disappeared | `/disappearances` | `disappeared` (field `status`, active to stale) | asset lifecycle worker, when no scan has seen the asset within the stale threshold |
| Newly exposed | `/newly-exposed` | `exposure_changed` to `public`, `internet_exposure_changed` to `true` | ingest re-scan merge; manual exposure edit |
| Exposure changes | `/exposure-changes` | every `exposure_changed` / `internet_exposure_changed` | same |
| Shadow IT | `/shadow-it` | `appeared` rows of assets currently in scope `shadow` | derived (asset scope) |

All five share one parameter set: `from`/`to` (or legacy `since`), `limit`/
`offset` with a real `total`, and `internet_facing=true|false` (asset is
currently `is_internet_accessible` or exposure `public`). Each row carries the
asset's current `asset_name`, `asset_type`, `asset_exposure`, `asset_scope` and
`asset_internet_accessible`, loaded with one tenant-scoped query per page.

Before this change several views could never show anything: nothing wrote
`disappeared` or `exposure_changed`, the single `change_type`/`source` filters
were ignored by the repository (so `/appearances` returned every change type),
`/newly-exposed` included assets that stopped being exposed, `/shadow-it`
reported `total` as the page length, and the asset upsert dropped the exposure
ingest inferred for a re-scanned asset still at `unknown` (it now fills that
gap, and never overrides a known exposure).

## 2. Workflow triggers

| Trigger | Fired from | Payload |
|---|---|---|
| `asset_discovered` | `ingest.AssetProcessor.ProcessBatch` via the discovered callback, wired in `cmd/server/services.go` | `asset` (first), `assets` (up to 100), `asset_count`, `internet_facing`, `internet_facing_count`, `truncated` |
| `scan_completed` | `scanrun.Service.finishRun` when a run settles `completed`, `partial` or `failed` | `scan.{run_id, scan_workflow_id, scan_id, status, trigger_type, total_findings, completed_at}` |

`asset_discovered` fires only for assets an ingest actually inserted: not for a
re-scan merge, and not for a local asset whose insert lost a concurrent-create
race (`UpsertBatch` returns the persisted id; a mismatch means the row already
existed). It does not fire on manual create: an operator creating an asset by
hand already knows about it, and "discovered" is what automation keys on.

Each matching workflow runs **once per ingest batch** with the batch in the
payload, not once per asset. Trigger filters: `internet_facing_only` (bool) and
`asset_type_filter` (list of asset types).

`scan_completed` takes `status_filter`, a list of the run outcomes it runs on
(`completed`, `partial`, `failed`). Without one it fires on `completed` runs
only, so an automation written for a successful scan never starts on a failed
one; "scan failed: alert" is `{"status_filter": ["failed", "partial"]}`. Any
other value is refused on save (`INVALID_TRIGGER_CONFIG`). A canceled run fires
nothing.

## 3. Notification: new internet-facing assets

`internal/app/assetdiscovery.Notifier` receives two ingest callbacks:
newly created assets, and existing assets a re-scan turned internet-facing. It
keeps the internet-facing ones and emits, per tenant:

- an in-app notification (`asset_discovered`, audience: whole tenant), and
- an outbox event `new_asset`, delivered to the tenant's notification
  integrations (Slack, Teams, email, webhook, Splunk HEC) that enabled it.
  `new_asset` is exempt from the per-integration severity filter: its severity
  is a fixed label, not a finding severity.

Throttle, per tenant: the first discovery notifies immediately and opens a
15-minute window; everything arriving during the window is buffered
(deduplicated by asset id, at most 10 named, all counted) and sent as one
summary when the window closes, which opens the next window. An empty window
returns the tenant to idle. A recon run that creates 5,000 assets across 200
batches therefore produces two notifications, not 5,000.

Limits, by design: state is in memory per API process (N replicas can send up
to N per window), and a buffered summary is flushed on graceful shutdown but
lost on a hard kill. The state history above is the durable record either way.
