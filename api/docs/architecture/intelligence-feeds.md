# Intelligence feeds: status model

The platform keeps three platform-wide feeds that every organization's prioritization reads: EPSS scores,
the CISA KEV catalog, and the signed vulnerability bundles. Each has one row in `threat_intel_sync_status`.
This page describes what the platform admin console and the organization routes report about them.

## What the server computes

`internal/app/feedstatus` turns a status row into one `View`:

| Field | Meaning |
|---|---|
| `state` | `up_to_date`, `waiting_for_publisher`, `stale`, `failing`, `refused`, `running`, `off` |
| `error_code`, `error_params` | the last failure, classified (below); the console translates it |
| `last_attempt_at`, `last_success_at`, `failing_since` | a failed attempt does not move the success time; `failing_since` is the start of an unbroken run of failures |
| `next_run_at` | last attempt plus the scheduler's own interval, never in the past |
| `catalog_records`, `records_changed` | size of the stored catalog, and what the last run wrote |
| `data_as_of` | EPSS: the score date; vulnfeed: when the applied bundle was created; KEV: the last successful check |
| `detail` (vulnfeed) | applied sequence, key set version, root key id, bundle age, and per-source freshness |

The success time, the failure start and the error code live in the row's `metadata` (no schema change).

### States

| State | Rule |
|---|---|
| `off` | scheduled sync is switched off |
| `running` | the row says running and was updated within the hour (a longer "running" is an interrupted run) |
| `waiting_for_publisher` | the key set or pointer answered 404 and no bundle was ever applied; turns `stale` after 3 days |
| `refused` | a signature, key set, sequence, expiry or size guard refused what was offered |
| `failing` | the last attempt failed and the data is not yet stale |
| `stale` | data older than the threshold: bundle 3 days, KEV 6 hours, EPSS 48 hours |
| `up_to_date` | none of the above |

### Error codes

`publisher_empty`, `unreachable`, `http_status`, `signature_invalid`, `keyset_rollback`, `sequence_rollback`,
`expired`, `bundle_invalid`, `guard_refused`, `empty_feed`, `not_configured`, `disabled`, `interrupted`, `failed`.
Fetchers return typed errors (`feedstatus.HTTPError`, `GuardError`, `Tag`); the bundle verifier reports by
message and is classified by `TagVerify`.

## Who sees what

- `GET /api/v1/admin/threat-intel/sync` (any platform admin): the full view, including the raw `last_error`.
- `GET /api/v1/threat-intel/sync`, `/sync/{source}` and `/stats` (organizations): state and freshness only. No
  error text, host, status code or bundle internals: a failed fetch can name hosts and paths.
- `POST /api/v1/admin/threat-intel/sync` (ops_admin+, audited): runs `epss`, `kev`, `vulnfeed` or `all`. It
  always answers 200 with one result per feed (`success`, `error`); a feed that is switched off or not
  configured is reported as failed.

## Fetch rules

- A KEV 304 keeps the stored count (and fills a count an earlier run left at zero).
- A 200 with no entries (an empty or renamed `vulnerabilities` array, an empty EPSS file) is a failure and
  its cache validators are not stored.
- KEV and EPSS refuse a snapshot under 90% of the stored catalog.

Shipped: all of the above. Designed, not shipped: the bundle carrying KEV and EPSS, direct fetch as a fallback.
