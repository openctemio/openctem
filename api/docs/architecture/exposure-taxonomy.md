# Exposure taxonomy and monitoring state

How the external attack surface presents exposures and assets: a fixed display
category per exposure type, a one-line description, an `in_progress` state, the
analyst severity override, and one derived monitoring state per asset.

Status: **shipped** (display categories, summaries, `in_progress`, severity
override, monitoring state). Producers for three of the new exposure types are
**planned** (see "Planned").

Key files:

- `pkg/domain/exposure/display.go`: display categories, `SummaryOf`.
- `pkg/domain/exposure/severity_override.go`: override, restore, provenance.
- `pkg/domain/exposure/value_objects.go`: event types, states and transitions.
- `internal/app/exposure/taxonomy.go`: `StartProgress`, `ChangeSeverity`, category filter and counts.
- `pkg/domain/asset/monitoring_state.go`: monitoring states and their precedence.
- `internal/infra/postgres/asset_scope_status.go`: `assetMonitoringStateSQL`, `MonitoringStates`.
- Migration `20261030200514_exposure_taxonomy_progress_severity`.

## Display categories

`exposure.EventType` stays the taxonomy. Each type maps to exactly one display
category, so the "by type" counts on the Exposures view are stable:

| Category | Event types | Producer today |
|---|---|---|
| `exposed_ports` | `port_open`, `port_closed`, `service_detected`, `service_changed` | port scans |
| `web_interfaces` | `web_interface_exposed` | planned |
| `exposed_apis` | `api_exposed`, `api_removed` | API discovery |
| `ai_services` | `mcp_server_exposed` | planned |
| `web_application` | `misconfiguration`, `header_missing` | web scans |
| `ssl_tls` | `ssl_issue` (a certificate authority problem is a reason of `ssl_issue`) | TLS checks |
| `certificates` | `certificate_expiring`, `certificate_expired` | certificate monitoring |
| `hijackable_subdomains` | `dangling_cname`, `dangling_ns`, `subdomain_takeover` | EASM DNS checks, takeover templates |
| `email_security` | `email_security_weak`, `mail_server_blocklisted` | SPF and DMARC checks; blocklist planned |
| `cloud_storage` | `bucket_public`, `bucket_private` | planned |
| `code_repositories` | `repo_public`, `repo_private` | planned |
| `credentials_data` | `credential_leaked`, `sensitive_data_exposed` | credential imports |
| `dns` | `subdomain_discovered`, `subdomain_removed`, `dns_change` | discovery |
| `lookalike_domains` | `lookalike_domain` | lookalike monitoring |
| `identity` | `identity_mfa_gap`, `identity_stale_principal`, `identity_overprivileged` | identity sources |
| `other` | `custom` and any unknown type | imports |

`exposure.Categories()` marks which categories have a producer (`Produced`).
The web shows a category in the summary strip only when it has a producer or
exposures, so empty placeholders never appear.

API: every exposure carries `display_category`; `GET /exposures?category=` filters
by category (ANDed with `event_type`; an unknown category is a validation
error); `GET /exposures/stats` returns `by_category`.

## One-line summary

`exposure.SummaryOf` renders a sentence from the type and the details, for
example "Port 6379 (Redis) is open to the internet". The API returns
`summary: {text, variant, args}`: the English text, plus the variant (which
sentence form was used) and the values, so the web renders the same sentence in
the viewer's language with `exposures.summary.<type>[.<variant>]` keys. Details
come from producers and are untrusted: only strings and whole numbers are used,
control characters are removed, each value is capped at 120 characters, the
summary is built from the redacted details (a leaked secret never reaches it),
and clients render it as text. Without the values a sentence needs, the
summary is the title.

## The in_progress state

`in_progress` means someone is working on the exposure; it is still open.
Transitions: `active ⇄ in_progress`, and either to `resolved`, `accepted` or
`false_positive`. `POST /exposures/{id}/start-progress` (`findings:write` and
`findings:exposures:triage`) sets it; `POST /{id}/reactivate` moves it back to
active. Every reader of open exposures counts both states
(`exposure.OpenStates`, `OpenStatesSQL`): the risk snapshot, the EASM summary,
the asset merge rank, the EASM alert reappearance check, and every automatic
resolution (closed port, rejected name, DNS check), which records the state the
exposure was really in.

## Severity override

`PATCH /exposures/{id}/severity` with `{severity, reason}` sets the effective
severity as an analyst decision; an empty `severity` removes the override. It
needs `findings:severity` and `findings:exposures:triage`, a reason (at most
1000 characters), and is audited as `exposure.severity_changed`.

Storage: `exposure_events.severity` stays the effective severity, so every
filter, count and dashboard is unchanged. Next to it, `source_severity` (what
the producer reported while an override stands), `severity_override_reason`,
`severity_overridden_by` and `severity_overridden_at` (NULL = no override).
A re-sighting while an override stands updates `source_severity` only, so a scan
never reverts the analyst.

Threat model:

- *Hiding risk by lowering severity.* The reported severity is kept and shown
  next to the override; the change needs a reason and is audited.
- *Lowering severity to skip the second approver.* The four-eyes rule on
  accepting or dismissing a high or critical exposure reads the peak severity,
  which only rises: an override pins the peak first, the stored peak is raised
  to the highest of the stored peak, the severity before the change and the
  reported severity, and re-sightings keep raising it.
- *Cross-tenant or out-of-scope change.* The exposure is loaded by tenant and id
  and checked against the caller's data scope; another tenant's exposure, or one
  on an asset outside the caller's scope, answers 404 and is not changed (DB
  tests `TestExposureTaxonomy_*`, `TestDataScope_*`).

## Monitoring state

One derived state per asset, computed in SQL beside the scope status; nothing is
stored. The first matching rule wins:

| State | Derived from |
|---|---|
| `irrelevant` | attribution `rejected`, or an in-effect `not_ours` exclusion |
| `out_of_scope` | an in-effect `do_not_scan` or `retired` exclusion |
| `inactive` | asset status `inactive` or `archived` |
| `pending_decision` | attribution `needs_review` |
| `unvalidated` | attribution `candidate`, or `discovered` below confidence 90 |
| `not_monitored` | attribution `monitor_only`, or no scope entry covers it (`not_covered`) while the organization does not scan unclassified assets |
| `monitored` | everything else (in scope, internal, or unclassified and scanned) |

An asset without an attribution record counts as confirmed. "Scans unclassified
assets" is the organization's unclassified-scans mode as the active-scan gate
applies it (Strict approval mode and an unreadable setting count as off, so an
unknown answer labels an asset not monitored, never monitored).

API: `GET /assets?monitoring_state=` filters (comma list); with
`?with_triage=true` each row carries `monitoring_state`. The Go form
(`asset.MonitoringStateOf`) and the SQL form are checked against each other on
every rule (`TestAssetMonitoringState_SQLMatchesDomain`). Every subquery is
pinned to the asset's tenant; the list's data scope applies as for every other
asset filter.

## Exposure Items view

Attack surface > Exposure items (`/attack-surface/exposures` in the web console)
is every exposure of the organization with the asset it is on, one table:

- `GET /api/v1/attack-surface/exposures` lists exposures through the list query
  contract (registry `exposure_items`, `pkg/domain/exposure/items.go`): filters
  `severity`, `state`, `event_type`, `category` (the display category),
  `source`, `asset_id`, `asset_name`, `asset_type`, `asset_monitoring_state`,
  `primary`, `severity_overridden`, `first_seen`, `last_seen`, a search over
  the title and the asset name, and sorts on `severity` (by rank), `state`,
  `event_type`, `asset_name`, `first_seen`, `last_seen`. Each row is the
  exposure response plus `asset_name`, `asset_type`, `asset_monitoring_state`
  and `asset_primary`.
- `GET /api/v1/attack-surface/exposures/stats` counts the same filtered set by
  severity, display category and state (the summary strips).
- `GET /api/v1/attack-surface/exposures/assets` folds the filtered set into one
  row per asset (counts per severity, highest severity, first and last seen),
  most severe first: the group-by-asset view. Exposures without an asset are
  left out of it.

All three need `findings:read` and `findings:exposures:read` (the gate of
`GET /exposures`) and the attack surface module. The web console opens on the
open exposures (active and in progress) of monitored assets; the filters can
widen to every state and every asset. Writes are the typed exposure commands
(`start-progress`, `resolve`, `accept`, `false-positive`, `reactivate`,
`PATCH /severity`), so the four-eyes rule and the audit log apply unchanged; the
severity cell opens the override dialog for a caller holding `findings:severity`
and exposure triage. The export is the CSV of the filtered list (at most 2000
rows, every cell formula-safe).

**Isolation.** Every read compiles the filter for the caller
(`filterspec.CompileFrom`): the tenant predicate first, then the data scope on
the exposure's asset, so a member sees only the exposures of assets in their
scope and an exposure without an asset (a leaked credential) reaches
unrestricted callers only. The asset join and every subquery of the
monitoring state and the primary marker carry the exposure's tenant. The
monitoring state needs the tenant's unclassified-scans mode, which the handler
resolves from the active-scan gate and binds as `$1` (unknown counts as not
scanned, so nothing is labeled monitored by mistake); the per-row state join
is only added when a filter or sort reads it.

**Primary assets.** A primary asset is one of the organization's root
domains: a domain asset named exactly like the root of a permanent, active
domain scope entry (`example.com` or `*.example.com`) or like a verified
domain (`asset.PrimarySQL`). The list marks it with a star and filters on it
(`primary=true`).

## Planned

- Producers for `web_interface_exposed` (exposed login and administration
  pages), `mcp_server_exposed` (a fingerprint on open ports) and
  `mail_server_blocklisted` (DNS blocklist lookups of mail server addresses),
  and for public storage buckets and repositories. The types exist so the
  categories and filters are stable.
- DKIM in the email checks.
- `inactive` from 30 days of NXDOMAIN.
- An inline monitoring control and scoping decision cards built on the state.
