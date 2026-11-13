# RFC-010 — Jira Assets / JSM CMDB integration

- **Status**: Proposed
- **Created**: 2026-06-22
- **Owner**: Platform / Mobilization + Asset Inventory
- **Depends on**: RFC-006 (ticketing provider + mapping). Independent of the
  core issue API already used for ticketing.

## Problem

A customer's authoritative inventory of business context — who owns a system,
its business criticality, environment, compliance scope, upstream/downstream
dependencies — frequently lives in **Jira Service Management Assets** (formerly
*Insight*), Atlassian's CMDB. OpenCTEM discovers the *technical* attack surface
(hosts, domains, cloud, repos) but has no link to that *business* context, so:

1. **Prioritization is context-poor.** A critical CVE on a host OpenCTEM knows
   only as an IP is far more urgent if the CMDB says that host runs the payments
   service owned by the Payments team under PCI scope. Today that mapping is
   manual.
2. **The CMDB drifts from reality.** Assets OpenCTEM discovers (a new subdomain,
   a shadow cloud account) are exactly the rows missing from a hand-maintained
   CMDB. OpenCTEM could push them back.
3. **Tickets aren't linked to CIs.** A remediation ticket created from a finding
   has no link to the configuration item (CI) it concerns, so JSM reporting
   can't roll security work up by service/owner.

> **This is the one place "Jira" and "asset" legitimately intersect.** A Jira
> *project* is a routing destination (RFC-006 config), **not** an asset. A Jira
> *site* can be modeled as a `web_application` asset (ordinary inventory). Jira
> **Assets/CMDB objects**, by contrast, *are* asset records — this RFC is about
> reconciling them with OpenCTEM's asset inventory.

## Why an RFC (decisions required)

1. **License gate.** Jira Assets is **JSM Premium/Enterprise only**. Before any
   build, an operator must confirm their site has Assets enabled and identify
   the **workspace id** (Assets is workspace-scoped, distinct from the Jira
   site). The integration must degrade cleanly (clear "Assets not available on
   this plan" rather than opaque 404s) when it isn't.
2. **Direction.** Pull (CMDB → OpenCTEM enrichment), push (OpenCTEM → CMDB), and
   link (CI ↔ ticket) are independent and separately valuable. We recommend
   **pull-first** (read-only, highest value, lowest blast radius) and treat push
   as opt-in much later.
3. **Schema mapping is per-tenant.** Assets object schemas are customer-defined
   (object types, attributes, AQL). There is no universal "host" type. The
   mapping from an Assets object type → OpenCTEM `AssetType` + which attribute
   carries the hostname/IP/owner must be **configurable per tenant**, with sane
   auto-detection but no hardcoded assumptions.

These are genuinely the operator's call — hence an RFC, not a PR.

## Background — the Assets API (grounded)

Jira Assets is **not** the issue REST API used by RFC-006. Key differences the
design must account for:

- **Workspace-scoped base URL**:
  `https://api.atlassian.com/jsm/assets/workspace/{workspaceId}/v1/...`. The
  workspace id is fetched once from
  `GET /rest/servicedeskapi/assets/workspace`.
- **AQL** (Assets Query Language) is how you list/filter objects, e.g.
  `objectType = "Host" AND "Environment" = "Production"`, posted to
  `.../object/aql` with pagination.
- **Object schemas / types / attributes** are introspected via
  `.../objectschema/list`, `.../objecttype/{id}/attributes`. Attribute values
  are typed (text, reference, status, user).
- Auth reuses the **same per-tenant credentials** as the ticketing integration
  (Atlassian account email + API token, basic auth) — no new secret scheme.

## Proposed design

### Reuse, don't rebuild

- **Credentials / tenant isolation**: reuse `ProviderJira` integration records
  and the per-tenant resolver pattern from RFC-006
  (`internal/infra/jira/resolver.go`). One Assets client per tenant, built from
  that tenant's connected Jira integration. **Never** trust a workspace/tenant
  id from a payload — derive tenant from the authenticated context, workspace
  from the tenant's own integration config (mirrors the ticketing tenant-
  isolation invariant).
- **Asset write path**: reuse the existing asset upsert + identity-resolution
  pipeline (`internal/app/ingest` correlator, `pkg/domain/asset` normalization).
  CMDB objects flow in as a new **discovery source** (`integration`/`jira_assets`),
  *not* a bespoke table.
- **SSRF**: all Assets HTTP via `httpsec.SafeHTTPClient`, as the issue client
  already does.

### New surface

```
pkg/domain/assetcmdb/            mapping config (object-type → AssetType, attr keys)
internal/infra/jira/assets.go    Assets API client (workspace lookup, AQL, schema introspect)
internal/app/assetcmdb/          reconcile service (pull → upsert assets; enrich; optional push)
internal/infra/http/handler/     assets_cmdb_handler.go (config, manual sync, schema discovery)
migrations/                      cmdb_object_links (asset_id, workspace_id, object_id, object_key)
```

### Phasing

- **10a — Assets client + discovery (read-only).** Workspace lookup, AQL list
  with pagination, schema/attribute introspection, `TestConnection`. A discovery
  endpoint returns the tenant's object schemas/types so the admin can map them.
  No writes to OpenCTEM yet. Fully unit-testable with fixtures (no live JSM).
- **10b — Mapping config + pull/enrich.** Per-tenant `assetcmdb` mapping
  (object type → `AssetType`; which attributes carry hostname/IP/owner/
  criticality/environment/compliance). A reconcile job pulls objects via AQL and
  **upserts/enriches** assets through the existing ingest pipeline: match by
  hostname/IP (correlator), set `ownerRef`, `criticality`, `complianceScope`,
  store `object_key` in `cmdb_object_links`. Read-only toward Jira.
- **10c — CI ↔ ticket link.** When a finding's ticket is created (RFC-006), if
  its asset has a linked CMDB object, set the issue's CI field / add the object
  link so JSM reporting rolls security work up by service. Read-only toward the
  CMDB schema (links only).
- **10d — Push discovered assets (opt-in, deferred).** Create/update CMDB
  objects for assets OpenCTEM discovered that are absent from the CMDB. **Off by
  default**, behind an explicit per-integration switch and a target object type,
  with a dry-run/report mode first — writing to a customer's system of record is
  high blast-radius.

### Security & correctness non-negotiables

- **Tenant isolation**: workspace id and credentials come only from the calling
  tenant's own integration; reconcile is scoped `WHERE tenant_id = ?`. A CMDB
  object never crosses tenants.
- **Pull never deletes.** Enrichment only sets/updates context; it must not
  auto-archive OpenCTEM assets just because they're absent from a (partial) AQL
  result — mirrors the batch-scoped auto-resolve invariant from RFC-007.
- **Push is opt-in + dry-run-first** (10d), never the default.
- **License/feature detection** is explicit: a non-Premium site returns a clear
  "Assets not enabled" state, not a 5xx.

## Out of scope

- Replacing OpenCTEM's asset inventory with the CMDB (we enrich + reconcile,
  not delegate).
- Bi-directional real-time sync (start with scheduled reconcile + manual run).
- Modeling Jira *projects* as assets (they are routing destinations — see
  RFC-006 / `docs/architecture/ticketing-integration.md`).

## Alternatives considered

- **Manual CSV import of CMDB context** — works once, but drifts immediately and
  doesn't link CIs to tickets. The API integration keeps context live.
- **Treat the CMDB as the asset source of truth (pull-only mirror)** — rejected:
  OpenCTEM discovers assets the CMDB doesn't have; reconciliation (both know
  things the other doesn't) is the correct model, not replacement.

## Open questions

- Reconcile cadence + cost: AQL pagination over a large CMDB — scheduled
  (reuse the integration sync interval) vs on-demand vs webhook (Assets has
  limited webhook support).
- Match key when an Assets object has neither hostname nor IP (e.g. a logical
  "Service" object) — link via owner/name, or only link when a technical
  identifier exists?
- Conflict policy when CMDB criticality disagrees with OpenCTEM's computed
  criticality — CMDB wins for *business* criticality, OpenCTEM keeps *risk*
  score; surface both rather than overwrite.

## Where it lives

```
docs/rfcs/RFC-010-jira-assets-cmdb.md      this document
docs/architecture/ticketing-integration.md  (Jira project ≠ asset; site = asset; CMDB = this RFC)
internal/infra/jira/                        existing per-tenant resolver + issue client (reused)
```

Conventions: PRs target `develop`; phased PRs reference this RFC number.
