# RFC-112: Asset technologies (detected technology fingerprint per asset)

| | |
|---|---|
| Status | Accepted (2026-10-16). Being implemented in small PRs; §9 lists what has shipped |
| Scope | api (asset_technologies table, ingest, `GET /assets/{id}/technologies`, asset list filters, backfill controller), web (Technologies section and tab, Software tab wording, list filters) |
| Related | RFC-066 (software inventory and CVE matching), RFC-069 (attribute reconciliation, set attributes), `docs/architecture/asset-technologies.md` |

## 1. Problem

Web probes (httpx, other fingerprinting tools) report what they recognise on a host: the web server,
the framework, JavaScript libraries, the CDN and hosting platform in front of it, analytics tags and
security headers. Until now every one of these detections was turned into a software component
(RFC-066). A security header ("HSTS") and a hosting platform ("Vercel") showed on the Software tab as
"version unknown · Unrecognised · confidence 50 · No CVEs": noise in the component list, a private
catalog product per name, and no place that answered "what is this host built with?".

## 2. How attack surface tools present a technology fingerprint

Surveyed in local research: products in this space show a host's fingerprint as **chips grouped by
category** (web server, framework, CMS, JavaScript library, CDN, hosting, WAF, analytics), with the
version when the probe could tell, and **first and last seen**. Every technology is a pivot: "all my
assets running X" and "all assets behind CDN Y" are one click from the chip and a filter on the asset
list. CVE matching runs only on detections that name a product and a version (or a CPE); a versionless
or non-software detection is a fact, never a vulnerable component. Security headers are presented as
HTTP security posture, not as software. Categories come from the tool's taxonomy mapped to a short,
fixed list the console can group and filter on.

## 3. Decision

1. **Every detection is an asset technology** (`asset_technologies`, one row per asset and normalised
   name): display name, optional version, a category from a closed set, the tool's confidence (0 when
   the tool gives none), the source tool, first and last seen.
2. **Closed category set** (`pkg/domain/assettech`): `web_server`, `framework` (framework or CMS),
   `language` (language or runtime), `js_library`, `cdn`, `hosting` (hosting or PaaS), `waf` (WAF or
   security service), `analytics` (analytics and marketing), `security_header`, `other`. A curated name
   list decides first (it knows HSTS is a header whatever a tool files it under); otherwise the tool's
   own categories are mapped (both "Web servers" and "web-server" spellings); otherwise `other`.
3. **Kinds.** `cdn`, `hosting` and `waf` are infrastructure facts; `security_header` is an HTTP security
   fact; `analytics` is marketing; the rest are software.
4. **Only software becomes a component.** A detection is also a software component (CVE matching) only
   when its kind is software and it has a version or a CPE (`IsSoftwareCandidate`). HSTS, Vercel,
   Cloudflare and a versionless nginx are technologies only.
5. **One store: the rows are the reconciled set.** Technologies reconcile per source (RFC-069): the
   per-source elements are the evidence, and the resolved set is written as `asset_technologies` rows
   in the same transaction (one row per name; when sources disagree on a version, a known version
   beats none and the higher version wins). `assets.properties.technologies` is retired: never
   written, never read (a guard test fails on any read). Ingest then adds what the report knew (the
   tool's category and confidence, the source, the last sighting) to rows that exist; it never adds
   one. A full fingerprint probe that no longer sees a technology removes it.
8. **Technologies and software are not duplicates.** The software catalog (`software_products` →
   `software_versions` → `asset_software`) is the one CVE-matchable entity: packages from SBOM/SCA/CI,
   installed products, service banners. A technology fingerprint is a fact about the asset with a
   category; only a versioned or CPE-identified software detection also becomes a component, so the
   catalog never holds a product per security header or hosting name. Per-endpoint technologies
   (`web_endpoints.technologies`) stay: they describe one path, not the asset.
6. **No new findings.** Security headers are recorded as present. Raising a finding for a *missing*
   header needs a probe that reports response headers and a rule; neither exists yet, and a technology
   probe that does not mention a header is not evidence that it is missing.
7. **Existing data.** A migration copies each asset's `properties.technologies` into
   `asset_technologies` (one `INSERT ... SELECT`, no lock on `assets`). A backfill controller then
   classifies the copied rows, removes the retired key (tags are left alone: a tag carries no origin, so
   a person's tag cannot be told from one the old converter added; new reports no longer create them)
   and removes component links that ingest no longer creates, tenant by tenant in batches of 500, without long locks. Only a technology link with no usable version (`CleanVersion` is
   empty) and no CPE is ever removed; a versioned or CPE-backed link stays whatever its category, and
   the delete statement repeats that rule. A link that is an end of a dependency edge is skipped. Every
   deleted link is recorded in `asset_technology_backfill_removed`. The first run is report-only
   (`ASSET_TECHNOLOGY_BACKFILL_REPORT_ONLY`, default `true`): it logs the count and a sample of the links
   it would remove and deletes nothing; an operator sets it to `false` to enforce, and tenants that
   were only reported are processed again.

## 4. API

- Asset responses (list, single, `/full`) embed `technologies` (name, version, category): at most 20
  per asset on a list, all of them on one asset.
- `GET /api/v1/assets/{id}/technologies` (`assets:read`): the asset's technologies with category, kind,
  version, confidence, source, first and last seen. The asset must be the caller's tenant's and in the
  caller's data scope; both misses answer 404.
- `GET /api/v1/assets?technology=nginx,next.js&technology_category=cdn,hosting`: assets using any of the
  named technologies (normalised names, at most 20) and assets with any technology in the categories.
  Both are tenant- and data-scope-filtered like every other list filter.

## 5. Security

- **Threat:** sensor and import output is untrusted. Names are trimmed, rejected on control characters,
  invalid UTF-8 or more than 128 bytes; versions over 64 bytes or with control characters are dropped;
  confidence is clamped to 0-100; the source is cleaned and capped at 100 bytes. One report records at
  most 100 technologies per asset and 5000 in all. The console renders every value as text.
- **Tenant isolation:** the tenant comes from the authenticated sensor or user. Every query carries
  `tenant_id`; inserts select the asset from the tenant's own assets, so an asset id from another tenant
  writes nothing. The read endpoint checks the tenant and the data scope (404 on either miss).
- **Filters** are bound parameters, capped at 20 values, and run inside the existing scoped list query.

## 6. Data model

`asset_technologies (tenant_id, asset_id, name_key, name, version, category, confidence, source,
first_seen, last_seen)`, primary key `(tenant_id, asset_id, name_key)`, foreign key to the asset
(cascade), indexes on `(tenant_id, name_key)` and `(tenant_id, category)`. An asset merge keeps the
kept asset's row for a name. `asset_technology_backfill` records the tenants the backfill has done (and whether removal was enforced); `asset_technology_backfill_removed` records each deleted link.

## 7. Console

- Asset overview: a **Technologies** section, chips grouped by category with the version when known, a
  tooltip with confidence, source and last seen; a **Technologies** tab lists every row.
- Software tab: only real components. A product without a CPE match reads "No CPE match: CVEs not
  checked" with a tooltip explaining why.
- Asset list: filters "Technology" and "Technology category".

## 8. Not doing

- No per-tenant category overrides or custom categories.
- No missing-header findings (see §3.6).
- No icons per technology (a remote icon set would be a third-party fetch from the console).

## 9. Status

| PR | Content | State |
|---|---|---|
| 1 | model, ingest, read endpoint | #2413 |
| 2 | backfill and cleanup of non-software component links | #2415 |
| 3 | one store: rows are the reconciled set, property retired, responses embed technologies | open |
