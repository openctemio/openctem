# RFC-070: Software components inventory

| | |
|---|---|
| Status | Accepted (2026-10-10; decisions C1–C10 adopted as recommended, §14; the owner may revise any of them). P0 in implementation |
| Scope | api (`pkg/domain/software`, `pkg/domain/component`, `internal/app/asset` component and SBOM services, ingest, `internal/infra/postgres` component/software repositories, migrations, routes), web (`/components`, the component detail page, dependency graph, SBOM import and export) |
| Architecture | [software-components.md](../architecture/software-components.md) |
| Related | RFC-066 (software catalog, matcher; O6 one inventory model, O11 catalog sharing, O12 feed outside the platform), RFC-069 (asset change timeline), RFC-064 (modules), ADR-004 (finding provenance), [finding-import.md](../architecture/finding-import.md) (VEX documents), [global-catalog-trust.md](../architecture/global-catalog-trust.md), [component-relationship-best-practices.md](../architecture/component-relationship-best-practices.md) |

## 1. Summary

`/components` is the inventory of the open-source and third-party packages the
organization's repositories, container images, hosts and applications are
built from. It answers four questions quickly:

1. **What do we run?** Every package, the versions in use, where each version
   is used, whether it is a direct or a transitive dependency and in which
   scope (runtime, development, test).
2. **What is wrong with it?** Known vulnerabilities per version, with severity,
   KEV, EPSS and whether a fixed version exists; license policy violations;
   health (outdated, deprecated, end of life).
3. **What do we do about it?** The upgrade that fixes it, the dependency path
   that brings it in, and a VEX statement when the organization is not
   affected.
4. **What can we hand over?** An SBOM (CycloneDX 1.6, SPDX 2.3) per asset,
   with the organization's VEX statements.

This RFC makes components **package-level entries of the RFC-066 software
catalog** instead of a parallel table: one product per package URL (purl)
identity, one version row per version, one per-tenant link per asset and
location, plus the dependency edges between links. The legacy `components`
and `asset_components` tables are migrated and dropped.

## 2. Current state (develop fe5c192e3, 2026-10-10)

- `components` is a **global** table (`purl`, `name`, `version`, `ecosystem`,
  `description`, `homepage`, `vulnerability_count`): one row per purl@version,
  shared by every tenant and created from any tenant's observation.
  - A tenant's private package (`pkg:npm/@acme/internal-auth@1.2.0`) becomes a
    global row.
  - Its `description` and `homepage` come from whichever tenant reported the
    package first, and every other tenant reads them.
  - Both contradict RFC-066 O11 (global rows only for public identities).
- `asset_components` is the per-tenant where-used row: asset, `component_id`,
  one `parent_component_id`, `depth`, `dependency_type`, a free-text
  `license`, manifest fields, `branch_id` (never written by ingest) and cached
  counters (`vulnerability_count`, `has_known_vulnerabilities`,
  `highest_severity`, `risk_score`) that only some paths keep current.
- `findings.component_id` references `components(id)`; finding groups, the VEX
  document matcher, finding re-keying and component CVE queries join
  `components` for the purl.
- The RFC-066 catalog (`software_products`, `software_product_aliases`,
  `software_versions`, `asset_software`) holds CPE products captured from
  technology, service and OS observations; its purl columns are unused.
- Ingest: CTIS `report.Dependencies` (sensor SCA tools such as trivy and
  osv-scanner, CI uploads), `POST /components/import` (CycloneDX or SPDX JSON,
  synchronous, 50 MB, rate limited) and finding import (CycloneDX SBOM, VDR,
  VEX, SPDX, OpenVEX, CSAF). Finding import applies VEX documents to existing
  findings once (`findings.vex_*`); nothing applies a statement to a finding
  that appears later.
- Export: `GET /components/sbom` builds CycloneDX 1.6 and SPDX 2.3.
- Licenses: the global `licenses` SPDX catalog (category, risk) is seeded; the
  observed license is a string on `asset_components`; there is no policy.
- Web: `/components` with five sub-pages (all, vulnerable, ecosystems,
  licenses, SBOM export), aggregation done in the browser on one page of rows,
  a detail sheet, English strings in components.

## 3. Goals and non-goals

Goals:

- G1. One inventory model: packages live in the RFC-066 catalog; `/components`
  and the asset Software tab read the same rows.
- G2. No tenant's observation creates or edits a global row (§4).
- G3. Where-used across every asset type, with all dependency paths, direct or
  transitive, scope, location, first and last seen, and the channel that
  reported it.
- G4. Vulnerabilities per version: scanner and SCA findings merged on the
  version, the RFC-066 matcher for versions the corpus covers, EPSS and KEV,
  fixed versions and upgrade advice.
- G5. Persisted VEX statements that apply to existing and future findings,
  with audit.
- G6. License policy (allow, review, deny) with violations as findings.
- G7. Health: latest version, outdated by N, deprecated, end of life, from the
  vulnerability feed bundle when it carries them; the hook exists before the
  data does.
- G8. Server-side list with filters, facets, sorting and pagination; detail,
  versions, where-used, paths, bounded graph; SBOM import with preview and
  validation; SBOM export per asset.
- G9. Every query is tenant scoped and limited to the caller's data scope.

Non-goals (later phases, §13): reachability analysis, provenance and
attestation verification, typosquat detection, registry calls from the
platform (the platform never calls package registries; O12 of RFC-066),
automatic upgrade pull requests.

## 4. Threat model

| Threat | Control |
|---|---|
| T1. A tenant's private package name or version reaches another tenant | Packages from observations are **tenant-private** catalog rows (`source = observed`, `tenant_id` set). A global package product exists only when the vulnerability feed names it (`source = osv`). The catalog is never listed; every API reads products through the caller's links. |
| T2. A tenant writes into a global row (catalog poisoning: description, homepage, license, "latest version") | Observations never update global rows. Package metadata observed in an SBOM is stored on the tenant's link (`asset_software.licenses`) or the tenant-private product, never on a global product. Global metadata comes only from verified feed bundles. |
| T3. Cross-tenant reference by id (a finding, VEX statement or edge pointing at another tenant's version or link) | The catalog scope trigger (RFC-066) is extended to `findings.component_id`, `vex_statements` and `asset_software_edges`: a reference must be global or in the row's own tenant. Edges also carry `tenant_id` and `asset_id` and both ends must be links of that asset. |
| T4. A member reads components of assets outside their data scope | Every list, facet, count, detail, path and graph query joins the caller's accessible assets (`DataScopeAssets`). A product or version with no in-scope link and no in-scope finding answers 404, the same as a missing one. Facets and KPIs count only in-scope rows. |
| T5. Hostile SBOM (size, depth, cycles, decompression, malformed purls, XML entities) | 50 MB body cap, 100 000 components and 500 000 edges per document, JSON only (no XML), purl parsed and length-checked, cycles tolerated (edges are a graph; traversals carry a visited set and a depth cap), unknown fields ignored, rate limit kept. Preview (`dry_run`) writes nothing. Fuzz tests on the parsers. |
| T6. VEX used to hide real findings | Creating, editing or deleting a statement that closes findings needs `findings:approve` (the false-positive permission). Human-sourced findings (pentest, manual, bug bounty, red team) are never closed by VEX. Every statement change and every closure is audited; a closed finding keeps the statement id. Expiring statements reopen nothing silently: on expiry the findings return to their previous status with a timeline entry. |
| T7. Denial of service through graph or facet queries | Graph depth ≤ 10, nodes ≤ 500, paths ≤ 20 per request, per-request statement timeout; facets computed in one grouped query over the scoped set with an index on `(tenant_id, product_id)`. |
| T8. Export leaks out-of-scope data | Export is per asset; the asset must be in scope; the document carries only that asset's links and the tenant's statements that cover them. |

## 5. Data model

### 5.1 Package products

Package identity is the purl type, namespace and name.

```
software_products (RFC-066), for packages:
  part = 'a', cpe_vendor/cpe_product NULL unless the feed maps one
  purl_type text        -- npm, pypi, maven, golang, cargo, nuget, gem, composer, hex, pub, swift, cran, cocoapods, conan, deb, rpm, apk, oci, github, generic
  purl_namespace text   -- '' when the type has none (lower case where the purl spec says so)
  purl_name text
  source               -- observed (tenant-private) | osv (global, from the feed) | curated | nvd
  description, homepage text NULL   -- tenant-private rows only from observations; global rows only from the feed
  UNIQUE (purl_type, purl_namespace, purl_name) per scope (global; per tenant)
```

- The existing tenant name index (`tenant_id, lower(name)` where no CPE) is
  narrowed to products without a purl, so `debug` on npm and `debug` on PyPI
  are two products.
- Resolution of an observed purl: the tenant's own product first, then the
  global product with the same purl identity, else a new tenant-private
  product. When the feed later publishes the identity, the tenant's private
  product is relinked to the global one (RFC-066 P1, "relinking"): links,
  versions and findings move in one transaction and the private product is
  deleted.
- The `qualifiers` and `subpath` of a purl are not identity; `arch`, `distro`
  and `type` qualifiers of OS packages go to the version `qualifier`.

### 5.2 Package versions

```
software_versions (RFC-066), for packages:
  raw text (≤ 128)            -- as observed; '' = version unknown
  normalized text NULL        -- = raw for package schemes (compared by the scheme's comparator), NULL when raw = ''
  scheme                      -- npm | pep440 | maven | go | semver (cargo, nuget, gem, composer, hex, pub, swift, cocoapods, conan) | deb | rpm | apk | generic
  purl text NULL              -- canonical pkg:type/namespace/name@version, no qualifiers; set for package versions
  published_at, deprecated, yanked  -- health hook, filled by the feed for global versions (§5.6)
```

- `raw` grows from 64 to 128 characters (Maven and Go pseudo-versions exceed
  64).
- `purl` makes the legacy joins (`components.purl`) one column and is indexed.
- `findings.component_id` keeps its name in the API and the database and now
  references `software_versions(id)` (`ON DELETE SET NULL`). The column name
  "component" means a package version throughout the API.

### 5.3 Where-used: `asset_software` for packages

A package observation is an `asset_software` row with `source = 'package'`.

```
asset_software (RFC-066) gains:
  location text (≤ 512)       -- for packages: the manifest or lock file path ('' when unknown); part of the unique key
  relationship text NULL      -- direct | transitive | unknown (packages only)
  dep_scope text NULL         -- runtime | development | test | optional | build | provided
  depth smallint NULL         -- shortest distance from a root (0 = direct)
  licenses text[] NOT NULL DEFAULT '{}'  -- SPDX ids or expressions as observed, ≤ 16, each ≤ 128
  channel text NULL           -- sensor | ci | sbom_upload | finding_import | integration
```

- Confidence is 100 for a version read from a lock file or SBOM with a purl,
  80 for a name and version without a purl.
- `superseded_at` is not used for packages: several versions of one package
  legitimately coexist in one lock file. A full snapshot (a sensor or CI
  report, an SBOM) replaces the links at the locations it names, so an
  upgrade shows as the old version's link going away; partial reports (a
  finding that names a package) only add or refresh.

### 5.4 Dependency graph: `asset_software_edges`

```
asset_software_edges
  tenant_id uuid NOT NULL, asset_id uuid NOT NULL
  parent_id uuid NOT NULL → asset_software(id) ON DELETE CASCADE
  child_id  uuid NOT NULL → asset_software(id) ON DELETE CASCADE
  PRIMARY KEY (parent_id, child_id), CHECK (parent_id <> child_id)
  INDEX (child_id)
```

- Many parents per child, so every introduction path is kept (the legacy
  model kept one parent).
- A trigger checks both ends belong to the same tenant and asset as the edge.
- Roots are the asset's links with `relationship = 'direct'` (or links with no
  parent when the producer did not mark them).
- `depth` on the link is recomputed after each snapshot (breadth-first from the
  roots, capped at 32).

### 5.5 Licenses

- The observed license list is per link (`asset_software.licenses`): the
  license a manifest or SBOM declares is a tenant observation.
- The global `licenses` table (SPDX id, name, category, risk, OSI/FSF flags) is
  the reference for categories: permissive, weak copyleft, strong copyleft,
  network copyleft, proprietary, public domain, unknown.
- Expressions (`MIT OR Apache-2.0`, `GPL-2.0-only WITH Classpath-exception-2.0`)
  are parsed; `OR` is satisfied by the most permissive allowed choice, `AND`
  needs every term allowed.
- The feed may later carry a declared license per global version
  (`software_versions.declared_licenses`); the effective license of a link is
  its observed list, else the declared one.

### 5.6 Health hook

```
software_product_health (global; one row per global product, written only by the bundle importer)
  product_id PK, latest_version text, latest_published_at timestamptz,
  deprecated bool, deprecation_message text, eol_date date, repository_archived bool,
  scorecard numeric(3,1), malicious bool, updated_at
```

- Created in the phase that imports it (P2); until then the API returns
  `health: null` and the UI shows "No health data yet" with the reason.
- "Outdated by N" = number of published versions newer than the version in
  use, from the global version rows; meaningful only for global products.
- Malicious packages arrive as OSV `MAL-` advisories through the normal
  matcher and show as critical findings with a "malicious" badge; the health
  flag only summarises them.

### 5.7 VEX statements

```
vex_statements
  id uuid PK, tenant_id uuid NOT NULL
  vuln_id text NOT NULL           -- CVE, GHSA, OSV or scanner rule id, upper case for CVE/GHSA
  product_id uuid NOT NULL → software_products   -- global or the tenant's own
  version_ids uuid[] NOT NULL DEFAULT '{}'       -- empty = every version of the product
  asset_id uuid NULL               -- NULL = every asset; otherwise only this asset
  status text NOT NULL             -- not_affected | affected | fixed | under_investigation
  justification text NULL          -- component_not_present | vulnerable_code_not_present | vulnerable_code_not_in_execute_path | vulnerable_code_cannot_be_controlled_by_adversary | inline_mitigations_already_exist (required when not_affected)
  impact_statement text, action_statement text (≤ 2000 each)
  origin text NOT NULL             -- manual | document
  document_ref text NULL           -- file name and statement id of an imported document
  expires_at timestamptz NULL
  created_by, updated_by uuid, created_at, updated_at
  UNIQUE (tenant_id, vuln_id, product_id, coalesce(asset_id, zero uuid), version_ids) -- one statement per subject
```

- Findings keep their `vex_*` columns as the applied snapshot and gain
  `vex_statement_id` (`ON DELETE SET NULL`).
- Imported VEX documents (finding import) are stored as statements
  (`origin = document`) when their product resolves to a catalog product, so
  they also cover findings that appear later.

## 6. Capture

| Producer | Path | Relationship / scope | Channel |
|---|---|---|---|
| Sensor SCA tools (trivy, osv-scanner, syft-based, grype) | CTIS `report.Dependencies` with `depends_on`, `type`, `licenses`, `location` | `type` direct/indirect; CycloneDX `scope`; trivy `Dev` → development | sensor |
| CI uploads (sdk-go, CI templates) | CTIS report | same | ci |
| SBOM upload in the UI or API | `POST /components/import` (CycloneDX 1.4–1.6 JSON, SPDX 2.2/2.3 JSON) | CycloneDX `dependencies` graph, `scope`; SPDX `DEPENDS_ON`, `DEV_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF` relationships | sbom_upload |
| Finding import (SBOM and VDR files) | `findingimport` | same | finding_import |
| Scanner findings with a package | CTIS findings with `PURL`/package | the link is created if missing (relationship unknown) and the finding's `component_id` set | sensor / ci |

All producers call one writer (`software.PackageWriter`): resolve products in
one round trip, ensure versions, upsert links, replace the asset's edges for
the reported locations, recompute depth, mark superseded versions. A snapshot
from an SBOM replaces the location; findings only add.

SPDX 3.0 JSON-LD import is planned for P1 once the producers we run emit it;
the parser is isolated so a format adds a reader, not a writer.

## 7. Vulnerabilities, upgrade advice, risk

- **Merged on the version.** A scanner finding with a package sets
  `findings.component_id` to the version; findings for the same CVE, asset and
  package merge as today (RFC-043 identity). The RFC-066 matcher evaluates each
  global package version once against the corpus once OSV ranges are imported
  (RFC-066 P1) and creates `technique va, tool version-match` findings; a
  scanner finding and a matcher finding for the same CVE, asset and version
  are one finding.
- **Per version** the API reports open findings by severity, KEV count, the
  highest EPSS, VEX status counts and the fixed versions the findings carry.
- **Upgrade advice** for a version: the nearest version (same scheme, greater
  than the current one) that is listed as fixed for every open CVE of that
  version; "breaking" when it changes the major component (semver, npm, cargo,
  pep440 epoch or major). Source: `findings.fixed_versions` now, corpus ranges
  after OSV import. When no single version fixes everything, the advice lists
  the minimum per CVE.
- **Risk score** (0–100) of a package: the maximum over its open in-scope
  findings of `(severity floor + 15 if known exploited + 10 if EPSS ≥ 0.1) ×
  asset criticality factor`, with the floors critical 90, high 70, medium 40,
  low 10 and the factors critical 1.0, high 0.9, medium 0.75, low 0.6 (0.75
  when unset), clamped to 0–100. Closed findings (including those closed by
  VEX) do not count. Dependency scope and reachability add factors when the
  data supports them (P1).

## 8. VEX

- **Create:** `POST /api/v1/vex-statements` (the subject, status,
  justification, statements, optional expiry). Applying it:
  - `not_affected` or `fixed` closes matching open, non-human findings
    (`false_positive` with `resolution_method = vex_not_affected`, or
    `resolved` with `vex_fixed`), sets `vex_*` and `vex_statement_id`;
  - `affected` and `under_investigation` annotate only.
- **Sticky:** ingest and the matcher check statements before creating or
  reopening a finding; a matching `not_affected` statement creates it closed.
- **Edit or delete:** findings the statement closed reopen (`open` or their
  previous status) unless another statement still covers them.
- **Expiry:** a controller reopens findings when a statement expires, with an
  audit and timeline entry.
- **Export:** the SBOM export includes the statements that cover the asset
  (CycloneDX `vulnerabilities[].analysis`); `GET /vex-statements/export`
  produces an OpenVEX document.
- Limits: one statement touches at most 5 000 findings per apply (as finding
  import); the rest are applied by the controller in batches.

## 9. License policy

- A tenant settings section `license_policy`:
  `{ "enabled": bool, "default": "allow"|"review", "unknown": "review"|"deny",
  "rules": [{ "match": "MIT" | "category:strong_copyleft", "action": "allow"|"review"|"deny", "scopes": ["runtime", ...] }] }`,
  at most 200 rules; the most specific rule wins (SPDX id over category); a
  rule may be limited to dependency scopes (copyleft in a test dependency is
  usually fine).
- Evaluated per link on capture and on policy change; the result is cached on
  the link (`license_verdict text`, `license_rule text`).
- `deny` creates a finding (`source = sca`, `finding_type = license`,
  severity high; `review` → medium only when the tenant opts in, otherwise only
  visible in the inventory). One finding per asset, package and license; it
  closes when the link goes away or the policy allows it.

## 10. API

All under `/api/v1`, tenant from the token, data scope applied (§11).

| Method and path | Purpose |
|---|---|
| `GET /components` | Package list (one row per product). Query: `q`, `ecosystem`, `license`, `license_category`, `license_verdict`, `severity` (has open findings of), `kev`, `has_fix`, `relationship`, `scope`, `asset_id`, `owner_id`, `sort` (`name`, `assets`, `versions`, `risk`, `vulns`, `last_seen`; `-` for descending), `page`, `per_page` (≤ 100), `facets=true`. Row: id, name, namespace, ecosystem, purl, versions in use, assets, direct and transitive link counts, open findings by severity, KEV count, fix available, licenses, license verdict, risk, first and last seen. |
| `GET /components/summary` | KPI strip for the current filter: packages, versions, assets with packages, vulnerable packages, KEV packages, license violations, outdated (null without health data). |
| `GET /components/{id}` | Product detail: identity, description and homepage (global feed or tenant-private), licenses, health, totals. |
| `GET /components/{id}/versions` | Versions in use with assets, findings by severity, KEV, fixed versions, upgrade advice, licenses, first and last seen. |
| `GET /components/{id}/assets` | Where-used: asset (name, type, criticality, owners), version, relationship, scope, location, depth, path count, channel, first and last seen. Filter `version_id`, `relationship`, `scope`; paginated. |
| `GET /components/{id}/vulnerabilities` | Findings grouped by vulnerability across versions: severity, CVSS, EPSS, KEV, fixed versions, affected versions, VEX status, open count. |
| `GET /assets/{id}/dependency-paths?version_id=&limit=` | Up to 20 shortest paths from a root to the version on that asset. |
| `GET /assets/{id}/dependency-graph?focus=&depth=&limit=` | Bounded graph (nodes with version, vulnerability summary, relationship, scope; edges; `truncated`). |
| `POST /components/import?asset_id=&dry_run=` | SBOM import; `dry_run=true` returns the preview (format, spec version, components, edges, licenses, invalid entries with reasons, the diff against the current inventory) and writes nothing. |
| `GET /components/sbom?asset_id=&format=` | Export (CycloneDX 1.6 JSON, SPDX 2.3 JSON), with VEX for CycloneDX. |
| `GET/POST/PATCH/DELETE /vex-statements[/{id}]` | VEX CRUD; list filters `vuln_id`, `product_id`, `asset_id`, `status`. |
| `GET/PUT /settings/license-policy` | License policy section. |

Retired with the legacy tables: `GET /components/stats`, `/ecosystems`,
`/vulnerable`, `/licenses` (replaced by `summary`, facets and list filters)
and `POST /components`, `PUT/DELETE /components/{id}` (inventory is written by
producers; a wrong row is fixed at its source or by a VEX statement).
`GET /assets/{id}/components` returns the asset's package links.

## 11. Authorization, data scope, module

| Route | Permission | Data scope |
|---|---|---|
| components list, summary, detail, versions, where-used, vulnerabilities, paths, graph, export | `components:read` | scoped (links of accessible assets; product detail 404 without an in-scope link) |
| SBOM import | `components:write` | scoped (target asset must be accessible) |
| VEX list | `components:read` | scoped (statements with an asset outside scope hidden; product-wide statements visible when the product has an in-scope link) |
| VEX create, edit, delete | `findings:approve` | scoped (asset-bound statements need the asset in scope; product-wide statements need full data access, because they close findings on every asset) |
| License policy read / write | `settings:read` / `settings:write` | config |

- Module: everything belongs to the `components` module (SBOM export already
  hard-depends on it). VEX statements are part of `components`; the finding
  closure they cause is visible in Findings regardless.
- Audit: VEX create, edit, delete, expiry; license policy change; SBOM import
  (file name, counts).

## 12. UI and UX

Design principles: package-first, one dense table that works on a phone,
every filter in the URL, the same KPI strip on every tab, actions where the
problem is, i18n (en, vi) for every string.

- **List** (`/components`): page header with Import SBOM and Export; KPI strip
  (packages, vulnerable, KEV, license violations, outdated); tabs as presets
  (All, Vulnerable, License issues, Outdated) that only change filters; facet
  sidebar on desktop, a filter sheet on phones (ecosystem, severity, KEV, fix
  available, relationship, scope, license category and verdict, asset,
  owner); every filter in the URL (shareable, bookmarkable); saved views once
  the list adopts the RFC-048 filter document (P1); columns: package (name,
  namespace, purl copy), ecosystem,
  versions in use, assets, severity counts, KEV, fix, license, risk; server
  pagination; row selection with bulk actions (create remediation group, VEX
  statement, export CSV).
- **Detail** (`/components/{id}`): header (name, ecosystem, purl, licenses,
  latest version and health, risk), then tabs: Versions (vulnerability badges,
  upgrade advice with a breaking hint), Where used (asset, version, direct or
  transitive, scope, location, "show path" expanding the introduction paths),
  Vulnerabilities (grouped by CVE, VEX status, link to findings), VEX
  statements, Licenses, Timeline (link added, version changed, removed, from
  `asset_software` and the RFC-069 asset timeline).
- **Dependency graph** (asset Software tab and the where-used path view):
  bounded, searchable, vulnerable paths highlighted, keyboard navigable; a
  tree list on phones.
- **SBOM import wizard** (shared dialog frame): file, target asset, preview
  (format, counts, invalid entries with reasons, diff), confirm, result.
- **Export dialog**: asset, format, include VEX.
- **Empty states** name the next step: connect CI, upload an SBOM, enable an
  SCA tool on a sensor; a filtered empty state offers to clear filters.
- Accessibility: tables with real headers and `aria-sort`, focus visible, badges
  with text not colour alone, dialogs trap focus; layouts checked at 390×844
  and 1440×900.

## 13. Phases

**P0** (this stack):

1. RFC and architecture doc.
2. Catalog unification: migration (package products and versions, link
   columns, edges, `findings.component_id` → `software_versions`, legacy data
   copied per tenant, legacy tables dropped), the package writer, ingest and
   SBOM import on the writer, component and finding queries on the catalog.
3. API: list with facets and summary, detail, versions, where-used,
   vulnerabilities, paths, graph, import preview; legacy routes retired.
4. Web: list, detail, graph and path view, import wizard, export dialog, empty
   states, en and vi.

**P1:** saved views for the list (RFC-048 filter document, `savedview`
page `components`); VEX statements (table, CRUD, sticky application, expiry controller,
OpenVEX and CycloneDX export, finding-import documents stored as statements);
license policy and license findings; upgrade advice from corpus ranges; OSV
package matching (RFC-066 P1) and relinking of private products; SPDX 3.0
import; timeline events for package changes.

**P2:** health from the feed bundle (latest, deprecated, EOL, scorecard),
outdated by N; provenance and attestation display; typosquat signal from a
popular-name list in the bundle; reachability from producers that report it.

## 14. Decisions

Adopted 2026-10-10 as recommended; the owner may revise any of them.

| # | Decision | Adopted |
|---|---|---|
| C1 | Inventory model | Packages are RFC-066 catalog products (purl identity) and versions; where-used is `asset_software` (`source = package`) plus `asset_software_edges`. No parallel component table |
| C2 | Legacy tables | `components` and `asset_components` are migrated per tenant and dropped in one migration (one-step upgrade note; the API stops during deploy) |
| C3 | Global package rows | Only from the feed (`source = osv`). Every observed package starts tenant-private, including public ones; relinked when the feed publishes the identity |
| C4 | `findings.component_id` | Keeps its name, references `software_versions(id)` |
| C5 | Graph | Edge table with many parents per child; traversals bounded (depth 10, 500 nodes, 20 paths) |
| C6 | VEX | Persisted per-tenant statements (product, optional versions, optional asset), sticky for future findings, `findings:approve` to write, never closes human-sourced findings |
| C7 | License policy | Tenant settings section; SPDX id or category rules, optional per scope; `deny` creates a `license` finding, `review` only on opt-in |
| C8 | Health data | Only from the signed feed bundle; the platform never calls registries |
| C9 | Legacy routes | Retired (`stats`, `ecosystems`, `vulnerable`, `licenses`, manual create, update, delete) |
| C10 | Branch dimension | Dropped (`asset_components.branch_id` was never written); the inventory is per asset and location |

## 15. Testing

- Migration: up, down, up on a database seeded with legacy rows for two
  tenants sharing one global component; counts match; findings remapped to the
  right tenant's version; a private package is never global.
- Writer: snapshot replaces a location; superseded detection; edges with
  cycles; depth; cross-tenant and cross-asset edge rejected by the trigger.
- Queries: list filters, facets, sorting, pagination; cross-tenant 404; member
  without scope sees nothing; member with partial scope sees only in-scope
  assets in counts, facets, where-used, paths and graph.
- SBOM import: valid CycloneDX and SPDX; preview writes nothing; oversize and
  over-count refused; malformed purls reported; fuzz tests on both parsers.
- VEX (P1): apply, sticky on ingest, reopen on delete and expiry, human sources
  untouched, permission and scope negatives.
- Web: component tests for the list (URL filters, facets, empty states),
  detail tabs, import wizard steps, i18n keys present in en and vi.
