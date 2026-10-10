# Software components inventory

Design: [RFC-070](../rfcs/RFC-070-software-components-inventory.md). Catalog
and matcher: [vulnerability-matching.md](vulnerability-matching.md) (RFC-066).

## Model

```
software_products (purl_type, purl_namespace, purl_name; tenant_id NULL = from the feed, else tenant-private)
  └── software_versions (raw, normalized, scheme, purl)
        ├── asset_software (tenant, asset, location = manifest path, source = package,
        │                   relationship, dep_scope, depth, licenses, channel, first/last seen, superseded_at)
        │     └── asset_software_edges (parent link → child link, same tenant and asset)
        ├── findings.component_id  (scanner, SCA and matcher findings on that version)
        └── vex_statements          (tenant; product, optional versions or range, optional asset)
```

- A **component** in the API is a package product; a **component version** is a
  `software_versions` row; a **usage** is an `asset_software` row.
- Observed packages are tenant-private catalog rows. A global package product
  is created only by the vulnerability feed; an observation never writes a
  global row (see [global-catalog-trust.md](global-catalog-trust.md)).
- The scope trigger of the catalog rejects a link, edge, finding or VEX
  statement that references another tenant's product or version.

## Capture

Every producer (sensor and CI CTIS dependencies, SBOM upload, finding import,
scanner findings that name a package) goes through one writer:

1. parse each purl (type, namespace, name, version, qualifiers); entries
   without a purl use the ecosystem and name;
2. resolve products for the batch (tenant row, then global row, else create a
   tenant-private row);
3. ensure versions (scheme from the purl type; `normalized = raw`);
4. upsert links per asset and location, with relationship, scope, licenses
   and channel (a re-report without a license keeps the recorded one);
5. replace the edges of the reported locations, then recompute `depth`
   breadth-first from the direct links (cycles are tolerated).

An SBOM or a sensor or CI report is a snapshot of the locations it names:
links at those locations that it does not list are removed (with their
edges). A scanner finding that names a package only resolves the version for
the finding's `component_id`.

The repository counters (`asset_repositories.component_count`,
`vulnerable_component_count`) are recomputed by the writer once per snapshot.

## Migration from the legacy tables

`components_on_software_catalog` copies every (tenant, legacy component)
pair found in `asset_components` or `findings` into tenant-private products
and versions (package URL parsed in SQL, `%40` decoded, PyPI names
normalised), copies `asset_components` into package links (location = the
manifest path, relationship from `is_direct`/`dependency_type`, scope from
`dependency_type`, licenses split from the license string), turns
`parent_component_id` into edges, repoints `findings.component_id` to the
finding tenant's version, and drops both legacy tables. The down migration
rebuilds them (one global row per package URL).

## Reading

All reads start from the caller's accessible assets (data scope) and the
tenant:

- the package list groups the in-scope links by product, joins the open
  findings on `component_id` for severity, KEV and fix counts, and returns
  facets from the same filtered set;
- detail, versions, where-used and vulnerabilities answer 404 when the
  product has no in-scope link;
- dependency paths and the graph walk `asset_software_edges` of one in-scope
  asset with a visited set, depth ≤ 10, ≤ 500 nodes and ≤ 20 paths.

## VEX statements

A VEX statement is the organization's word on one vulnerability in one
package: `not_affected` (with a justification or an impact statement),
`affected`, `fixed` or `under_investigation`, for every version, listed
versions or a version range (`>=1.2.0,<1.4.3`, compared like the matcher
compares versions), on every asset or one asset, with an optional expiry.

- **Matching.** A finding is covered when its package version
  (`findings.component_id`) is a version of the statement's product, one of
  its ids (CVE, CVEs, rule id, typed ids) is the statement's `vuln_id`, the
  version is listed or in the range (or none is given) and, for an
  asset-bound statement, the finding is on that asset. When several
  statements cover a finding the most specific governs: one asset over every
  asset, listed versions over a range over every version, then the most
  recently edited.
- **Effect.** `not_affected` closes an open finding (new, confirmed, in
  progress, fix applied) as `false_positive` with resolution method
  `vex_not_affected`; `fixed` resolves it with `vex_fixed`; `affected` and
  `under_investigation` only annotate. The finding keeps the statement as
  `vex_statement_id` and its `vex_*` columns show the reason. A finding a
  person closed, and a finding from a human source (pentest, manual, bug
  bounty, red team), is annotated, never closed.
- **When it applies.** On create, edit, delete and expiry (in batches of
  1 000 findings per transaction) and to every finding an ingest writes
  later (sticky). A scan that reports a finding again does not reopen a
  finding a standing `fixed` statement resolved.
- **Withdrawal.** Editing, deleting or expiring a statement re-decides its
  findings: the ones it closed reopen (false positive to `new`, resolved to
  `confirmed`) unless another statement covers them. Every status move writes
  a `status_changed` activity entry; every create, edit, delete, expiry,
  import and sticky application writes an audit event with the findings it
  moved. The expiry controller (`vex-statement-expiry`) runs every 5 minutes.
- **Import.** `POST /api/v1/vex-statements/import` reads OpenVEX, CSAF VEX
  and CycloneDX VEX (JSON, 5 MB, 5 000 statements) and stores one statement
  per vulnerability and package (`origin = document`) for one asset or every
  asset; `dry_run=true` previews. Packages not in the inventory, products
  without a package URL and statements about components inside a product
  without a target asset are reported as skipped. An import never overwrites
  a statement written in the organization.
- **Isolation.** The product of a statement is global or the tenant's own
  (trigger), its asset is the tenant's (composite foreign key), and a
  finding can only carry its own tenant's statement (trigger).

## Authorization

| Action | Permission | Scope |
|---|---|---|
| Read the inventory, paths, graph, export | `components:read` | scoped |
| Import an SBOM | `components:write` | target asset in scope |
| VEX statements (list, read) | `components:read` | asset-bound: asset in scope; product-wide: an in-scope asset uses the package |
| VEX statements (create, edit, delete, import) | `findings:approve` | asset-bound: asset in scope; product-wide: full data access |
| License policy | `settings:read` / `settings:write` | config |

Module: `components`.

## Limits

| Limit | Value |
|---|---|
| SBOM body | 50 MB (JSON only) |
| Components per SBOM | 100 000 |
| Edges per SBOM | 500 000 |
| Graph depth / nodes / paths | 10 / 500 / 20 |
| Version string | 128 characters |
| Licenses per link | 16 |
| List page size | 100 |
| VEX document | 5 MB, 5 000 statements (JSON) |
| VEX statement | 64 versions, range of 8 terms, statements of 2 000 characters, expiry within 5 years |

## Web console

- `/components`: one row per package (versions in use, assets, open findings
  by severity, KEV, fix, licenses, risk, last seen); KPI strip and presets
  (vulnerable, known exploited, fixable, direct); facets (risk toggles,
  severity, ecosystem, dependency, scope, license) in a side panel on desktop
  and a sheet on phones; search, sort, page and every filter in the URL;
  Import SBOM (asset, file, preview, import) and Export SBOM (format, one
  asset or every visible asset). An empty inventory says how to get data.
- `/components/{id}`: header with the package URL, licenses, KEV and risk;
  tabs Versions (upgrade advice, major-version hint), Where used (asset,
  version, direct or transitive, scope, manifest, open findings; the paths
  that bring the package in; the asset's dependency graph) and
  Vulnerabilities (links to the findings of each CVE).
- The dependency graph is laid out left to right from the direct packages,
  highlights packages with open vulnerabilities and every path to them, is
  searchable and keyboard operable, and has a tree list view (the default on
  phones).
- Findings filter chips resolve a `component_id` through
  `GET /components/versions/{versionId}`.
