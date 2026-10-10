### Security: private package names no longer become shared catalog rows

- Software components move into the software catalog (RFC-070, migrations
  `components_on_software_catalog` and `drop_components_delete_permission`).
  The old global `components` table held one row per package URL and version
  for every tenant: a private package one organization reported
  (`pkg:npm/@acme/internal-auth`) became a shared row, and its description
  and homepage came from whichever organization reported it first. Every
  package an organization reports is now private to it; a shared package row
  exists only when the vulnerability feed names the package.
- A finding, a package link and a dependency edge can only reference the
  organization's own package versions or shared ones (database triggers).

### Behaviour change: one software inventory with a dependency graph

- Packages are catalog products (package URL identity) with versions; where
  an asset uses one is a package link (`asset_software`, source `package`)
  with its relationship (direct or transitive), dependency scope, manifest
  path, licenses and the channel that reported it. Every parent of a package
  is kept (`asset_software_edges`), so all introduction paths are known.
- A report or SBOM is a snapshot of the manifests it names: packages it no
  longer lists at those paths are removed.
- `findings.component_id` now references `software_versions(id)`.
- **Upgrade note:** destructive migration; stop the API during the deploy
  (old code reads the dropped `components` and `asset_components` tables).
  Existing rows are copied per organization; the old shared description and
  homepage are not copied.

### Added: software components API

- `GET /api/v1/components` lists packages (one row per package) with versions
  in use, assets, open findings by severity, KEV, fix availability, licenses
  and risk; server-side filters, sorting, pagination and facets.
- `GET /api/v1/components/summary`, `GET /api/v1/components/{id}`,
  `/{id}/versions` (with upgrade advice), `/{id}/assets` (where used),
  `/{id}/vulnerabilities`; `GET /api/v1/assets/{id}/dependency-paths` and
  `/dependency-graph` (bounded).
- `POST /api/v1/components/import?dry_run=true` previews an SBOM (counts,
  skipped entries with reasons, the difference with the current inventory)
  without writing; the import reads the CycloneDX dependency graph and SPDX
  relationships.

### Removed: legacy component endpoints and permission

- `GET /api/v1/components/stats`, `/ecosystems`, `/vulnerable`, `/licenses`
  (use `summary`, facets and list filters) and `POST /api/v1/components`,
  `PUT/DELETE /api/v1/components/{id}` (the inventory is written by sensors,
  CI and SBOM import). The permission `assets:components:delete` is removed;
  it gated nothing else.
