# Upgrading to CTIS 2.0

> **Applies to:** the first platform release that accepts CTIS 2.0
> (`changelog.d/ctis-2-switch.md`). From that release on the platform accepts
> **only** CTIS 2.x documents. There is no compatibility layer: sensors,
> connectors, CI integrations and the asset collector are upgraded together
> with the platform.
>
> Design: `docs/architecture/ctis-receiver.md`.

## 1. What changes for you

- Every producer must send CTIS 2.0. A 1.x document is refused:
  - protocol v2 sensors get `415` for the old media type
    (`application/vnd.openctem.ctis.v1+json`) and `422 version-mismatch` for a
    1.x body;
  - CI uploads, finding imports of a 1.x CTIS file and DefectDojo syncs on an
    old connector are refused with a validation error;
  - a CI upload (`POST /api/v1/ci/runs/{id}/results`) is the CTIS 2.0
    document itself. The `{"report": ...}` envelope the 1.x CI integration
    sent is refused with `400` ("Not a CTIS 2.0 document ... upgrade the CI
    integration"), even around a 2.0 document. A job result on the sensor
    queue is likewise the document itself;
  - a 1.x report still queued, or held in the results quarantine, when you
    upgrade cannot be applied any more (see section 3).
- Import mappings are `openctem.io/mapping/v2`. A saved v1 mapping no longer
  loads: open it in the editor, rename the targets (`vulnerability.cve_id` ->
  `vulnerability.ids`, `vulnerability.package` -> `vulnerability.package_name`,
  `vulnerability.affected_version` -> `vulnerability.installed_version`,
  `vulnerability.fixed_version` -> `vulnerability.fixed_versions`,
  `network.protocol` -> `network.transport`; `impact`, `likelihood`,
  `vulnerability.cvss_*`, `vulnerability.ecosystem`, `vulnerability.vendor_severity`
  and `remediation.references` are gone) and save it as a new version. CI jobs
  that pin a mapping version must be pinned to the new version.
- Stored asset names are moved to their CTIS 2.0 canonical form on the first
  start of the new release (section 4). Findings are re-keyed by the finding
  identity migration (`docs/architecture/deduplication.md`).

## 2. Minimum producer versions

Upgrade these together with the platform; an older release sends CTIS 1.x
and is refused:

| Producer | Minimum version |
|---|---|
| sensor | the first release with CTIS 2.0 (v0.36.0) |
| sdk-go (custom tools) | v0.46.0 |
| openctem-ci (CI integration) | the first release with CTIS 2.0 (v0.4.0) |
| connector-tenable | v0.2.0 |
| asset-collector | the first release with CTIS 2.0 (v0.3.0) |
| ai-worker | v0.1.0 |

## 3. Upgrade order

1. **Before the window.** Run the asset name migration dry (section 4.1) on
   a copy of the database or read-only on production, and keep the counts.
   Review the sensor results held for review (the results quarantine of each
   sensor, `GET /api/v1/sensors/quarantined-results`) and accept or reject what is pending: an item stored from a 1.x sensor cannot be
   accepted after the upgrade. Let the ingest queue drain (no pending CI or
   import jobs).
2. **Stop the producers**: pause scheduled scans, stop sensors and the asset
   collector, pause CI jobs and connector syncs.
3. **Upgrade the platform** (migrations run as usual; the migration adds the
   `asset_canonical_changes` journal table). On its first start the server
   runs the asset name migration (section 4) and the finding re-key in the
   background; watch the log for "asset names moved to the CTIS 2.0
   canonical form".
4. **Upgrade the producers** to the minimum versions (section 2) and start
   them. Re-save any v1 import mapping (section 1).
5. **Check**: a scan of a known target updates the same assets and findings
   (no new duplicates); the inventory counts match the dry run plus what the
   scan added.

## 4. Stored asset names

Ingest stores an asset under the canonical form of its CTIS value. A name
stored before the switch in another spelling (a Unicode host name instead of
its IDNA A-label, a URL path with `..` segments or lower-case percent
escapes, an image named `nginx@sha256:...` instead of
`docker.io/library/nginx@sha256:...`) would no longer be found and would be
split. The migration renames such an asset, or merges it into the asset of
the same type that already has the canonical name (the asset merge: every
reference moves, findings are re-keyed and folded, triage is kept). An asset
whose canonical name an asset of another type holds is left as it is and
recorded. Tag-only image names (`nginx:1.25`) have no digest and are left as
they are; new reports create the digest-named asset.

### 4.1 Dry run

```sh
docker compose exec api asset-canonical            # every tenant, read-only
docker compose exec api asset-canonical -tenant <id> -json
```

The output is counts only: assets checked, would be renamed, merged, left.

### 4.2 Apply

The server applies it on start. To run it by hand:

```sh
docker compose exec api asset-canonical -apply
```

It is idempotent (a second run changes nothing), runs one transaction per
asset and writes one audit entry per changed tenant (`assets.merged`).

### 4.3 Rollback

1. Stop the new release.
2. Undo the renames: `asset-canonical -revert` (with the new release's
   image). It gives every renamed asset its old name back unless the asset
   changed meanwhile or another asset took the old name. **Merges are not
   undone**, as with every asset merge: the merged asset is gone and its
   references live on the kept asset.
3. Migrate the database down to before the switch (`openctem-migrate down N`
   with N the migrations applied since, the last being
   `ctis2_asset_canonical_changes`, whose down drops the journal) and undo the finding re-key as its own guide describes.
4. Start the previous release and the previous producer versions together.
