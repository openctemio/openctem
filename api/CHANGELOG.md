# Changelog

Notable changes to the OpenCTEM API. Release notes for each version are
published at https://docs.openctem.io (operations/release-notes-*).

## Unreleased

### Changed: suppressed findings are dispositions, not fixes

- **A suppression rule marks a finding `false_positive` or `accepted`,
  never `resolved`** (research 18 F7, owner decision O9). A false-positive
  rule gives `false_positive`; accepted-risk and won't-fix rules give
  `accepted`. The resolution stays `suppressed` and `finding_suppressions`
  names the rule. Fix rate and MTTR therefore count real fixes only.
- Migration 000751 moves existing `resolved` / `suppressed` rows to the
  disposition of their recorded rule (same tenant), only when that rule is
  certain; rows with no recorded rule or conflicting rules stay as they are.
  The relabel is not counted as a regression.

### Findings keep the scanner details they used to drop (research 17 R2)

- Ingest now stores the rule **family** (Nessus / Tenable.sc plugin family,
  scanner category), the scanner's **exploit-available** verdict as a column,
  **VPR** (display only, no priority effect), the **CVSS version**, **every
  CVE** named on the finding (`cve_ids`) and the vendor **patch publication
  date**. The finding API returns them. Migrations 000688-000689 (nullable
  columns, NOT VALID checks, partial indexes, and a backfill of the exploit
  flag from metadata). Fingerprints are unchanged.

### Added: the `not_observed` finding status

- **`not_observed`: not seen lately, not fixed** (research 18, owner
  decision O2). Recent scans no longer report the finding, but nothing
  proves the check ran against it. It is an open status: never counted as
  fixed, no `resolved_at`, and its SLA keeps running. Only the platform sets
  it; a sighting reopens it (not counted as a regression), and it reaches
  `resolved` only through a retest or a `findings:verify` holder.
- **Feature-branch expiry writes `not_observed`** instead of `resolved`, so
  "not seen for N days on a branch" no longer counts as a fix in fix-rate
  or MTTR. Migration 000640 moves existing `resolved` / `branch_expired`
  rows to `not_observed` (no other row is touched) and adds a CHECK
  constraint on `findings.status`, which had none.
- Retest runs on `not_observed` findings. The web labels the status
  "Not Observed" and lists it in the "Open" filter group.

### Behaviour change: resolving a finding needs findings:verify

- **Members can no longer close findings as resolved** (research 18 F1,
  owner decision O12). Moving a finding to `resolved` now needs
  `findings:verify` from every status, `fix_applied` included, on every path:
  `PATCH /findings/{id}/status`, `POST /findings/bulk/status`,
  `POST /findings/remediation-groups/{key}/resolve` and remediation campaign
  resolve. Before, a Member (`findings:fix_apply` + `findings:bulk_update`)
  could mark findings `fix_applied` and then bulk-close them with no
  checklist and no proof of fix. Without the permission these calls now
  answer **403** and change nothing. Members keep `fix_applied`; a retest, a
  verified scan or a security reviewer closes the finding. The web hides
  "Resolved" from people without the permission. Give `findings:verify` to a
  custom role if a team should keep closing findings by hand.
- **Every human resolve records how and by whom.** The single, bulk, group
  and campaign paths stamp `resolution_method` (`security_reviewed` when the
  finding's verification checklist is complete, `admin_direct` otherwise) and
  `resolved_by`, and the bulk path now writes a status-change activity per
  finding. Any move away from `resolved` clears `resolution_method`.
- The unused, unguarded `VulnerabilityService.BulkUpdateFindingStatus` was
  removed.

### Security: validation evidence no longer resolves a finding

- **A validation "not detected" keeps a `fix_applied` finding open**
  (research 18 F6, RFC-040). The only proof that the target answered was
  `raw_meta.reachable`, which the sensor asserts about its own run, so a
  hostile or broken sensor could close any `fix_applied` finding. The verdict
  is still recorded on the finding; a retest (whose reachability probe the
  platform dispatches) or a `findings:verify` holder closes it. Downgrades of
  still-open findings to `validated_fixed` (which a person still closes) and
  reopen on "detected" are unchanged.

### Security: custom template trust (RFC-038 §6.12)

- **Custom templates reach sensors only in a signed manifest.** Every
  command poll signs one DSSE envelope per command (Ed25519 over the exact
  bytes) listing the tenant, the polling sensor, the command, a 1-hour
  expiry and the SHA-256 of every template; templates are validated again
  first, and a set that fails is sent unsigned so the sensor refuses it.
  Keys are per tenant, derived from `APP_TEMPLATE_SIGNING_KEY` (new;
  unset: derived from `APP_ENCRYPTION_KEY`). New
  `GET /api/v1/scanner-templates/signing-key` returns the tenant's public
  key to pin on its sensors (`SENSOR_TEMPLATE_SIGNING_KEYS`). **Upgrade
  note:** sensors on the matching sdk-go refuse custom templates until the
  key is pinned; scans without custom templates are unaffected.
- **More nuclei protocols refused at upload.** The `file` protocol (reads
  the sensor's disk) and self-contained templates are refused like `code`,
  `javascript` and `headless` already were, with an error naming the
  protocol.

### Fixed

- **Coverage-scoped auto-resolve no longer reads a missing `coverage_type`
  as full** (safety; CTIS spec 4.5, research 16 G4, owner decision Q5).
  A scan command's run closed findings it no longer reported when its
  report declared `full` *or nothing at all*, while the report-level
  (repository) path already treated an absent value as no auto-resolve.
  Now only an explicit `full` qualifies; an undeclared report is refused
  with reason `coverage_undeclared`. **Upgrade note:** sensors whose sdk-go
  predates openctemio/sdk-go#150 send no `coverage_type`, so their scans no
  longer close findings on this path (fail safe; the mode defaults to
  `dry_run`). Sensors with that change send `full` only for completed runs
  and `partial` for runs that stopped part-way.

- **A finding's occurrence count grows with every sighting** (RFC-043 P0).
  Re-ingesting an existing finding wrote back the count it had loaded before
  the merge, so `occurrence_count` stayed at 1 however often a scan saw the
  finding, and concurrent ingests overwrote each other. The update now adds
  one to the stored value in SQL.
- **A finding another ingest just created is no longer reported as new, and
  keeps its ticket links** (RFC-043 P0). Ingest checked which fingerprints
  existed and then inserted the rest; when two ingests raced on one new
  finding, or one report named a finding twice, the second insert still
  counted as created and ran the new-finding steps (workflows,
  notifications, assignment rules, remediation keys, exposure bridge) under
  an id that was never stored. Its `ON CONFLICT` update also replaced the
  stored ticket links (`work_item_uris`) and metadata with the empty values
  of the incoming row. The upsert now returns the stored id and whether it
  inserted; only inserted rows count as created and run those steps, a
  repeated finding in one report is folded into the first, ticket links are
  never taken from the incoming row, and metadata keeps the stored keys.
- **Asset stats and facets respect data scope.** `GET /api/v1/assets/stats`
  and `GET /api/v1/assets/facets` counted every asset of the organization,
  so a member restricted to some assets (access groups) could read totals,
  breakdowns and property values of assets they cannot list. Both now apply
  the same data-scope filter as the asset list: a scoped member's numbers
  equal what their list shows, and in an organization where members without
  an access group see nothing, such a member gets empty stats and no facets.
  Administrators and unrestricted members see the same numbers as before.
  The facets query is also bounded: it reads the 5,000 most recently
  updated assets in scope, expands at most 50 elements of an array property
  per asset and returns the top 20 values per key from the database. On a
  larger inventory the facet counts are counts within that sample.

- **Findings keep the port they were found on.** CTIS `Finding.Network`
  (port, transport, service) was used only inside the network-VA dedup
  fingerprint and then dropped, so no stored finding knew its port. Ingest
  now stores it in `findings.network_port`, `network_transport` and
  `network_service` (migration 000377), and the finding API returns
  `network_port`, `network_transport` and `network_service`. A re-sighting
  fills a missing value and never replaces a stored port, so the port does
  not flip between scans for a finding whose fingerprint does not include
  it. Fingerprints are unchanged. Existing findings get the value on their
  next scan.

- **Scope exclusions apply on every path that scans or discovers, not
  only at scan trigger** (RFC-042 F16). Four paths ignored them:
  - `POST /api/v1/pipelines/runs` and the `trigger_pipeline` workflow
    action passed `context.targets` straight into the step commands. The
    run's targets now get a scan's checks: excluded targets are dropped
    (every target excluded: `ALL_TARGETS_EXCLUDED`); a private address
    outside every scan zone, loopback, link-local or metadata address, or
    a target zone routing cannot place refuses the run (400
    `TARGET_REFUSED`); a caller's `scan_zone_id` is ignored and set from
    the routing. These starts also crashed on a nil scan id before
    creating the run; they now work and are limited per pipeline.
  - The Tenable rolling coverage dispatcher sent its batches unchecked.
    Excluded or refused assets are now skipped for that rotation, a batch
    stays in one scan zone and its command is stamped with it.
  - Certificate Transparency discovery no longer queries an excluded
    domain or raises exposures for an excluded host.
  - Ingest no longer adds a new asset (or a root domain or resolved IP
    derived from one) that matches an exclusion by name, repository URL
    or address. It is counted as `assets_skipped_excluded` and named in
    the warnings; its findings are skipped, never attached to another
    asset of the report. Assets already in the inventory are not changed
    or deleted.
  A failed exclusion lookup stops each of these paths (fail closed).

- **Group scans resolve members as assets and skip archived ones.** A scan
  of an asset group matched scope exclusions against each member's name
  only, so a host whose address was in an excluded network was scanned. It
  also scanned archived members. Members are now read by asset id (only
  assets of the scan's tenant), exclusions are tested against the member's
  name, addresses (`ip_addresses`, `ip`) and repository URLs, and archived
  members are skipped and counted (`archived_target_count` in the run
  context, and a warning). **Behaviour change:** archived assets in a group
  are no longer scanned, and a member whose address matches an approved
  exclusion is now excluded. Stale and inactive members are still scanned.

- **A pipeline step's settings reach the sensor.** Step commands carried
  the step's config as `step_config`, which no sensor reads, so every step
  ran with its tool's defaults (a naabu step with `ports: "80"` scanned the
  top 100 ports). The payload now carries it as `config`, the key the
  sensor SDK reads. Needs sensor with sdk-go per-scan settings (naabu:
  `ports`, `top_ports`, `exclude_ports`, `rate`, `retries`; nuclei: `tags`,
  `exclude_tags`, `severity`). Saving a step now checks these keys against
  the sensor's rules (`INVALID_STEP_SETTING`): a port list that is not one,
  a flag-like tag, an intrusive tag (`dos`, `fuzz`, `fuzzing`,
  `intrusive`), ports together with top_ports. `allow_interactsh` is refused
  on a pipeline step. A stored step with such a value fails when its run
  queues it, with the reason.

### Changed (behaviour change)

- **The crown-jewel flag is the `assets.is_crown_jewel` column** (owner
  decision O5). It was written into `properties.is_crown_jewel`, while the
  scoping summary read the column, so the two disagreed. Migration 000760
  backfills the column from the property (JSON `true` or the string `"true"`,
  any case; anything else reads as false), removes the key from properties
  and makes the column `NOT NULL DEFAULT FALSE`. Priority classification, the
  attack-path graph, exposure chains, threat models, the executive
  dashboard, the crown-jewel filter and dedup merge (a merged crown jewel
  keeps the flag) read the column; asset responses carry `is_crown_jewel`.
  Only `PATCH /assets/{id}/crown-jewel` writes it: assets:write, the asset in
  the caller's data scope (404 otherwise), audited. `is_crown_jewel` stays a
  reserved key, so a create, update, import or sensor report cannot set it
  through properties. **Upgrade note:** a crown jewel marked by a pod of the
  previous release while the migration runs must be marked again.

- **`POST /api/v1/assets` for an asset that already exists is a 409** (owner
  decision O4). A name, or an address the name correlates to (IP/hostname),
  that matches an asset of the organization used to merge the request into
  that asset; it now creates and changes nothing. The 409 carries
  `details.existing_asset_id` only when that asset is in the caller's data
  scope; otherwise it is the same generic conflict for every match, so it
  reveals nothing about an asset the caller cannot see. Another
  organization's assets never match. The web offers to open the existing
  asset. Sensor ingest and the SCM repository import
  (`POST /api/v1/assets/repository`) keep their merge paths. **Upgrade
  note:** an API client that relied on the create upserting must handle the
  409 (update the named asset) or send its data through ingest.

- **Tenable rolling coverage of private addresses needs a scan zone.**
  The coverage dispatcher now applies scan create's private-range policy:
  a private address is dispatched only when a scan zone of the tenant
  covers it (and the pinned sensor, if any, is in that
  zone). Tenants that rotated internal assets without zones see those
  assets skipped (logged) until they add a zone.

- **`*.example.com` means the subdomains of example.com, not example.com
  itself.** The scope matcher used to let a wildcard domain pattern match the
  bare name too, which is not what the pattern says (RFC-042 §6.13, F17).
  `**.example.com` means the same as `*.example.com`. Matching ignores case
  and a trailing dot, and compares names in their IDNA form
  (`*.bücher.example` matches `shop.xn--bcher-kva.example`). The web's scope
  preview already matched this way. Both directions change:
  - **Scope targets:** a target `*.example.com` no longer puts
    `example.com` in scope (coverage counts, `POST /scope/check`, overlap
    warnings). This only narrows scope. Existing targets are not rewritten:
    add `example.com` as its own target if the apex should stay in scope.
  - **Exclusions:** an exclusion `*.example.com` no longer excludes
    `example.com` from scans. So that nothing excluded today is scanned
    tomorrow, migration 000292 adds an apex sibling (`example.com`, same
    type, status, approval and expiry) for every existing domain/subdomain
    exclusion written `*.x` or `**.x`, except rejected ones and names that
    already have their own row. The siblings have `created_by =
    system:migration-000292` and a reason naming the wildcard row; the down
    migration removes exactly those. New wildcard exclusions cover
    subdomains only: request the apex separately.

- **Organizations are created by the platform administrator by default.**
  `TENANT_CREATION_MODE` now defaults to `admin_only` (was `self_service`).
  Signed-in users can no longer create organizations themselves
  (`POST /api/v1/auth/create-first-team` and `POST /api/v1/tenants` return
  403); the administrator creates them in the console or with
  `bootstrap-admin -org-*`. Existing organizations and memberships are
  unaffected. To keep self-service creation (SaaS or trial installs), set
  `TENANT_CREATION_MODE=self_service` (Helm: `api.tenantCreationMode=self_service`).
  Any value other than `self_service` is treated as admin-only.

### Added

- `bootstrap-admin` creates the first organization: `-org-name`,
  `-org-slug` (derived when empty), `-org-owner-email`, `-org-owner-name`
  (env `ORG_NAME`, `ORG_SLUG`, `ORG_OWNER_EMAIL`, `ORG_OWNER_NAME`). It uses
  the console's organization service (audited `tenant.created` and
  `user.created`); a new owner gets a one-time set-password link, emailed
  with SMTP or printed once. Re-running skips an existing organization.
- `create-first-team` (self-service mode) is audited as `tenant.created` and
  writes the organization and its owner in one transaction.

### Removed

- `bootstrap-tenant` (raw SQL, unaudited, ignored `TENANT_CREATION_MODE`) is
  no longer built or shipped in the image. Use
  `bootstrap-admin -org-name … -org-owner-email …`.
- `sla.Service.CreateDefaultTenantPolicy`, which nothing called.
