# Changelog

Notable changes to the OpenCTEM API. Release notes for each version are
published at https://docs.openctem.io (operations/release-notes-*).

## Unreleased

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

- **Tenable rolling coverage of private addresses needs a scan zone.**
  The coverage dispatcher now applies scan create's private-range policy:
  a private address is dispatched only when a scan zone of the tenant
  covers it (and the pinned sensor, if any, is in that
  zone). Tenants that rotated internal assets without zones see those
  assets skipped (logged) until they add a zone.

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
