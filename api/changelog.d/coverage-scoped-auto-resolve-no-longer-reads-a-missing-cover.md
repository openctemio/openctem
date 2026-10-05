### Fixed: Coverage-scoped auto-resolve no longer reads a missing coverage_type

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
