# RFC-028: Asset identity model

| | |
|---|---|
| Status | Implemented (decisions 2026-10-01) |
| Builds on | RFC-001 (identity resolution), api#645 (rename handling), api#647 (lossless merge) |
| Repos | ctis (schema), sdk-go (scanners), api (matching, storage, backfill), ui (asset detail, duplicate review) |

## Problem

Ingest matched an incoming asset to an existing one by name, then by IP
address. Both are attributes, not identity:

- A renamed host or repository became a new asset and lost its owners, tags,
  criticality and finding history (fixed for the IP case in api#645, which
  made the next problem worse).
- An IP address is reused (DHCP). A match within the 30-day staleness window
  merged, and since api#645 renamed, a different machine.
- Two scanners that name one host differently produced two assets unless both
  reported the same IP.

Scanners already know better identifiers (Nessus reports the MAC and BIOS
UUID; cloud collectors know instance IDs; SCM hosts assign repository IDs),
but CTIS had nowhere to put them and the API had nowhere to keep them.

## Decisions (2026-10-01)

1. Keep following renames, but an IP counts only if it was seen on the asset
   within the last **7 days** (was 30). Shipped first, separately (api#650).
2. Identifier order: **sensor host ID > cloud instance ID / ARN > BIOS UUID /
   serial > MAC** (excluding shared, virtual and locally administered MACs)
   **> FQDN > hostname > IP**. IP counts only within the window and only when
   unambiguous. Repositories use the SCM repository ID; domains stay keyed by
   name.
3. A new `asset_identifiers` table (tenant, asset, kind, value, source,
   first_seen, last_seen). Strong kinds are unique per tenant; IP and hostname
   are not. Renames are recorded in state history.
4. Matching: strong identifiers first, in order, with a conflict veto; then
   the exact name; then the windowed IP; otherwise a new asset. On a match the
   attributes and the display name are updated. Conflicting strong matches go
   to the existing dedup review queue. Nothing is merged automatically.
5. CTIS gets an identifiers block; sdk-go scanners fill it.
6. A backfill derives identifiers for existing assets and queues suspected
   duplicates for review, without merging.
7. Applies to protocol v1 and v2 (both go through `AssetProcessor.processBatch`).

## Design

### Kinds

| Kind | Strong | Single-valued | Comes from |
|---|---|---|---|
| `host_id` | yes | yes | `identifiers.machine_id`; properties `host_id`, `machine_id`, `sensor_host_id`, `machine_guid` |
| `cloud_id` | yes | yes | `identifiers.cloud_resource_id`; `technical.cloud.arn` / `resource_id`; properties `cloud_resource_id`, `instance_id`, `cloud_instance_id`, `vm_id`, `arn` |
| `bios_uuid` | yes | yes | `identifiers.bios_uuid`; properties `bios_uuid`, `system_uuid`, `smbios_uuid` |
| `serial_number` | yes | yes | `identifiers.serial_number`; properties `serial_number`, `hardware_serial` |
| `mac` | yes | no | `identifiers.mac_addresses`; properties `mac_address`, `mac_addresses`, `mac` |
| `scm_repo_id` | yes | yes | `identifiers.scm_repo_id`; properties `scm_repo_id`, `repo_id`, `repository_id`, `project_id`; `asset_repositories.repo_id` (backfill) |
| `fqdn`, `hostname` | no | no | the asset name, properties `hostname`, `fqdn`, `netbios_name` |
| `ip` | no | no | every IP shape ingest already reads, plus an IP `value` |

Hardware kinds (host ID, BIOS UUID, serial, MAC) are read only for host-like
types (host, ip_address, network, endpoint). Domains, subdomains and
certificates get no identifiers.

Values are normalized: MACs to lower-case colon form, rejecting multicast,
locally administered (Docker, most VPN and virtual NICs), all-zero and known
shared addresses (VRRP, HSRP, GLBP, Cisco AnyConnect, FortiClient, Windows WAN
Miniport and RAS adapters); BIOS UUIDs and host IDs lower-cased, rejecting
vendor placeholders (all zeros, all F, the AMI default); serials rejecting
"To be filled by O.E.M." and similar; ARNs keep their case. An SCM ID is
stored as `<host>:<id>` (`github.com:123456`) so the same number on two SCM
hosts does not collide.

### Matching (per incoming asset)

1. **Strong identifiers**, strongest first. The first asset found is the
   candidate. It is **vetoed** when it holds a different value of a
   single-valued kind ranked above the matching one that the incoming asset
   also carries: a different host ID beats an equal MAC. Other assets that
   the incoming strong identifiers point at, and an asset that owns the
   incoming name without a conflicting identifier, become an
   `identifier_conflict` review.
2. **Exact name** (`assets.name`). Names are unique per tenant, so a report
   whose name matches an asset with a conflicting identifier still lands on it
   (logged; the conflicting identifier is not recorded).
3. **Hostname / FQDN** the asset was seen with inside the window, when exactly
   one asset of the same family has it. This is what keeps two scanners that
   name one host differently on one asset after the IP changes.
4. **IP** seen on exactly one asset inside the window (per-IP `last_seen`;
   assets without identifier rows fall back to the asset's `last_seen`). An IP
   on several assets matches none; they get a `shared_ip` review.
5. Otherwise a **new asset**.

On a match the report's attributes are merged and the display name follows
the api#645 rule (better name wins; same quality wins when unambiguous and not
a former name; worse never). A rename onto a name another asset holds is not
done. Every rename writes a `renamed` state-history row (`field=name`,
`old_value`, `new_value`, reason `matched by <kind>`); manual renames through
the asset API do too.

After the upsert the batch's identifiers are written. A strong identifier
another asset already holds is left with it and raises an
`identifier_conflict` review.

### Storage

Migration `000243_asset_identifiers`:

- `asset_identifiers`: unique `(tenant_id, kind, value) WHERE strong`, unique
  `(asset_id, kind, value)`, lookup index `(tenant_id, kind, value)`. A
  `strong` column is pinned to the kind by a check constraint so the partial
  index can be used by `ON CONFLICT`.
- `asset_dedup_review.reason` and `.evidence` (nullable).
- `asset_state_history.chk_change_type` allows `renamed`.
- `asset_identity_backfill`: one row per tenant per backfill version.

A merge (api#647) moves identifiers to the kept asset (conflict-safe on
`kind, value`).

### Backfill

The `asset-identity-backfill` controller runs at start and hourly. For every
tenant without a row at the current version it pages through the assets,
derives identifiers with the same code ingest uses (plus the repository ID and
former names, whose `last_seen` is the asset's creation time so they are not
recent evidence), and records them with the asset's `last_seen`. It then
queues reviews:

- `shared_identifier`: two assets carry one strong identifier.
- `renamed_host`: two host assets one Nessus/Tenable/Vuls source reported with
  the same IP under different names (the shape api#645 fixed going forward),
  unless their single-valued strong identifiers differ.

It never merges. Reviews keep the asset with more findings, then the older one.
A pair an operator rejected is not raised again.

### API

- `GET /api/v1/assets/{id}/identifiers` (`assets:read`).
- `GET /api/v1/assets/{id}/state-history?change_type=renamed`.
- Dedup review items carry `reason` and `evidence`. The review list is now
  encoded with snake_case keys; it was encoded with Go field names, which the
  duplicates page could not read.

## Limits and follow-ups

- `assets.name` is unique per tenant. Two machines with the same hostname but
  different host IDs still share one asset (identifiers are not mixed).
  Splitting them needs a name-uniqueness change.
- The sensor's own host ID (`machine_id`) has to be sent by the sensor
  repository; sdk-go fills MAC, BIOS UUID, cloud instance ID and repository ID
  where its sources report them.
- A tenant can still widen the IP window with `stale_asset_days` (1-365).
