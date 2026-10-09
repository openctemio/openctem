# Asset Identity Resolution & Deduplication

> **Status**: Production-ready | **Origin**: RFC-001 (completed 2026-04-15); identity model RFC-028 (2026-10-01)

## Overview

Multi-layer deduplication system that ensures the same real-world entity maps to a single asset regardless of how different sources name it.

**Problem solved**: one source sends `192.0.2.10`, another sends `web-server-01`, a third sends `web-server-01.corp` — all for the same host. Without identity resolution, these create 3 separate assets with fragmented findings and incorrect risk scores.

## Architecture

```
Incoming asset (sensor protocol v2 or an import, AssetProcessor.processBatch)
    │
    ▼
Normalize name (Layer 1)
    │
    ▼
1. Strong identifiers, strongest first, with the conflict veto
   host ID > cloud ID > BIOS UUID > serial > MAC   (repositories: SCM repo ID)
    │ none
    ▼
2. Exact name (assets.name)
    │ none
    ▼
3. Hostname / FQDN seen on exactly one asset in the last 7 days
    │ none
    ▼
4. IP seen on exactly one asset in the last 7 days (hosts)
   Other types: repository suffix, external ID, certificate fingerprint
    │ none
    ▼
5. New asset
    │
    ▼
Upsert assets → record identifiers, renames (state history), duplicate reviews
```

Nothing in this path merges two existing assets. Conflicts go to the dedup
review queue for an operator. Design and decisions: `docs/rfcs/RFC-028-asset-identity-model.md`.

## Identifiers

Table `asset_identifiers` (tenant_id, asset_id, kind, value, source,
first_seen, last_seen). Strong kinds are unique per tenant; FQDN, hostname and
IP are not.

| Kind | Strong | Vetoes a match | Read from |
|---|---|---|---|
| `host_id` | yes | yes | CTIS `identifiers.machine_id`; properties `host_id`, `machine_id`, `sensor_host_id`, `machine_guid` |
| `cloud_id` | yes | yes | `identifiers.cloud_resource_id`; `technical.cloud.arn`/`resource_id`; properties `cloud_resource_id`, `instance_id`, `cloud_instance_id`, `vm_id`, `arn` |
| `bios_uuid` | yes | yes | `identifiers.bios_uuid`; properties `bios_uuid`, `system_uuid`, `smbios_uuid` |
| `serial_number` | yes | yes | `identifiers.serial_number`; properties `serial_number`, `hardware_serial` |
| `mac` | yes | no (hosts have several) | `identifiers.mac_addresses`; properties `mac_address` (the Nessus parser), `mac_addresses`, `mac` |
| `scm_repo_id` | yes | yes | `identifiers.scm_repo_id`; properties `scm_repo_id`, `repo_id`, `repository_id`, `project_id`; `asset_repositories.repo_id` |
| `fqdn`, `hostname` | no | — | asset name; properties `hostname`, `fqdn`, `netbios_name` |
| `ip` | no | — | every IP shape listed under Renames, plus an IP `value` |

Hardware kinds are read only for host, ip_address, network and endpoint
assets. Domains, subdomains and certificates stay keyed by name.

Normalization (`pkg/domain/asset/identifier.go`) drops values that do not
identify one machine: multicast, locally administered and all-zero MACs, the
shared MACs of VRRP/HSRP/GLBP and of common VPN and dial-up adapters, and
vendor placeholder UUIDs and serials. SCM IDs are stored as `<host>:<id>`.

**Veto.** A candidate found by a strong identifier is skipped when it holds a
different value of a single-valued kind ranked above the one that matched,
and the incoming asset carries that kind. For the name, hostname and IP steps
every single-valued strong kind counts.

**Reviews** (`asset_dedup_review.reason`):

| Reason | Raised by | When |
|---|---|---|
| `shared_ip` | ingest | an IP matched several assets (none of them is used) |
| `identifier_conflict` | ingest | strong identifiers point at different assets, or the incoming name belongs to another asset, or a strong identifier is held by another asset |
| `shared_identifier` | backfill | two assets carry one strong identifier |
| `renamed_host` | backfill | one scanner source reported one IP under two host names |

`evidence` holds what the assets share. A pair an operator rejected is not
raised again.

**API**: `GET /api/v1/assets/{id}/identifiers` (`assets:read`).

## Backfill

The `asset-identity-backfill` controller (start, then hourly) derives
identifiers for every tenant not yet done at the current version
(`asset_identity_backfill`), with the same extraction ingest uses, the
repository ID, and former names (`properties.aliases`, recorded with the
asset's creation time so they are not recent evidence). It queues
`shared_identifier` and `renamed_host` reviews and never merges. Bump
`ingest.IdentityBackfillVersion` to run it again for every tenant.

## Layer 1: Name Normalization

Applied in `NewAsset()` constructor — single chokepoint, every entry point covered.

| Asset Type | Rule | Example |
|---|---|---|
| domain, subdomain | lowercase + strip trailing dot | `Example.COM.` → `example.com` |
| ip_address | `net.ParseIP` canonical, strip brackets/port/CIDR | `[2001:db8::1]:443` → `2001:db8::1` |
| host | DNS normalize or IP canonical | `Web-Server.CORP.` → `web-server.corp` |
| repository | lowercase, strip protocol/SSH/.git, preserve host | `git@GitHub.com:Org/Repo.git` → `github.com/org/repo` |
| application, website, api | URL normalize (lowercase host, strip default port, strip query) | `HTTPS://API.Example.COM:443/v1?k=v` → `https://api.example.com/v1` |
| service/open_port | `host:port:protocol` canonical | `192.0.2.10:443/tcp` → `192.0.2.10:443:tcp` |
| certificate | lowercase, normalize fingerprint | `AB:CD:EF:...` → `abcdef...` |
| database | strip protocol/credentials/query | `postgres://user:pass@db:5432/mydb?ssl=true` → `db:5432/mydb` |
| network, subnet | canonical CIDR (zero host bits) | `192.0.2.100/24` → `192.0.2.0/24` |
| storage/s3_bucket | extract bucket name from URL | `my-bucket.s3.us-east-1.amazonaws.com` → `my-bucket` |
| identity (IAM) | trim only (ARN is case-sensitive) | preserve case |

**Key files**: `pkg/domain/asset/normalize.go`, `normalize_test.go` (158 test cases)

## Correlation (legacy identifiers)

When neither an identifier nor the name matches, the correlator checks:

| Asset Type | Correlation Method | Query |
|---|---|---|
| host, ip_address | IP addresses array, filtered by per-IP `last_seen` | `FindByIPs()` — GIN index on `properties->'ip_addresses'` |
| repository | Integration URL prefix + suffix match | `FindRepositoryByFullName()` |
| cloud_account, IAM | external_id | `FindByExternalID()` |
| certificate | fingerprint property | `FindByPropertyValue("fingerprint", ...)` |

**Safeguards**:
- **IP trust window**: an IP match counts only if that IP was seen on the asset within the last N days (configurable per tenant, default 7; per-IP `last_seen` from `asset_identifiers`, else the asset's `last_seen`). Outside the window the incoming host is not merged or renamed.
- **Unambiguous**: an IP that matches several assets matches none of them; they get a `shared_ip` review.
- **DoS protection**: Skip correlation if asset has > N IPs (configurable, default 20)
- **Type guard**: Only correlate same asset type (host ↔ host, not host ↔ domain)

**Key files**: `internal/app/ingest/correlator.go`, `correlator_test.go`

## Renames

A host matched by an identifier, a hostname or an IP takes the name the scanner reports when:

| Incoming vs current name | Renamed? |
|---|---|
| Better (IP → hostname → FQDN) | Yes |
| Different, same quality (`x` → `y`, `x.corp` → `y.corp`) | Yes, if the IP matched exactly one asset and the name is not already one of its aliases |
| Worse (FQDN → short name, hostname → IP) | No |

The alias rule keeps two sources that name one IP differently from renaming
the asset back and forth on every scan. The cost: renaming a host back to a
name it had before is not followed.

The batch upsert renames rows by id, in its own transaction, before its
`ON CONFLICT (tenant_id, name)` insert. Without that step a renamed row was
inserted under its own id with a new name, failed on `assets_pkey`, and rolled
back every asset in the report.

IP correlation reads addresses from `ip`, `ip_address` (a string or an object
with `address`), `ip_addresses`, and from the CTIS `value` when the asset is
named by hostname and its value is an IP address (the Vuls adapter does this).

A rename by IP alone can still be wrong when another machine took the IP
within the 7-day window and neither reports a strong identifier. A host that
reports one is matched on it first, and a conflicting single-valued identifier
vetoes the IP match.

Every rename writes a `renamed` row to `asset_state_history` (`field=name`,
old and new value, reason `matched by <kind>`); manual renames through the
asset API do too. A rename onto a name another asset holds is not done; it
raises an `identifier_conflict` review instead.

## Aliases

When an asset is renamed (e.g., IP → hostname via correlation), the old name is stored in `properties.aliases[]` (max 10). Search queries check aliases so users can still find assets by old names.

## Per-Tenant Configuration

Settings stored in `tenant.Settings.AssetIdentity`:

```json
{
  "asset_identity": {
    "stale_asset_days": 7,
    "max_ips_per_asset": 20
  }
}
```

`stale_asset_days` is the IP trust window. `0` (or unset) means the system
default of 7 days; a tenant can set 1-365.

**API**: `GET/PATCH /api/v1/tenants/{id}/settings/asset-identity` (admin+)

## Admin Dedup Review

When the data migration detects existing duplicates, they go into a review queue:

```
GET  /api/v1/assets/dedup/reviews              — list pending
POST /api/v1/assets/dedup/reviews/{id}/approve  — merge assets
POST /api/v1/assets/dedup/reviews/{id}/reject   — keep separate
GET  /api/v1/assets/dedup/merge-log             — audit trail
```

A merge moves every row that references the merged assets to the kept asset, then deletes the merged assets. The full list is in `internal/infra/postgres/asset_merge_plan.go`:

- Plain moves: findings, exposures, suppression rules, SLA policies, scan sessions, scan runs, exposure events, runtime telemetry, attack-path nodes, threat-model threats.
- Moves that drop a merged row when the kept asset already has the same unique key: services, components, owners, business units and services, asset groups, compensating controls, sources, scan coverage, asset identifiers, and the derived `user_accessible_assets`.
- Relationships and relationship suggestions. Edges that would become loops are dropped.
- Child assets are re-parented to the kept asset, and pentest campaign asset lists are rewritten.
- Repository data: the kept asset gets a copy of the merged repository row when it has none. Branches move to it. A branch whose name the kept repository already has hands its findings, branch occurrences and components to that branch first.
- Other pending dedup reviews about a merged asset are deleted. Ingest proposes them again if the duplicates remain.
- Left alone on purpose: `asset_state_history` (immutable, removed with the merged asset), `asset_merge_log`, CTEM cycle scope snapshots and ingest report records.

`TestAssetMergeCoversEveryAssetReference` fails when a table in the schema references assets and the merge does not handle it, or when the merge names a table that no longer exists. Before this list existed, the merge skipped two tables that had been dropped (the error was swallowed), rows in 17 tables were deleted by `ON DELETE CASCADE` or orphaned by `SET NULL`, and two tables kept ids of deleted assets.

## Sensor integration

All 5 recon parsers normalize names before sending to API (defense-in-depth):
- subfinder → subdomain lowercase
- dnsx → domain lowercase
- naabu → IP canonical
- httpx → URL lowercase
- katana → URL lowercase

**Key file** (sensor repository): `internal/executor/recon.go`

Shared normalization: the `ctis` module (sdk-go imports it)

## Database

**Migrations**: `000138_asset_identity_resolution` (merge_log, dedup_review, alias index), `000139_normalize_existing_assets` (normalize + detect duplicates), `000243_asset_identifiers` (identifiers, review reason/evidence, `renamed` history, backfill state)

**Indexes used**:
- `idx_assets_props_aliases` — GIN on `properties->'aliases'`
- `idx_assets_props_ip_addresses` — GIN on `properties->'ip_addresses'`
- `idx_assets_props_ip`, `idx_assets_props_hostname` — btree

## Edge Cases (170 documented)

See `docs/rfcs/RFC-001-appendix-edge-cases.md` for the full list covering all 16 asset types.

Key edge cases:
- **IP reuse (DHCP)**: the 7-day IP trust window prevents merging old assets with new hosts
- **NAT/shared IP**: Correlate on private IPs only, skip public behind NAT
- **Race condition**: Accept eventual consistency, next ingest cycle catches duplicates
- **IPv4-mapped IPv6**: `::ffff:192.0.2.1` normalized to `192.0.2.1`
- **Repo platform preserved**: `github.com/org/repo` ≠ `gitlab.com/org/repo`
