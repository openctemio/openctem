# Asset Identity Resolution & Deduplication

> **Status**: Production-ready | **Origin**: RFC-001 (completed 2026-04-15)

## Overview

Multi-layer deduplication system that ensures the same real-world entity maps to a single asset regardless of how different sources name it.

**Problem solved**: Splunk sends `192.168.1.10`, Qualys sends `web-server-01`, Nessus sends `web-server-01.corp` — all for the same host. Without identity resolution, these create 3 separate assets with fragmented findings and incorrect risk scores.

## Architecture

```
Incoming Asset
    │
    ▼
┌──────────────────────┐
│ Layer 1: Normalize    │  Deterministic, idempotent
│ (16 asset types)      │  dns lowercase, IP canonical, repo format, URL strip
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Layer 2: Name Match   │  Existing behavior — ON CONFLICT (tenant_id, name)
│ (GetByNames batch)    │
└──────────┬───────────┘
           │ no match?
           ▼
┌──────────────────────┐
│ Layer 3: Correlate    │  IP, external_id, fingerprint, repo suffix
│ (per asset type)      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Layer 4: Upsert       │  ON CONFLICT merge properties, tags
│ (unchanged)           │
└──────────────────────┘
```

## Layer 1: Name Normalization

Applied in `NewAsset()` constructor — single chokepoint, every entry point covered.

| Asset Type | Rule | Example |
|---|---|---|
| domain, subdomain | lowercase + strip trailing dot | `Example.COM.` → `example.com` |
| ip_address | `net.ParseIP` canonical, strip brackets/port/CIDR | `[2001:db8::1]:443` → `2001:db8::1` |
| host | DNS normalize or IP canonical | `Web-Server.CORP.` → `web-server.corp` |
| repository | lowercase, strip protocol/SSH/.git, preserve host | `git@GitHub.com:Org/Repo.git` → `github.com/org/repo` |
| application, website, api | URL normalize (lowercase host, strip default port, strip query) | `HTTPS://API.Example.COM:443/v1?k=v` → `https://api.example.com/v1` |
| service/open_port | `host:port:protocol` canonical | `192.168.1.10:443/tcp` → `192.168.1.10:443:tcp` |
| certificate | lowercase, normalize fingerprint | `AB:CD:EF:...` → `abcdef...` |
| database | strip protocol/credentials/query | `postgres://user:pass@db:5432/mydb?ssl=true` → `db:5432/mydb` |
| network, subnet | canonical CIDR (zero host bits) | `192.168.1.100/24` → `192.168.1.0/24` |
| storage/s3_bucket | extract bucket name from URL | `my-bucket.s3.us-east-1.amazonaws.com` → `my-bucket` |
| identity (IAM) | trim only (ARN is case-sensitive) | preserve case |

**Key files**: `pkg/domain/asset/normalize.go`, `normalize_test.go` (158 test cases)

## Layer 3: Correlation

When name match fails, correlator checks alternative identifiers:

| Asset Type | Correlation Method | Query |
|---|---|---|
| host, ip_address | IP addresses array | `FindByIPs()` — GIN index on `properties->'ip_addresses'` |
| repository | Integration URL prefix + suffix match | `FindRepositoryByFullName()` |
| cloud_account, IAM | external_id | `FindByExternalID()` |
| certificate | fingerprint property | `FindByPropertyValue("fingerprint", ...)` |

**Safeguards**:
- **IP trust window**: an IP match counts only if the existing asset was seen within the last N days (configurable per tenant, default 7). Outside the window the incoming host is not merged or renamed.
- **DoS protection**: Skip correlation if asset has > N IPs (configurable, default 20)
- **Type guard**: Only correlate same asset type (host ↔ host, not host ↔ domain)

**Key files**: `internal/app/ingest/correlator.go`, `correlator_test.go`

## Renames

A host matched by IP takes the name the scanner reports when:

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

Renames rely on an IP match, so a host whose IP is reused by another machine
within the IP trust window (7 days by default; it was 30 before 2026-10-01)
can be renamed wrongly. Hosts with stable
identifiers (MAC address, sensor host ID, cloud instance ID) are not matched
on those identifiers yet.

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

- Plain moves: findings, exposures, suppression rules, SLA policies, scan sessions, pipeline runs, exposure events, runtime telemetry, attack-path nodes, threat-model threats.
- Moves that drop a merged row when the kept asset already has the same unique key: services, components, owners, business units and services, asset groups, compensating controls, sources, scan coverage, and the derived `user_accessible_assets`.
- Relationships and relationship suggestions. Edges that would become loops are dropped.
- Child assets are re-parented to the kept asset, and pentest campaign asset lists are rewritten.
- Repository data: the kept asset gets a copy of the merged repository row when it has none. Branches move to it. A branch whose name the kept repository already has hands its findings, branch occurrences and components to that branch first.
- Other pending dedup reviews about a merged asset are deleted. Ingest proposes them again if the duplicates remain.
- Left alone on purpose: `asset_state_history` (immutable, removed with the merged asset), `asset_merge_log`, CTEM cycle scope snapshots and ingest report records.

`TestAssetMergeCoversEveryAssetReference` fails when a table in the schema references assets and the merge does not handle it, or when the merge names a table that no longer exists. Before this list existed, the merge skipped two tables that had been dropped (the error was swallowed), rows in 17 tables were deleted by `ON DELETE CASCADE` or orphaned by `SET NULL`, and two tables kept ids of deleted assets.

## Agent Integration

All 5 recon parsers normalize names before sending to API (defense-in-depth):
- subfinder → subdomain lowercase
- dnsx → domain lowercase
- naabu → IP canonical
- httpx → URL lowercase
- katana → URL lowercase

**Key file**: `agent/internal/executor/recon.go`

Shared normalization library: `sdk-go/pkg/ctis/normalize.go`

## Database

**Migrations**: `000138_asset_identity_resolution` (merge_log, dedup_review, alias index), `000139_normalize_existing_assets` (normalize + detect duplicates)

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
- **IPv4-mapped IPv6**: `::ffff:192.168.1.1` normalized to `192.168.1.1`
- **Repo platform preserved**: `github.com/org/repo` ≠ `gitlab.com/org/repo`
