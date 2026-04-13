# Asset IP-Hostname Correlation

## Problem

Assets arrive from multiple sources with different identifiers for the same machine:

| Source | Sends | Example |
|--------|-------|---------|
| ESXi / vCenter | hostname + IP | `web-server-01` (IP: `10.0.1.5`) |
| Splunk / SIEM | IP only | `10.0.1.5` |
| CMDB | hostname + FQDN | `web-server-01.internal.corp` |
| Network scan | IP + reverse DNS | `10.0.1.5` (rDNS: `web-server-01`) |

Without correlation, the system creates **duplicate assets** for the same machine.

---

## Solution: 3-Layer Correlation

### Layer 1: Exact Name Match (existing)

```
Ingest "web-server-01" → GetByName("web-server-01") → FOUND → merge & update
```

Uses the `UNIQUE(tenant_id, name)` constraint on the `assets` table.

### Layer 2: Property-Based Correlation (new)

When exact name match fails, search by IP or hostname in properties:

```
Ingest "10.0.1.5" (type=host):
  1. GetByName("10.0.1.5")                    → not found
  2. FindByIP("10.0.1.5")                     → searches:
     - assets.name = '10.0.1.5'
     - assets.properties->>'ip' = '10.0.1.5'
     - assets.properties->'ip_address'->>'address' = '10.0.1.5'
  3. If found → merge into existing asset
  4. If not found → create new host with name="10.0.1.5"
```

```
Ingest "web-server-01" (type=host, properties.ip="10.0.1.5"):
  1. GetByName("web-server-01")               → not found
  2. FindByHostname("web-server-01")           → searches:
     - assets.name = 'web-server-01'
     - assets.properties->>'hostname' = 'web-server-01'
     - assets.properties->'ip_address'->>'hostname' = 'web-server-01'
  3. Found host "10.0.1.5" with matching hostname in properties
  4. Rename "10.0.1.5" → "web-server-01" (hostname is more descriptive)
  5. Merge properties from both sources
```

### Layer 3: Manual Merge (future)

Admin UI to manually merge two assets into one when auto-correlation misses.

---

## Data Flow Diagram

```
┌──────────────────────────────────────────────────────────┐
│                    CreateAsset / Ingest                    │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  1. GetByName(input.name)                                 │
│     ├─ FOUND → mergeAndUpdateExisting()                   │
│     └─ NOT FOUND ↓                                        │
│                                                           │
│  2. correlateByIPOrHostname(input.name)                   │
│     ├─ looksLikeIP(name)?                                 │
│     │   YES → FindByIP(name)                              │
│     │         ├─ FOUND → merge (IP data into existing)    │
│     │         └─ NOT FOUND ↓                              │
│     │                                                     │
│     │   NO  → FindByHostname(name)                        │
│     │         ├─ FOUND → rename IP→hostname + merge       │
│     │         └─ NOT FOUND ↓                              │
│     │                                                     │
│  3. Create new asset                                      │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---

## Freshness-Aware Property Merge

When merging properties from multiple sources, **newer data wins**:

```sql
-- In UpsertBatch (batch ingestion)
properties = CASE
    WHEN EXCLUDED.last_seen >= COALESCE(assets.last_seen, '1970-01-01'::timestamptz)
    THEN merge_jsonb_deep(assets.properties, EXCLUDED.properties)  -- new overrides old
    ELSE merge_jsonb_deep(EXCLUDED.properties, assets.properties)  -- old stays, new fills gaps
END
```

**Example:**
```
Source A scans at 10:00 today   → ingest at 10:05 → last_seen = 10:00 today
Source B scans at 14:00 yesterday → ingest at 11:00 today → last_seen = 14:00 yesterday

Result: Source A data wins (10:00 today > 14:00 yesterday)
        Source B data only fills missing fields (does not overwrite)
```

---

## Property Format Standard

After migration 000124, all host IP data uses a single format:

```json
// ✅ STANDARD (host)
{
  "type": "host",
  "properties": {
    "ip_addresses": ["10.0.1.5", "10.0.2.5"],   // array — multiple IPs
    "hostname": "web-server-01"                   // top-level string
  }
}

// ✅ STANDARD (ip_address type — unchanged, uses CTIS technical schema)
{
  "type": "ip_address",
  "properties": {
    "ip_address": {
      "address": "203.0.113.5",    // structured object
      "version": 4,
      "hostname": "web-server-01",
      "asn": 13335,
      "ports": [80, 443]
    }
  }
}

// ❌ DEPRECATED (auto-migrated by 000124)
{ "ip": "10.0.1.5" }              // single string — converted to ip_addresses[]
```

---

## Asset Type: `host` vs `ip_address`

| Type | Represents | Created By | Example |
|------|-----------|------------|---------|
| `host` | Physical/virtual machine | ESXi, CMDB, agent, Splunk logs | `web-server-01`, `10.0.1.5` (placeholder) |
| `ip_address` | Network endpoint | DNS resolution, network scan | `203.0.113.5` (from domain A record) |

**Key rules:**
- Log sources (Splunk, SIEM) → always create `host` (even if only IP is known)
- DNS resolution → creates `ip_address` (and `resolves_to` relationship)
- A `host` can have multiple IPs (multi-NIC)
- An `ip_address` can be shared (load balancer VIP)

**Relationship graph:**
```
domain "example.com"
    │ resolves_to
    ▼
ip_address "203.0.113.5"       ← DNS endpoint
    │ runs_on
    ▼
host "web-server-01"           ← actual machine
    │ runs_on
    ▼
container "nginx-prod"         ← workload
```

---

## Auto-Rename Logic

When a hostname arrives for an IP-named host:

```
Before: host { name: "10.0.1.5", properties: { ip: "10.0.1.5" } }
After:  host { name: "web-server-01", properties: { ip: "10.0.1.5", hostname: "web-server-01" } }
```

The rename only happens when:
1. Existing asset name `looksLikeIP()` (e.g., `10.0.1.5`)
2. New input name does NOT look like IP (e.g., `web-server-01`)
3. Correlation found via hostname property match

---

## Database Indexes

Migration `000123_asset_ip_correlation_indexes`:

```sql
-- Flat IP lookup (single IP string)
CREATE INDEX idx_assets_props_ip ON assets ((properties->>'ip'))
    WHERE properties->>'ip' IS NOT NULL;

-- Structured IP lookup (ip_address type)
CREATE INDEX idx_assets_props_ip_addr ON assets ((properties->'ip_address'->>'address'))
    WHERE properties->'ip_address'->>'address' IS NOT NULL;

-- Multi-IP array lookup (host with multiple IPs)
CREATE INDEX idx_assets_props_ip_addresses ON assets USING GIN ((properties->'ip_addresses'))
    WHERE properties->'ip_addresses' IS NOT NULL;

-- Hostname lookup
CREATE INDEX idx_assets_props_hostname ON assets ((properties->>'hostname'))
    WHERE properties->>'hostname' IS NOT NULL;

-- Structured hostname lookup (ip_address type)
CREATE INDEX idx_assets_props_ip_hostname ON assets ((properties->'ip_address'->>'hostname'))
    WHERE properties->'ip_address'->>'hostname' IS NOT NULL;
```

All indexes are **partial** (WHERE ... IS NOT NULL) to minimize storage and only index assets that have the relevant property.

---

## Multi-IP Hosts

A host can have multiple IP addresses (multi-NIC, dual-stack IPv4/IPv6):

```json
{
  "name": "web-server-01",
  "type": "host",
  "properties": {
    "hostname": "web-server-01",
    "ip_addresses": ["10.0.1.5", "10.0.2.5", "fd00::5"],
    "ip": "10.0.1.5",
    "mac_addresses": ["00:50:56:a1:b2:c3", "00:50:56:a1:b2:c4"]
  }
}
```

**Correlation searches ALL IP formats:**
- `properties->>'ip'` — single IP string (legacy/simple sources)
- `properties->'ip_addresses' ? '10.0.1.5'` — JSONB array contains operator
- `properties->'ip_address'->>'address'` — structured ip_address type

**When Splunk sends `10.0.2.5`** (secondary NIC):
1. `FindByIP("10.0.2.5")` → matches `ip_addresses` array → returns `web-server-01`
2. Merge findings into existing host — no duplicate

---

## Key Files

| File | Purpose |
|------|---------|
| `internal/app/asset_service.go` | `correlateByIPOrHostname()`, `mergeAndUpdateExisting()`, `looksLikeIP()` |
| `internal/infra/postgres/asset_repository.go` | `FindByIP()`, `FindByHostname()` |
| `pkg/domain/asset/repository.go` | Interface definitions |
| `migrations/000123_asset_ip_correlation_indexes.up.sql` | Property indexes |
