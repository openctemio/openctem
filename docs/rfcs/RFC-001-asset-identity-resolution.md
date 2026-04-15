# RFC-001: Asset Identity Resolution & Deduplication

- **Status**: Completed — moved to [docs/architecture/asset-identity-resolution.md](../architecture/asset-identity-resolution.md)
- **Author**: OpenCTEM Core Team
- **Created**: 2026-04-15
- **Updated**: 2026-04-15

---

## 0. Asset Type Taxonomy & Dedup Strategy Matrix

### Core Types + Sub Types (TypeAliases system)

```
CORE TYPE        SUB_TYPE              NAMING PATTERN              NORMALIZE          CORRELATE BY
─────────        ────────              ──────────────              ─────────          ────────────
domain           —                     example.com                 lowercase+trim.    —
subdomain        —                     api.example.com             lowercase+trim.    —
certificate      —                     subject CN / serial         lowercase+trim.    fingerprint
ip_address       —                     192.168.1.1                 net.ParseIP        —

host             —                     hostname or IP              DNS norm           IP addresses
                 compute               vm-name                     DNS norm           IP addresses
                 serverless            function-name               lowercase          —

service          —                     host:port:proto             canonical form     parent host
                 http                  https://host:port           URL norm           parent host
                 open_port             host:port:proto             canonical form     parent host
                 discovered_url        https://host/path           URL norm           parent host

application      —                     app name or URL             URL norm           —
                 website               https://example.com         URL norm           —
                 web_application       https://app.example.com     URL norm           —
                 api                   https://api.example.com/v1  URL norm           —
                 mobile_app            com.company.app             lowercase          bundle ID

repository       —                     github.com/org/repo         repo norm          integration URL

cloud_account    —                     account alias               trim               account ID
storage          —                     bucket/registry name        trim               —
                 s3_bucket             bucket-name                 strip s3://        —
                 container_registry    registry.io/path            URL norm           —

container        —                     container name/ID           lowercase          image SHA

kubernetes       —                     cluster or ns name          lowercase          —
                 cluster               cluster-name                lowercase          —
                 namespace             cluster/namespace           lowercase          —

database         —                     connection or name          host:port:db       —
                 data_store            store name                  lowercase          —

network          —                     CIDR or name                CIDR canonical     —
                 firewall              fw-name                     lowercase          —
                 load_balancer         lb-name                     lowercase          —
                 vpc                   vpc-id or name              lowercase          VPC ID
                 subnet                CIDR                        CIDR canonical     —

identity         —                     username or ARN             trim               ARN/external_id
                 iam_user              username or ARN             trim               ARN/external_id
                 iam_role              role-name or ARN            trim               ARN/external_id
                 service_account       sa@project.iam              lowercase          ARN/external_id

unclassified     —                     anything                    trim               —
```

### Service type — special considerations

`service` gộp từ `http_service`, `open_port`, `discovered_url` — đây là 3 concept khác nhau:

| Sub Type | Layer | Example Name | Represents |
|---|---|---|---|
| `open_port` | L4 | `192.168.1.10:443:tcp` | Raw port scan result |
| `http` | L7 | `https://192.168.1.10:443` | HTTP service on port |
| `discovered_url` | L7 path | `https://192.168.1.10/login` | Specific endpoint |

**Rule**: Khác sub_type → KHÔNG merge. `open_port:443` và `http_service:https://host:443` là 2 assets riêng — liên kết qua relationship `exposes`.

**Normalization cho service:**
```go
func normalizeServiceName(name string, subType string) string {
    switch subType {
    case "open_port", "":
        // Canonical: "host:port:protocol" (lowercase)
        // Input: "192.168.1.10:443/tcp" → "192.168.1.10:443:tcp"
        // Input: "192.168.1.10:443"     → "192.168.1.10:443:tcp" (default tcp)
        return normalizePortIdentifier(name)
    case "http":
        return normalizeURL(name)
    case "discovered_url":
        return normalizeURL(name) // Keep path, strip query/fragment
    default:
        return strings.ToLower(strings.TrimSpace(name))
    }
}

func normalizePortIdentifier(name string) string {
    // Parse "host:port/proto" or "host:port:proto" or "host:port"
    // Normalize host (IP canonical or DNS lowercase)
    // Default protocol to "tcp"
    // Output: "normalized_host:port:protocol"
    host, port, proto := parsePortIdentifier(name)
    host = normalizeHostName(host)
    if proto == "" { proto = "tcp" }
    return host + ":" + port + ":" + proto
}
```

### Dedup risk summary

| Risk | Core Types |
|---|---|
| VERY HIGH | `host`, `repository` |
| HIGH | `domain`, `subdomain`, `service`, `application`, `certificate`, `cloud_account`, `identity` |
| MEDIUM | `ip_address`, `container`, `kubernetes`, `database`, `storage` |
| LOW | `network`, `unclassified` |

---

## 1. Problem Statement

OpenCTEM deduplicates assets using a single unique constraint: `(tenant_id, name)`. This causes **duplicate assets** when different sources provide different identifiers for the same real-world entity.

### Real-world example

```
Splunk sends:   name="192.168.1.10"       (only has IP)
Qualys sends:   name="web-server-01"       (hostname + same IP in properties)
Nessus sends:   name="web-server-01.corp"  (FQDN + same IP)

Result: 3 separate assets for 1 physical server
        Findings split across 3 assets
        Risk score inaccurate
        Dashboard metrics inflated
```

### Scope of impact

| Asset Type | Risk Level | Duplicate Scenario |
|---|---|---|
| Host | VERY HIGH | hostname vs IP vs FQDN for same server |
| Repository | VERY HIGH | `github.com/org/repo` vs `org/repo` vs `repo` |
| Domain/Subdomain | HIGH | `example.com` vs `Example.COM` (case) |
| API/Website | HIGH | URL protocol/trailing slash variations |
| Cloud Account | HIGH | account alias vs account ID |
| IAM User/Role | HIGH | ARN vs username |
| Certificate | HIGH | serial vs fingerprint vs subject CN |
| IP Address | MEDIUM | IPv6 normalization (`::1` vs `0:0:0:0:0:0:0:1`) |

---

## 2. Design Goals

1. **Same physical entity = 1 asset** regardless of source naming
2. **No breaking changes** to existing data or API contracts
3. **Backward compatible** — old data works, new ingests deduplicate correctly
4. **Performance** — no significant impact on ingest throughput
5. **Auditable** — log when assets are merged/renamed

---

## 3. Architecture Overview

Add two layers **before** the existing `UpsertBatch()`:

```
                    CURRENT                              PROPOSED
                    ───────                              ────────
                                                  ┌──────────────────┐
                                                  │  Layer 1:        │
                                                  │  Normalize Name  │
                                                  │  (deterministic) │
                                                  └────────┬─────────┘
                                                           │
  ┌──────────────┐                                ┌────────▼─────────┐
  │ getAssetName │                                │  Layer 2:        │
  │ GetByNames() │    ──── becomes ────>          │  Correlate by    │
  │ UpsertBatch  │                                │  alt identifiers │
  └──────────────┘                                └────────┬─────────┘
                                                           │
                                                  ┌────────▼─────────┐
                                                  │  Layer 3:        │
                                                  │  UpsertBatch     │
                                                  │  (unchanged)     │
                                                  └──────────────────┘
```

---

## 4. Layer 1: Name Normalization

### 4.1 Design

A **pure function** that converts any asset name to a **canonical form** before storage. Applied at every entry point: CTIS ingest, Nessus import, CSV import, API create, API update.

```go
// File: pkg/domain/asset/normalize.go

// NormalizeName returns the canonical form of an asset name for the given type.
// This is called before storage and before lookup — ensuring consistent dedup.
func NormalizeName(name string, assetType AssetType) string {
    // Step 1: Common normalization (all types)
    name = strings.TrimSpace(name)
    name = strings.ReplaceAll(name, "\x00", "")
    if name == "" {
        return ""
    }

    // Step 2: Type-specific normalization
    switch assetType {
    case AssetTypeDomain, AssetTypeSubdomain:
        return normalizeDNSName(name)
    case AssetTypeHost:
        return normalizeHostName(name)
    case AssetTypeIPAddress:
        return normalizeIPAddress(name)
    case AssetTypeRepository, AssetTypeCodeRepo:
        return normalizeRepoName(name)
    case AssetTypeAPI, AssetTypeWebsite, AssetTypeWebApplication:
        return normalizeURL(name)
    case AssetTypeCertificate:
        return normalizeCertName(name)
    case AssetTypeCloudAccount:
        return normalizeCloudAccount(name)
    default:
        return name
    }
}
```

### 4.2 Normalization rules per type

#### DNS Names (domain, subdomain, host)

```go
func normalizeDNSName(name string) string {
    // DNS is case-insensitive per RFC 4343
    name = strings.ToLower(name)
    // Strip trailing dot (FQDN notation)
    name = strings.TrimRight(name, ".")
    // Strip leading/trailing whitespace (already done but safe)
    name = strings.TrimSpace(name)
    return name
}
```

**Before → After:**
| Input | Output |
|---|---|
| `Example.COM` | `example.com` |
| `api.example.com.` | `api.example.com` |
| `API.EXAMPLE.COM.` | `api.example.com` |

#### Host Names

```go
func normalizeHostName(name string) string {
    // If it's an IP address, normalize as IP
    if ip := net.ParseIP(name); ip != nil {
        return ip.String() // Canonical form (strips leading zeros, shortens IPv6)
    }
    // Otherwise treat as DNS name
    return normalizeDNSName(name)
}
```

**Before → After:**
| Input | Output |
|---|---|
| `Web-Server-01` | `web-server-01` |
| `192.168.001.010` | `192.168.1.10` |
| `2001:0db8:0000::0001` | `2001:db8::1` |
| `server.corp.local.` | `server.corp.local` |

#### IP Addresses

```go
func normalizeIPAddress(name string) string {
    ip := net.ParseIP(name)
    if ip == nil {
        return strings.TrimSpace(name)
    }
    return ip.String() // Go's net.IP.String() produces canonical form
}
```

`net.ParseIP` + `.String()` handles:
- IPv4 leading zeros: `192.168.001.001` → `192.168.1.1`
- IPv6 shorthand: `2001:0db8::1` → `2001:db8::1`
- IPv6 full form: `2001:0db8:0000:0000:0000:0000:0000:0001` → `2001:db8::1`

#### Repository Names

**Key principle**: `host` (platform) là một phần identity — `github.com/org/repo` và `gitlab.com/org/repo` là 2 repo khác nhau. Không bao giờ strip host.

Khi repo name không có host (e.g., `org/repo` từ scanner), **KHÔNG tự gán host** vì không biết chắc platform. Thay vào đó, dùng **correlation** (Layer 2) dựa trên context từ integration/tool.

```go
func normalizeRepoName(name string) string {
    // Step 1: Normalize protocol prefixes
    name = strings.TrimPrefix(name, "https://")
    name = strings.TrimPrefix(name, "http://")

    // Step 2: Handle SSH format: git@github.com:org/repo → github.com/org/repo
    if strings.HasPrefix(name, "git@") {
        name = strings.TrimPrefix(name, "git@")
        // Only replace first ":" which separates host from path
        if idx := strings.Index(name, ":"); idx > 0 {
            name = name[:idx] + "/" + name[idx+1:]
        }
    }

    // Step 3: Remove .git suffix
    name = strings.TrimSuffix(name, ".git")

    // Step 4: Lowercase (GitHub/GitLab/Bitbucket are case-insensitive)
    name = strings.ToLower(name)

    // Step 5: Remove trailing slash
    name = strings.TrimRight(name, "/")

    return name
}
```

**Before → After:**
| Input | Output | Note |
|---|---|---|
| `https://github.com/Org/Repo` | `github.com/org/repo` | Host preserved |
| `git@github.com:Org/Repo.git` | `github.com/org/repo` | SSH → canonical |
| `https://gitlab.com/Org/Repo` | `gitlab.com/org/repo` | Different platform, different asset |
| `github.com/Org/Repo.git` | `github.com/org/repo` | Strip .git |
| `Org/Repo` | `org/repo` | No host — kept as-is |
| `repo` | `repo` | Bare name — kept as-is |

**Correlation for repos without host (Layer 2):**

Khi ingest nhận `org/repo` (không có host), correlator sẽ:

```go
func (c *AssetCorrelator) CorrelateRepository(
    ctx context.Context,
    tenantID shared.ID,
    incomingName string,           // e.g., "org/repo"
    toolIntegrationURL string,     // e.g., "https://github.com" from integration config
) (*CorrelationResult, error) {
    // If name already has host → no correlation needed
    if hasRepoHost(incomingName) {
        return &CorrelationResult{}, nil
    }

    // Strategy 1: Tool's integration tells us the platform
    // If this scan came from a GitHub integration, prefix with "github.com/"
    if toolIntegrationURL != "" {
        host := extractHost(toolIntegrationURL) // "github.com"
        fullName := host + "/" + incomingName    // "github.com/org/repo"
        existing, _ := c.repo.GetByName(ctx, tenantID, fullName)
        if existing != nil {
            return &CorrelationResult{
                Matched:         existing,
                CorrelationType: "repo_integration",
            }, nil
        }
    }

    // Strategy 2: Fuzzy match — find repos ending with "/org/repo"
    existing, _ := c.repo.FindRepositoryByFullName(ctx, tenantID, incomingName)
    if existing != nil {
        // Only 1 match → confident correlation
        return &CorrelationResult{
            Matched:         existing,
            CorrelationType: "repo_suffix",
        }, nil
    }

    // No match → create new (name stays as "org/repo")
    return &CorrelationResult{}, nil
}

// hasRepoHost checks if a repo name includes a platform host.
func hasRepoHost(name string) bool {
    knownHosts := []string{
        "github.com/", "gitlab.com/", "bitbucket.org/",
        "dev.azure.com/", "ssh.dev.azure.com/",
    }
    for _, h := range knownHosts {
        if strings.HasPrefix(name, h) {
            return true
        }
    }
    // Generic: has a dot before the first slash → likely a hostname
    if idx := strings.Index(name, "/"); idx > 0 {
        return strings.Contains(name[:idx], ".")
    }
    return false
}
```

**Edge cases:**

| Scenario | Behavior |
|---|---|
| `github.com/org/repo` + `gitlab.com/org/repo` | 2 assets (different platforms, correct) |
| `github.com/org/repo` + `org/repo` (from GitHub integration) | 1 asset (correlated via integration URL) |
| `org/repo` (from Semgrep, no integration) + `github.com/org/repo` | Fuzzy match: merge if only 1 `*/org/repo` exists |
| `org/repo` (from Semgrep) + both `github.com/org/repo` AND `gitlab.com/org/repo` exist | Ambiguous — create new `org/repo`, no auto-merge |
| `repo` (bare name, no org) | No correlation possible — stays as separate asset |

#### URL Names (API, Website)

```go
func normalizeURL(name string) string {
    // Lowercase the hostname portion
    // Strip default ports (:443 for https, :80 for http)
    // Remove trailing slash
    // Keep path as-is (paths can be case-sensitive)

    u, err := url.Parse(name)
    if err != nil {
        return strings.ToLower(strings.TrimSpace(name))
    }

    // Lowercase scheme and host
    scheme := strings.ToLower(u.Scheme)
    host := strings.ToLower(u.Host)

    // Strip default ports
    if (scheme == "https" && strings.HasSuffix(host, ":443")) {
        host = strings.TrimSuffix(host, ":443")
    }
    if (scheme == "http" && strings.HasSuffix(host, ":80")) {
        host = strings.TrimSuffix(host, ":80")
    }

    // Reconstruct: scheme://host/path (no query, no fragment)
    path := strings.TrimRight(u.Path, "/")

    if scheme != "" && host != "" {
        return scheme + "://" + host + path
    }
    // No scheme — just lowercase host part
    return strings.ToLower(name)
}
```

**Before → After:**
| Input | Output |
|---|---|
| `HTTPS://API.Example.COM/v1/` | `https://api.example.com/v1` |
| `https://api.example.com:443/` | `https://api.example.com` |
| `http://app.test:80/path` | `http://app.test/path` |

#### Certificate Names

```go
func normalizeCertName(name string) string {
    // Lowercase (subject CN is case-insensitive for domains)
    name = strings.ToLower(name)
    // Strip trailing dot if present
    name = strings.TrimRight(name, ".")
    return name
}
```

#### Cloud Account Names

```go
func normalizeCloudAccount(name string) string {
    // Keep as-is — account IDs are already normalized by cloud providers
    return strings.TrimSpace(name)
}
```

### 4.3 Integration points

Apply `NormalizeName()` at every asset creation/update entry point:

| Entry Point | File | Change |
|---|---|---|
| CTIS ingest | `processor_assets.go:createAssetFromCTIS()` | Before `NewAsset()` |
| CTIS batch name collection | `processor_assets.go:ProcessBatch()` line 104 | Before adding to `names[]` |
| Nessus import | `asset_import_service.go:ImportNessus()` | Before `NewAssetWithTenant()` |
| CSV import | `asset_import_service.go:ImportCSVAssets()` | Before `NewAssetWithTenant()` |
| API create | `handler/asset_handler.go:Create()` | Before service call |
| API update name | `asset/entity.go:UpdateName()` | Inside method |
| Entity constructor | `asset/entity.go:NewAsset()` | Apply after null byte strip |

### 4.4 Migration for existing data

One-time migration to normalize existing asset names:

```sql
-- Migration: 000XXX_normalize_asset_names.up.sql

-- Step 1: Normalize domain/subdomain names (lowercase, strip trailing dot)
UPDATE assets
SET name = LOWER(RTRIM(name, '.')),
    updated_at = NOW()
WHERE asset_type IN ('domain', 'subdomain')
  AND (name != LOWER(name) OR name LIKE '%.');

-- Step 2: Normalize host names
UPDATE assets
SET name = LOWER(RTRIM(name, '.')),
    updated_at = NOW()
WHERE asset_type = 'host'
  AND name !~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  -- Skip IPs
  AND (name != LOWER(name) OR name LIKE '%.');

-- Step 3: Normalize repository names
UPDATE assets
SET name = LOWER(
      RTRIM(
        REGEXP_REPLACE(
          REGEXP_REPLACE(
            REGEXP_REPLACE(name, '^https?://', ''),
            '^git@([^:]+):', '\1/', 'g'
          ),
          '\.git$', ''
        ),
        '/'
      )
    ),
    updated_at = NOW()
WHERE asset_type IN ('repository', 'code_repo')
  AND (
    name ~ '^https?://'
    OR name ~ '^git@'
    OR name ~ '\.git$'
    OR name != LOWER(name)
  );

-- Step 4: Handle duplicate names created by normalization
-- (merge duplicates — keep the oldest, update references)
-- This is handled by the merge procedure below.
```

**Merge duplicates after normalization:**

```sql
-- Find groups that became duplicates after normalization
-- For each group: keep the one with most findings, merge others into it
WITH duplicates AS (
  SELECT
    tenant_id,
    LOWER(RTRIM(name, '.')) AS normalized_name,
    array_agg(id ORDER BY finding_count DESC, created_at ASC) AS ids,
    COUNT(*) AS cnt
  FROM assets
  WHERE asset_type IN ('domain', 'subdomain', 'host', 'repository', 'code_repo')
  GROUP BY tenant_id, LOWER(RTRIM(name, '.'))
  HAVING COUNT(*) > 1
)
SELECT tenant_id, normalized_name, ids, cnt FROM duplicates;

-- For each duplicate group:
-- 1. Keep ids[1] (most findings)
-- 2. UPDATE findings SET asset_id = ids[1] WHERE asset_id = ANY(ids[2:])
-- 3. UPDATE asset_services SET asset_id = ids[1] WHERE asset_id = ANY(ids[2:])
-- 4. UPDATE asset_relationships ... (both source and target)
-- 5. DELETE FROM assets WHERE id = ANY(ids[2:])
-- 6. Log merge in asset_merge_log
```

**Risk mitigation:**
- Run in transaction
- Dry-run first: query `WITH duplicates` to see how many groups affected
- Log every merge to `asset_merge_log` table

---

## 5. Layer 2: Identity Correlation

### 5.1 Design

For asset types where name alone isn't sufficient (hosts, cloud accounts, IAM), add a **correlation step** that checks alternative identifiers before creating a new asset.

```go
// File: internal/app/ingest/correlator.go

// AssetCorrelator resolves incoming assets against existing ones
// using alternative identifiers beyond name.
type AssetCorrelator struct {
    repo   AssetLookupRepo
    logger *logger.Logger
}

type AssetLookupRepo interface {
    FindByIP(ctx context.Context, tenantID shared.ID, ip string) (*asset.Asset, error)
    FindByHostname(ctx context.Context, tenantID shared.ID, hostname string) (*asset.Asset, error)
    FindByExternalID(ctx context.Context, tenantID shared.ID, externalID string) (*asset.Asset, error)
    FindByPropertyValue(ctx context.Context, tenantID shared.ID, key, value string) (*asset.Asset, error)
}

// CorrelationResult tells the caller what to do with the incoming asset.
type CorrelationResult struct {
    // Matched is the existing asset that matches the incoming one.
    // nil if no match found (caller should create new).
    Matched *asset.Asset

    // ShouldRename indicates the existing asset should be renamed
    // to a better name (e.g., IP → hostname).
    ShouldRename bool
    NewName      string

    // CorrelationType records how the match was found (for audit).
    CorrelationType string // "name", "ip", "hostname", "external_id", "fingerprint"
}
```

### 5.2 Correlation strategy per asset type

#### Host correlation

```go
func (c *AssetCorrelator) CorrelateHost(
    ctx context.Context,
    tenantID shared.ID,
    incomingName string,
    properties map[string]any,
) (*CorrelationResult, error) {

    // Step 1: Extract all IPs from incoming properties
    ips := extractAllIPs(properties, incomingName)

    // Step 2: For each IP, check if an existing asset has it
    for _, ip := range ips {
        existing, err := c.repo.FindByIP(ctx, tenantID, ip)
        if err != nil {
            return nil, err
        }
        if existing == nil {
            continue
        }

        // Found match by IP
        result := &CorrelationResult{
            Matched:         existing,
            CorrelationType: "ip",
        }

        // Should we rename the existing asset to a better name?
        // Only if incoming has a hostname and existing is named by IP
        if !looksLikeIP(incomingName) && looksLikeIP(existing.Name()) {
            result.ShouldRename = true
            result.NewName = incomingName
        }

        return result, nil
    }

    // Step 3: If incoming name is an IP, check by hostname from properties
    if hostname, ok := properties["hostname"].(string); ok && hostname != "" {
        existing, err := c.repo.FindByHostname(ctx, tenantID, hostname)
        if err != nil {
            return nil, err
        }
        if existing != nil {
            return &CorrelationResult{
                Matched:         existing,
                CorrelationType: "hostname",
            }, nil
        }
    }

    // No correlation found
    return &CorrelationResult{}, nil
}
```

**Priority chain for name quality (higher = better):**

```go
// nameQuality returns a score for how "good" an asset name is.
// Higher score = more stable, more human-readable identifier.
func nameQuality(name string) int {
    if name == "" {
        return 0
    }
    // IP address — least preferred (can change via DHCP)
    if looksLikeIP(name) {
        return 10
    }
    // Short hostname without domain (e.g., "server01")
    if !strings.Contains(name, ".") {
        return 30
    }
    // FQDN (e.g., "server01.corp.local")
    return 50
}
```

**Rename logic:**
- Only rename if incoming name has **higher quality** than existing
- Log the rename to `asset_merge_log`
- Findings/relationships use UUID — not affected by rename

#### Cloud Account / IAM correlation

```go
func (c *AssetCorrelator) CorrelateByExternalID(
    ctx context.Context,
    tenantID shared.ID,
    incomingName string,
    externalID string,
    assetType asset.AssetType,
) (*CorrelationResult, error) {
    if externalID == "" {
        return &CorrelationResult{}, nil
    }

    existing, err := c.repo.FindByExternalID(ctx, tenantID, externalID)
    if err != nil {
        return nil, err
    }
    if existing == nil || existing.AssetType() != assetType {
        return &CorrelationResult{}, nil
    }

    return &CorrelationResult{
        Matched:         existing,
        CorrelationType: "external_id",
    }, nil
}
```

#### Certificate correlation

```go
func (c *AssetCorrelator) CorrelateCertificate(
    ctx context.Context,
    tenantID shared.ID,
    properties map[string]any,
) (*CorrelationResult, error) {
    // Certificates are uniquely identified by fingerprint
    fingerprint, _ := properties["fingerprint"].(string)
    if fingerprint == "" {
        return &CorrelationResult{}, nil
    }

    existing, err := c.repo.FindByPropertyValue(ctx, tenantID, "fingerprint", fingerprint)
    if err != nil {
        return nil, err
    }
    if existing == nil {
        return &CorrelationResult{}, nil
    }

    return &CorrelationResult{
        Matched:         existing,
        CorrelationType: "fingerprint",
    }, nil
}
```

### 5.3 Integration into ingest flow

Modify `ProcessBatch()` in `processor_assets.go`:

```go
// Current flow (line 137-161):
for i := range report.Assets {
    ctisAsset := &report.Assets[i]
    name := getAssetName(ctisAsset)

    if existing, ok := existingMap[name]; ok {
        // Name match → merge
        p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
        assetMap[ctisAsset.ID] = existing.ID()
    } else {
        // No name match → create new       ← CHANGE THIS
        newAsset, err := p.createAssetFromCTIS(...)
    }
}

// Proposed flow:
for i := range report.Assets {
    ctisAsset := &report.Assets[i]
    name := asset.NormalizeName(getAssetName(ctisAsset), assetType)  // Layer 1

    if existing, ok := existingMap[name]; ok {
        // Name match → merge (same as before)
        p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
        assetMap[ctisAsset.ID] = existing.ID()
    } else {
        // No name match → try correlation (Layer 2)      ← NEW
        props := mapCTISProperties(ctisAsset)
        result, err := p.correlator.Correlate(ctx, tenantID, name, props, assetType)
        if err != nil {
            // Log and continue — correlation failure shouldn't block ingest
            p.logger.Warn("correlation failed", "name", name, "error", err)
        }

        if result != nil && result.Matched != nil {
            // Correlation found existing asset
            existing := result.Matched
            p.mergeCTISIntoAsset(existing, ctisAsset, report.Tool)
            assetMap[ctisAsset.ID] = existing.ID()

            if result.ShouldRename {
                existing.UpdateName(result.NewName)
                p.logger.Info("asset renamed via correlation",
                    "id", existing.ID(),
                    "old_name", existing.Name(),
                    "new_name", result.NewName,
                    "correlation_type", result.CorrelationType,
                )
            }

            // Add to existingMap so later assets in same batch also match
            existingMap[name] = existing
        } else {
            // No correlation → create new (same as before)
            newAsset, err := p.createAssetFromCTIS(...)
            existingMap[name] = newAsset
        }
    }
}
```

### 5.4 Batch optimization

`FindByIP()` per-asset is N queries. For batch performance:

```go
// FindByIPs returns assets matching ANY of the given IPs.
// Single query, uses GIN index on properties->'ip_addresses'.
func (r *AssetRepository) FindByIPs(
    ctx context.Context,
    tenantID shared.ID,
    ips []string,
) (map[string]*asset.Asset, error) {
    if len(ips) == 0 {
        return make(map[string]*asset.Asset), nil
    }

    query := r.selectQuery() + ` WHERE a.tenant_id = $1 AND (
        a.name = ANY($2)
        OR a.properties->>'ip' = ANY($2)
        OR a.properties->'ip_address'->>'address' = ANY($2)
        OR a.properties->'ip_addresses' ?| $2
    )`

    rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(ips))
    // ... scan into map[ip]*Asset
}
```

This does **1 query per batch** instead of N queries per asset.

---

## 6. Audit Trail

### 6.1 Merge log table

```sql
-- Migration: 000XXX_asset_merge_log.up.sql

CREATE TABLE IF NOT EXISTS asset_merge_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The asset that was kept
    kept_asset_id UUID NOT NULL,
    kept_asset_name VARCHAR(1024) NOT NULL,

    -- The asset that was merged into kept (NULL if rename only)
    merged_asset_id UUID,
    merged_asset_name VARCHAR(1024),

    -- What triggered the merge
    correlation_type VARCHAR(30) NOT NULL,  -- 'ip', 'hostname', 'external_id', 'fingerprint', 'normalization'
    correlation_value VARCHAR(1024),        -- The IP/hostname/ID that matched

    -- What changed
    action VARCHAR(20) NOT NULL,  -- 'rename', 'merge', 'normalize'
    old_name VARCHAR(1024),
    new_name VARCHAR(1024),

    -- Context
    source VARCHAR(100),          -- 'ingest', 'nessus_import', 'csv_import', 'migration'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_merge_log_tenant ON asset_merge_log(tenant_id);
CREATE INDEX idx_asset_merge_log_kept ON asset_merge_log(kept_asset_id);
CREATE INDEX idx_asset_merge_log_merged ON asset_merge_log(merged_asset_id) WHERE merged_asset_id IS NOT NULL;
```

---

## 7. Edge Cases & Mitigations

### 7.1 Multi-match: 1 incoming asset matches 2+ existing assets

```
Incoming: name="web-01", IPs=[10.0.0.1, 10.0.0.2]
Existing: Asset A (name="10.0.0.1"), Asset B (name="10.0.0.2")
```

**Strategy**: Merge all matched assets into one.
- Keep the one with highest `finding_count` (most data)
- Merge others into it (move findings, relationships, services)
- Log all merges

```go
if len(matchedAssets) > 1 {
    // Sort by finding_count DESC, created_at ASC
    sort.Slice(matchedAssets, func(i, j int) bool {
        if matchedAssets[i].FindingCount() != matchedAssets[j].FindingCount() {
            return matchedAssets[i].FindingCount() > matchedAssets[j].FindingCount()
        }
        return matchedAssets[i].CreatedAt().Before(matchedAssets[j].CreatedAt())
    })
    primary := matchedAssets[0]
    for _, secondary := range matchedAssets[1:] {
        mergeAsset(ctx, primary, secondary) // Move references, delete secondary
    }
}
```

### 7.2 Rename conflicts: new name already exists

```
Asset A: name="192.168.1.10" (being renamed to "web-server-01")
Asset B: name="web-server-01" (already exists)
```

**Strategy**: This is actually a merge scenario.
- Merge A into B (B already has the better name)
- Move A's findings/relationships to B
- Delete A
- Log merge

### 7.3 Race condition: two ingest jobs at same time

```
Job 1: Creating asset "192.168.1.10"
Job 2: Creating asset "web-server-01" with IP 192.168.1.10
Both run simultaneously
```

**Strategy**: `UpsertBatch` already uses transactions + `ON CONFLICT`. The correlation query uses `FOR UPDATE SKIP LOCKED` or accepts that occasional duplicates will be caught on next ingest cycle.

**Pragmatic approach**: Don't use locks for correlation. Accept that in rare race conditions, a duplicate may be created. The next ingest cycle will detect and merge it. This avoids correlation becoming a performance bottleneck.

### 7.4 IP reuse: different hosts get same IP over time (DHCP)

```
Monday:  Host A has IP 192.168.1.10
Tuesday: Host A decomissioned, Host B gets IP 192.168.1.10
```

**Strategy**: Check `last_seen` timestamps.
- If existing asset's `last_seen` is >30 days old AND incoming has different hostname → **don't merge**, create new asset
- If `last_seen` is recent (<7 days) → likely same host, merge
- Configurable threshold per tenant

```go
const staleAssetThreshold = 30 * 24 * time.Hour

func shouldCorrelateByIP(existing *asset.Asset, incomingName string) bool {
    // Same name → always merge (existing behavior)
    if existing.Name() == incomingName {
        return true
    }
    // Different name + stale asset → might be IP reuse, don't auto-merge
    if time.Since(existing.LastSeen()) > staleAssetThreshold {
        return false
    }
    return true
}
```

### 7.5 NAT/VPN: multiple hosts share same public IP

```
Host A (internal: 10.0.0.1) → NAT → Public: 203.0.113.1
Host B (internal: 10.0.0.2) → NAT → Public: 203.0.113.1
```

**Strategy**: Correlate only on **private IPs** (RFC 1918) and unique public IPs.
- If IP is `10.x`, `172.16-31.x`, `192.168.x` → use for correlation (internal, likely unique per host)
- If IP is public AND multiple internal hosts share it → don't auto-merge by public IP alone
- Heuristic: if existing asset already has 3+ internal IPs, don't add more via correlation (likely different hosts behind NAT)

### 7.6 IPv4 vs IPv6 for same host

```
Host has both: 192.168.1.10 and fe80::1
```

**Strategy**: Both IPs stored in `ip_addresses[]` array. Correlation checks all IPs in the array. If incoming asset has IPv6 that matches, it merges correctly.

### 7.7 Existing data with duplicates

**Strategy**: Provide a CLI tool or admin endpoint:

```
POST /api/v1/admin/assets/deduplicate
{
  "dry_run": true,     // Preview only
  "asset_types": ["host", "domain"],
  "tenant_id": "..."   // Optional, all tenants if omitted
}

Response:
{
  "duplicate_groups": 42,
  "assets_to_merge": 87,
  "findings_to_reassign": 1234,
  "preview": [
    {
      "keep": {"id": "...", "name": "web-server-01", "finding_count": 50},
      "merge": [
        {"id": "...", "name": "192.168.1.10", "finding_count": 12},
        {"id": "...", "name": "web-server-01.corp", "finding_count": 3}
      ],
      "correlation": "ip:192.168.1.10"
    }
  ]
}
```

---

## 8. Implementation Plan

### Phase 1: Name Normalization (Low risk, high impact)

**Effort**: 2 days | **Risk**: Low | **Impact**: Prevents 60%+ of future duplicates

1. Create `pkg/domain/asset/normalize.go` with all normalization functions
2. Add unit tests for every normalization case
3. Apply `NormalizeName()` in `NewAsset()` constructor
4. Apply in `UpdateName()` method
5. Apply in `getAssetName()` in ingest processor
6. Apply in `ImportNessus()` and `ImportCSVAssets()`
7. Write migration to normalize existing data
8. Write migration to merge duplicates created by normalization
9. Create `asset_merge_log` table

**Files changed:**
- `pkg/domain/asset/normalize.go` (NEW)
- `pkg/domain/asset/normalize_test.go` (NEW)
- `pkg/domain/asset/entity.go` (modify `NewAsset`, `UpdateName`)
- `internal/app/ingest/processor_assets.go` (modify `getAssetName` call sites)
- `internal/app/asset_import_service.go` (modify import functions)
- `migrations/000XXX_normalize_asset_names.up.sql` (NEW)
- `migrations/000XXX_asset_merge_log.up.sql` (NEW)

### Phase 2: IP Correlation for Hosts (Medium risk, high impact)

**Effort**: 3 days | **Risk**: Medium | **Impact**: Solves the core host dedup problem

1. Create `internal/app/ingest/correlator.go`
2. Add `FindByIPs()` batch query to repository
3. Wire correlator into `ProcessBatch()` flow
4. Add `shouldCorrelateByIP()` with staleness check
5. Implement rename logic with merge log
6. Add integration tests with multi-source scenarios

**Files changed:**
- `internal/app/ingest/correlator.go` (NEW)
- `internal/app/ingest/correlator_test.go` (NEW)
- `internal/infra/postgres/asset_repository.go` (add `FindByIPs`)
- `internal/app/ingest/processor_assets.go` (modify `ProcessBatch`)

### Phase 3: Extended Correlation (Low risk, medium impact)

**Effort**: 2 days | **Risk**: Low | **Impact**: Covers cloud/IAM/cert dedup

1. Add `FindByExternalID()` to repository
2. Add `FindByPropertyValue()` for certificate fingerprint
3. Wire cloud account and IAM correlation
4. Wire certificate correlation

### Phase 4: Duplicate Detection Admin Tool (No risk)

**Effort**: 2 days | **Risk**: None | **Impact**: Cleans up historical data

1. Create admin endpoint for duplicate detection
2. Dry-run mode to preview merges
3. Execute mode to perform merges
4. Detailed logging and rollback support

---

## 9. Testing Strategy

### Unit tests

```
normalize_test.go:
  - TestNormalizeDNSName (10 cases: case, trailing dot, whitespace, empty)
  - TestNormalizeHostName (8 cases: hostname, IPv4, IPv6, FQDN)
  - TestNormalizeIPAddress (6 cases: v4 padded, v6 short/full, invalid)
  - TestNormalizeRepoName (8 cases: https, ssh, .git, trailing slash)
  - TestNormalizeURL (8 cases: protocol, port, trailing slash, case)

correlator_test.go:
  - TestCorrelateHostByIP (match single IP)
  - TestCorrelateHostByMultipleIPs (match from array)
  - TestCorrelateHostNoMatch (create new)
  - TestCorrelateHostRename (IP name → hostname)
  - TestCorrelateHostStaleAsset (skip old asset)
  - TestCorrelateMultiMatch (merge multiple)
```

### Integration tests

```
TestIngestDedup_SplunkThenQualys:
  1. Ingest Splunk report with host "192.168.1.10"
  2. Ingest Qualys report with host "web-server-01" (IP=192.168.1.10)
  3. Assert: 1 asset exists, name="web-server-01", ip_addresses contains "192.168.1.10"
  4. Assert: All findings from both reports on same asset

TestIngestDedup_CaseInsensitive:
  1. Ingest report with domain "Example.COM"
  2. Ingest report with domain "example.com"
  3. Assert: 1 asset exists, name="example.com"

TestIngestDedup_RepoFormats:
  1. Ingest report with repo "https://github.com/Org/Repo.git"
  2. Ingest report with repo "org/repo"
  3. Assert: 1 asset exists, name="github.com/org/repo"

TestMigration_NormalizeExistingAssets:
  1. Insert 3 domains: "Example.COM", "example.com", "example.com."
  2. Run normalization migration
  3. Assert: 1 asset remains, findings from all 3 consolidated
```

---

## 10. Rollback Plan

Each phase is independently reversible:

- **Phase 1**: Remove `NormalizeName()` calls. Migration is forward-only but data is still valid (just normalized). No rollback needed for normalized names.
- **Phase 2**: Remove correlator from `ProcessBatch()`. Assets created during correlation period keep their merged state (no harm). Disable correlator via config flag.
- **Phase 3-4**: Same as Phase 2.

**Config flag for gradual rollout:**

```go
// Config
type AssetConfig struct {
    EnableNameNormalization bool `env:"ASSET_NAME_NORMALIZATION" envDefault:"true"`
    EnableIPCorrelation    bool `env:"ASSET_IP_CORRELATION" envDefault:"false"`
    StaleAssetDays         int  `env:"ASSET_STALE_DAYS" envDefault:"30"`
}
```

Phase 1 enabled by default. Phase 2 disabled by default — enable per environment after testing.

---

## 11. Cross-Component Impact Analysis

### Which components need changes?

```
┌───────────────────────────────────────────────────────────────────┐
│                    DATA FLOW: Asset Creation                      │
│                                                                   │
│  Scanner Tool                                                     │
│      │                                                            │
│      ▼                                                            │
│  ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌───────────┐ │
│  │  Agent   │────▶│  SDK-Go  │────▶│   API   │────▶│  Postgres │ │
│  │ recon.go │     │ types.go │     │ ingest  │     │  upsert   │ │
│  └─────────┘     └──────────┘     └─────────┘     └───────────┘ │
│   NORMALIZE       NORMALIZE        NORMALIZE       STORE         │
│   (Phase 1)       (shared lib)     (authoritative)  (canonical)  │
│                                                                   │
│                        ┌──────┐                                   │
│                        │  UI  │                                   │
│                        │ form │                                   │
│                        └──┬───┘                                   │
│                           │ POST /api/v1/assets                   │
│                           ▼                                       │
│                       ┌─────────┐                                 │
│                       │   API   │                                 │
│                       │ handler │                                 │
│                       └─────────┘                                 │
│                        NORMALIZE                                  │
│                        (authoritative)                            │
└───────────────────────────────────────────────────────────────────┘
```

**Principle**: API is the **authoritative normalizer**. Agent/SDK/UI normalize as **best-effort** (defense in depth) but API always re-normalizes before storage.

### Component change matrix

| Component | What Changes | Files | Effort | Priority |
|---|---|---|---|---|
| **Schemas (CTIS)** | Document normalization rules in asset.json | `schemas/ctis/v1/asset.json` | Low | P1 |
| **SDK-Go** | Add `NormalizeName()` helper shared by Agent + API | `sdk-go/pkg/ctis/normalize.go` (NEW) | Low | P1 |
| **API - Domain** | Add `NormalizeName()` to entity constructor | `api/pkg/domain/asset/normalize.go` (NEW), `entity.go` | Medium | P1 |
| **API - Ingest** | Apply normalization in `ProcessBatch()` + add IP correlation | `api/internal/app/ingest/processor_assets.go`, `correlator.go` (NEW) | High | P1 |
| **API - Import** | Apply normalization in Nessus/CSV import | `api/internal/app/asset_import_service.go` | Low | P1 |
| **API - Repository** | Add `FindByIPs()` batch query, update `GetByNames()` | `api/internal/infra/postgres/asset_repository.go` | Medium | P1 |
| **API - Handler** | Normalize in asset create/update API | `api/internal/infra/http/handler/asset_handler.go` | Low | P1 |
| **API - Migration** | Normalize existing data + `asset_merge_log` table | `api/migrations/000XXX_*.sql` (NEW, 2 files) | Medium | P1 |
| **Agent** | Normalize names before sending CTIS report | `agent/internal/executor/recon.go` (subfinder, dnsx, naabu, httpx, katana parsers) | Medium | P2 |
| **Agent** | Normalize in vulnscan asset creation | `agent/internal/executor/vulnscan.go` | Low | P2 |
| **UI - Form** | Add normalization preview in asset creation form | `ui/src/features/assets/components/.../asset-form-dialog.tsx` | Low | P3 |
| **UI - Utility** | Create normalization helper (mirror of API logic) | `ui/src/features/assets/lib/normalize.ts` (NEW) | Low | P3 |

### Per-component details

#### 1. Schemas (`schemas/ctis/v1/asset.json`)

- Add `description` fields documenting normalization rules per type
- No schema enforcement changes (normalization happens in code, not JSON Schema)
- Document that `name` and `value` will be normalized by API before storage

#### 2. SDK-Go (`sdk-go/pkg/ctis/`)

Create shared normalization library used by both Agent and API:

```go
// sdk-go/pkg/ctis/normalize.go (NEW)
package ctis

// NormalizeAssetName normalizes an asset name for the given type.
// This is the shared implementation used by both Agent and API.
// API re-normalizes as authoritative source — this is defense-in-depth.
func NormalizeAssetName(assetType AssetType, name string) string { ... }
```

- Agent imports `ctis.NormalizeAssetName()` directly
- API imports and wraps in its own `asset.NormalizeName()` (may add extra rules)

#### 3. Agent (`agent/internal/executor/`)

**recon.go** — 5 parsers need normalization:

| Parser | Line | Current | Change |
|---|---|---|---|
| `parseSubfinderOutput` | ~371 | `Name: jsonResult.Host` | `Name: ctis.NormalizeAssetName("subdomain", jsonResult.Host)` |
| `parseDNSXOutput` | ~442 | `Name: jsonResult.Host` | `Name: ctis.NormalizeAssetName("domain", jsonResult.Host)` |
| `parseNaabuOutput` | — | `Name: host:port` | `Name: ctis.NormalizeAssetName("service", host+":"+port)` |
| `parseHTTPXOutput` | — | `Name: url` | `Name: ctis.NormalizeAssetName("service", url)` |
| `parseKatanaOutput` | — | `Name: url` | `Name: ctis.NormalizeAssetName("discovered_url", url)` |

**vulnscan.go** — Asset creation from scan results needs normalization

#### 4. API — Ingest (`api/internal/app/ingest/`)

The most critical changes. See Sections 4-5 of this RFC for full design.

**Key change in `ProcessBatch()` flow:**
```
BEFORE: getAssetName() → GetByNames() → create/merge
AFTER:  getAssetName() → NormalizeName() → GetByNames() → correlate → create/merge
```

#### 5. API — Handler (`api/internal/infra/http/handler/`)

Normalize in Create/Update asset API endpoints:
```go
func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
    // ... parse request ...
    req.Name = asset.NormalizeName(req.Name, req.AssetType, req.SubType)
    // ... create asset ...
}
```

#### 6. UI (`ui/src/features/assets/`)

Create client-side normalization for instant feedback:
```typescript
// ui/src/features/assets/lib/normalize.ts (NEW)
export function normalizeAssetName(name: string, assetType: string): string {
    switch (assetType) {
        case 'domain':
        case 'subdomain':
            return name.toLowerCase().trim().replace(/\.+$/, '')
        case 'ip_address':
            return name.trim()
        case 'repository':
            return normalizeRepoName(name)
        default:
            return name.trim()
    }
}
```

Update asset creation form to show normalized preview:
```tsx
{watchedName && normalizedName !== watchedName && (
    <p className="text-xs text-muted-foreground">
        Will be saved as: <code>{normalizedName}</code>
    </p>
)}
```

### What does NOT need changes

| Component | Why |
|---|---|
| Redis cache | Cache keys use asset UUID, not name |
| Notification system | References assets by UUID |
| Permission system | Not asset-name dependent |
| Compliance/SLA | References assets by UUID |
| Findings | Linked to assets by UUID, not name |
| Relationships | Linked by UUID |
| Reports | Query by UUID/type, not name |

---

## 12. Open Questions

1. **Subdomain ↔ Domain relationship**: Should `api.example.com` auto-create a relationship to `example.com`? Currently it doesn't.
2. **Merge notification**: Should users be notified when assets are auto-merged? Via UI banner or notification?
3. **Undo merge**: Should we support undoing a merge? Would require keeping deleted asset data for N days.
4. **Tenant-level config**: Should correlation rules be configurable per tenant? (e.g., disable IP correlation for tenants with heavy NAT)
5. **Performance threshold**: At what asset count does batch correlation become too slow? Need benchmarks with 100K+ assets.
6. **Unique constraint change**: Should unique constraint become `(tenant_id, asset_type, normalized_name)` to allow same name across different types? Currently `example.com` as domain blocks `example.com` as host.
