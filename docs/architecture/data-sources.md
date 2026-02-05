# Data Sources Architecture

> **Version**: 1.0
> **Last Updated**: 2024-01-16
> **Status**: Implemented (Migration 000008)

## Overview

Data Sources is the system for tracking where assets and findings come from in Rediver. It supports multiple collection methods (pull and push) and tracks the provenance of every asset.

## Key Concepts

### Source Types

| Type | Direction | Description | Examples |
|------|-----------|-------------|----------|
| `integration` | PULL | Server pulls data from external APIs on schedule | GitHub, GitLab, AWS, GCP, Azure |
| `collector` | PUSH | Agent passively collects and pushes data | Log collector, K8s agent, Asset inventory |
| `scanner` | PUSH | Agent actively scans and pushes results | Nuclei, Trivy, Nmap, Secret scanner |
| `manual` | - | User-created via UI or API | Direct API calls, UI forms |

### Source Status

| Status | Description |
|--------|-------------|
| `pending` | Registered but not yet active |
| `active` | Running and reporting data |
| `inactive` | Not reporting (timeout > 15 min default) |
| `error` | Has errors, check `last_error` |
| `disabled` | Manually disabled by user |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        REDIVER SERVER                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐         ┌─────────────────────────────┐   │
│  │  Integration     │  PULL   │  External APIs              │   │
│  │  Service         │◄────────│  (GitHub, AWS, GCP...)      │   │
│  │  (Scheduled)     │         │                             │   │
│  └────────┬─────────┘         └─────────────────────────────┘   │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────┐         ┌─────────────────────────────┐   │
│  │  Ingestion       │  PUSH   │  Collectors & Scanners      │   │
│  │  API             │◄────────│  (On-premise agents)        │   │
│  │  (Real-time)     │         │                             │   │
│  └────────┬─────────┘         └─────────────────────────────┘   │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    ASSET SERVICE                          │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │   │
│  │  │ Validation  │─►│ Dedup/Merge │─►│ Store + Track   │   │   │
│  │  │ (Schema)    │  │ Logic       │  │ Sources         │   │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema

### Tables

#### `data_sources`
Registry of all data sources.

```sql
CREATE TABLE data_sources (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,

    -- Identity
    name VARCHAR(255) NOT NULL,        -- "vuln-scanner-prod-01"
    type source_type NOT NULL,         -- integration/collector/scanner/manual
    description TEXT,

    -- Deployment info (for collectors/scanners)
    version VARCHAR(50),               -- "1.2.3"
    hostname VARCHAR(255),             -- "scanner-01.internal"
    ip_address INET,

    -- Authentication
    api_key_hash VARCHAR(255),         -- Hashed API key
    api_key_prefix VARCHAR(12),        -- "rs_live_xxxx"

    -- Status
    status source_status NOT NULL,     -- pending/active/inactive/error/disabled
    last_seen_at TIMESTAMPTZ,
    last_error TEXT,

    -- Capabilities
    capabilities JSONB,                -- ["domain", "vulnerability", ...]
    config JSONB,                      -- Source-specific config

    -- Stats
    assets_collected BIGINT,
    findings_reported BIGINT,

    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
```

#### `asset_sources`
Many-to-many relationship tracking all sources for each asset.

```sql
CREATE TABLE asset_sources (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL,

    -- Source reference
    source_type source_type NOT NULL,
    source_id UUID,                    -- FK to data_sources

    -- Timing
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,

    -- Source-specific data
    source_ref VARCHAR(255),           -- Scan ID, job ID, etc.
    contributed_data JSONB,            -- What this source knows
    confidence INTEGER,                -- 0-100
    is_primary BOOLEAN,                -- Authoritative source?
    seen_count INTEGER,                -- Times reported

    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
```

#### `assets` (updated)
New columns for quick source access.

```sql
ALTER TABLE assets ADD COLUMN source_type source_type;
ALTER TABLE assets ADD COLUMN source_id UUID;
ALTER TABLE assets ADD COLUMN source_ref VARCHAR(255);
ALTER TABLE assets ADD COLUMN discovered_at TIMESTAMPTZ;
```

### Relationships

```
┌─────────────┐       ┌────────────────┐       ┌──────────────┐
│   assets    │◄──────│ asset_sources  │──────►│ data_sources │
│             │  1:N  │   (M:N join)   │  N:1  │              │
│ source_type │       │ contributed_   │       │ capabilities │
│ source_id   │       │ data           │       │ status       │
│ source_ref  │       │ confidence     │       │ last_seen_at │
└─────────────┘       └────────────────┘       └──────────────┘
```

## Multi-Source Asset Tracking

### Problem
An asset can be discovered by multiple sources:
1. GitHub Integration finds `api.example.com` in repo config
2. Network Scanner finds it via port scan
3. AWS Collector reports it from Route53

### Solution
Track ALL sources via `asset_sources` table:

```json
{
  "asset": {
    "id": "asset-uuid",
    "name": "api.example.com",
    "type": "domain"
  },
  "sources": [
    {
      "type": "integration",
      "name": "GitHub Production",
      "first_seen": "2024-01-10",
      "is_primary": true,
      "contributed": {"repository": "org/api"}
    },
    {
      "type": "scanner",
      "name": "Network Scanner",
      "first_seen": "2024-01-12",
      "contributed": {"ports": [80, 443], "ip": "1.2.3.4"}
    },
    {
      "type": "collector",
      "name": "AWS Collector",
      "first_seen": "2024-01-14",
      "contributed": {"hosted_zone": "Z123"}
    }
  ]
}
```

### Merge Strategy

| Field | Strategy | Description |
|-------|----------|-------------|
| `name` | First wins | Unique identifier |
| `type` | First wins | Asset type |
| `criticality` | Highest wins | critical > high > medium > low |
| `exposure` | Most exposed | public > restricted > private |
| `tags` | Union | Combine all tags |
| `metadata` | Deep merge | Combine all fields |

## API Endpoints

### Source Management

```
POST   /api/v1/sources              # Register new source
GET    /api/v1/sources              # List sources
GET    /api/v1/sources/{id}         # Get source details
PATCH  /api/v1/sources/{id}         # Update source
DELETE /api/v1/sources/{id}         # Delete source
POST   /api/v1/sources/{id}/regenerate-key  # New API key
```

### Data Ingestion (Push)

```
POST   /api/v1/ingest/assets        # Push assets
POST   /api/v1/ingest/findings      # Push findings
POST   /api/v1/ingest/heartbeat     # Source heartbeat
```

### Query by Source

```
GET    /api/v1/assets?source_id={id}        # Assets from source
GET    /api/v1/assets?source_type=scanner   # Assets by type
GET    /api/v1/assets/{id}/sources          # All sources for asset
```

## Authentication

### For Integrations (Pull)
- Uses existing SCM Connection credentials
- OAuth tokens or API keys stored encrypted

### For Collectors/Scanners (Push)
- API key generated on registration
- Format: `rs_live_xxxxxxxxxxxxxxxxxxxx`
- Stored as hash, prefix shown for identification
- Sent via `Authorization: Bearer <key>` header

## Source Lifecycle

```
┌─────────┐     ┌────────┐     ┌────────┐     ┌──────────┐
│ pending │────►│ active │────►│inactive│────►│ disabled │
└─────────┘     └────────┘     └────────┘     └──────────┘
     │               │              │
     │               ▼              │
     │          ┌────────┐         │
     └─────────►│ error  │◄────────┘
                └────────┘
```

### Status Transitions

| From | To | Trigger |
|------|-----|---------|
| pending | active | First successful data push/pull |
| active | inactive | No heartbeat > 15 minutes |
| active | error | Repeated failures |
| inactive | active | Heartbeat received |
| * | disabled | Manual disable |

## Rediver Ingest Schema (RIS)

RIS is the standard format for pushing data to Rediver. It provides a unified way for collectors and scanners to submit assets and findings.

### Package Location
```
pkg/parsers/ris/
├── doc.go       # Package documentation
├── types.go     # Data structures
├── parser.go    # Parser implementation
└── convert.go   # SARIF and other format converters
```

### Basic Usage
```go
import "github.com/exploopio/api/pkg/parsers/ris"

// Parse RIS report
parser := ris.NewParser(nil)
report, err := parser.ParseFile("scan-results.json")

// Or convert from SARIF
sarifLog, _ := sarif.NewParser(nil).ParseFile("sast-results.sarif")
risReport := ris.FromSARIF(sarifLog, &ris.SARIFConvertOptions{
    AssetValue: "github.com/org/repo",
    AssetType:  ris.AssetTypeRepository,
})
```

### Report Structure
```json
{
  "version": "1.0",
  "metadata": {
    "timestamp": "2024-01-16T10:00:00Z",
    "source_type": "scanner",
    "source_ref": "scan-12345"
  },
  "tool": {
    "name": "my-scanner",
    "version": "1.0.0",
    "capabilities": ["vulnerability", "secret"]
  },
  "assets": [
    {
      "type": "repository",
      "value": "github.com/org/repo",
      "confidence": 100
    }
  ],
  "findings": [
    {
      "type": "vulnerability",
      "title": "SQL Injection in login handler",
      "severity": "high",
      "rule_id": "CWE-89",
      "location": {
        "path": "src/auth/login.go",
        "start_line": 45
      }
    }
  ]
}
```

### Supported Formats
RIS supports conversion from:
- **SARIF** - SAST results (Semgrep, CodeQL, etc.)
- **Direct RIS** - Native format for custom collectors

### Building Reports Programmatically
```go
report := ris.NewReportBuilder().
    WithTool("my-collector", "1.0.0").
    WithToolCapabilities("domain", "ip_address").
    AddAsset(
        ris.NewAssetBuilder(ris.AssetTypeDomain, "example.com").
            WithCriticality(ris.CriticalityHigh).
            Build(),
    ).
    AddFinding(
        ris.NewFindingBuilder(ris.FindingTypeVulnerability, "Open Port 22", ris.SeverityMedium).
            WithDescription("SSH port is publicly accessible").
            Build(),
    ).
    Build()
```

## Finding Provenance Tracking

Similar to assets, findings also support multi-source tracking via `finding_data_sources` table.

### Database Schema
```sql
CREATE TABLE finding_data_sources (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL,
    source_type source_type NOT NULL,
    source_id UUID,
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    source_ref VARCHAR(255),
    scan_id VARCHAR(255),
    contributed_data JSONB,
    confidence INTEGER,
    is_primary BOOLEAN,
    seen_count INTEGER
);
```

### Multi-Source Finding Example
The same vulnerability can be reported by multiple scanners:
```json
{
  "finding": {
    "id": "finding-uuid",
    "title": "SQL Injection",
    "severity": "critical"
  },
  "sources": [
    {
      "type": "scanner",
      "name": "Semgrep",
      "scan_id": "scan-001",
      "is_primary": true,
      "contributed": {"rule": "sql-injection-go"}
    },
    {
      "type": "scanner",
      "name": "CodeQL",
      "scan_id": "codeql-run-123",
      "contributed": {"cwe": "CWE-89", "cvss": 9.8}
    }
  ]
}
```

## Web3 Support

RIS fully supports Web3 assets and smart contract vulnerabilities.

### Web3 Asset Types

| Type | Example Value | Description |
|------|---------------|-------------|
| `smart_contract` | `0x1234...abcd` | Smart contracts (ERC-20, ERC-721, DeFi) |
| `wallet` | `0xabcd...1234` | Crypto wallets (EOA, multisig) |
| `token` | `0x5678...efgh` | Fungible tokens |
| `nft_collection` | `0x9abc...5678` | NFT collections |
| `defi_protocol` | `uniswap-v3` | DeFi protocols |
| `blockchain` | `ethereum` | Blockchain networks |

### Web3 Finding Type

```go
FindingTypeWeb3 FindingType = "web3" // Smart contract vulnerabilities
```

### Web3 Vulnerability Classes

Based on [SWC Registry](https://swcregistry.io/) and DeFi-specific vulnerabilities:

| Class | SWC ID | Description |
|-------|--------|-------------|
| `reentrancy` | SWC-107 | Reentrancy attacks |
| `integer_overflow` | SWC-101 | Integer overflow/underflow |
| `access_control` | SWC-105 | Missing access control |
| `delegate_call` | SWC-112 | Dangerous delegatecall |
| `flash_loan_attack` | - | Flash loan exploitation |
| `oracle_manipulation` | - | Price oracle attacks |
| `front_running` | - | Transaction ordering attacks |

### Web3 Scanner Integration

RIS automatically detects Web3 security tools:
- **Slither** (Trail of Bits)
- **Mythril** (ConsenSys)
- **Securify** (ETH Zurich)
- **Manticore** (Trail of Bits)
- **Echidna** (Trail of Bits)
- **Aderyn** (Cyfrin)
- **Foundry** (Invariant tests)

### Web3 Finding Example

```json
{
  "type": "web3",
  "title": "Reentrancy Vulnerability in withdraw()",
  "severity": "critical",
  "rule_id": "SWC-107",
  "web3": {
    "vulnerability_class": "reentrancy",
    "swc_id": "SWC-107",
    "contract_address": "0x1234...abcd",
    "chain_id": 1,
    "function_signature": "withdraw(uint256)",
    "detection_tool": "slither",
    "reentrancy": {
      "type": "cross_function",
      "external_call": "msg.sender.call{value: amount}(\"\")",
      "state_modified_after_call": "balances[msg.sender]"
    }
  }
}
```

## Infrastructure Layer

### PostgreSQL Repositories

Located in `internal/infra/postgres/`:

| Repository | File | Description |
|------------|------|-------------|
| `DataSourceRepository` | `datasource_repository.go` | CRUD for data sources |
| `AssetSourceRepository` | `asset_source_repository.go` | Asset-source relationships |
| `FindingDataSourceRepository` | `finding_data_source_repository.go` | Finding-source relationships |

### Repository Interfaces

```go
// internal/domain/datasource/repository.go

type Repository interface {
    Create(ctx context.Context, ds *DataSource) error
    GetByID(ctx context.Context, id shared.ID) (*DataSource, error)
    GetByAPIKeyPrefix(ctx context.Context, prefix string) (*DataSource, error)
    List(ctx context.Context, tenantID shared.ID, filter ListFilter) ([]*DataSource, int, error)
    Update(ctx context.Context, ds *DataSource) error
    Delete(ctx context.Context, id shared.ID) error
    MarkStaleAsInactive(ctx context.Context, tenantID shared.ID, staleThresholdMinutes int) (int, error)
    IncrementStats(ctx context.Context, id shared.ID, assets, findings int) error
}

type AssetSourceRepository interface {
    Create(ctx context.Context, as *AssetSource) error
    Upsert(ctx context.Context, as *AssetSource) error  // Idempotent upsert
    GetByAsset(ctx context.Context, assetID shared.ID) ([]*AssetSource, error)
    GetBySource(ctx context.Context, sourceID shared.ID) ([]*AssetSource, error)
    SetPrimary(ctx context.Context, assetID, assetSourceID shared.ID) error
}

type FindingDataSourceRepository interface {
    Create(ctx context.Context, fs *FindingDataSource) error
    Upsert(ctx context.Context, fs *FindingDataSource) error
    GetByFinding(ctx context.Context, findingID shared.ID) ([]*FindingDataSource, error)
    CountBySource(ctx context.Context, sourceID shared.ID) (int64, error)
}
```

### Upsert Pattern

Repositories use PostgreSQL `ON CONFLICT` for idempotent updates:

```go
func (r *AssetSourceRepository) Upsert(ctx context.Context, as *AssetSource) error {
    query := `
        INSERT INTO asset_sources (...) VALUES (...)
        ON CONFLICT (asset_id, source_type, source_id)
        DO UPDATE SET
            last_seen_at = EXCLUDED.last_seen_at,
            contributed_data = asset_sources.contributed_data || EXCLUDED.contributed_data,
            seen_count = asset_sources.seen_count + 1
    `
    // ...
}
```

## JSON Schemas

Official JSON schemas are available at:

| Schema | URL |
|--------|-----|
| Report | `https://schemas.exploop.io/ris/v1/report.json` |
| Asset | `https://schemas.exploop.io/ris/v1/asset.json` |
| Finding | `https://schemas.exploop.io/ris/v1/finding.json` |
| Web3 Asset | `https://schemas.exploop.io/ris/v1/web3-asset.json` |
| Web3 Finding | `https://schemas.exploop.io/ris/v1/web3-finding.json` |

Repository: [github.com/exploopio/schemas](https://github.com/exploopio/schemas)

## Future Enhancements

1. **Source SDK** - Go/Python SDKs for building collectors/scanners
2. **Webhook Notifications** - Alert on source status changes
3. **Source Groups** - Group related sources (e.g., all scanners in prod)
4. **Data Retention Policies** - Per-source retention rules
5. **CycloneDX/SPDX Support** - SBOM format conversion
6. **Web3 Bridge Support** - Cross-chain asset tracking
7. **MEV Detection** - MEV vulnerability analysis

## Related Documentation

- [Asset Types](./asset-types.md)
- [Ingestion API](../api/ingestion.md)
- [Asset Schema](./asset-schema.md)
- [Building Ingestion Tools](https://docs.exploop.io/guides/building-ingestion-tools)
- [RIS JSON Schemas](https://github.com/exploopio/schemas)
