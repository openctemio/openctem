# Component-Dependency-Finding-Vulnerability: Best Practices

## Executive Summary

This document describes the industry-aligned design for component relationship tracking in Exploop, based on analysis of leading SBOM and dependency management systems.

## Industry Comparison

| System | Finding→Component | Parent Tracking | Multiple Parents | Depth Tracking |
|--------|-------------------|-----------------|------------------|----------------|
| **CycloneDX** | Direct (via bom-ref) | Full graph | Yes | Yes |
| **SPDX 3.0** | Direct relationships | Full graph | Yes | Yes |
| **Dependency-Track** | Direct (via PURL) | Parent chains | Yes | Yes |
| **GitHub Dep Graph** | Direct | "Show paths" | Yes | Yes |
| **Snyk** | Direct | dependency_path | Yes | Yes |
| **Exploop** | Direct (components.id) | parent_component_id | Single | depth column |

## Data Model

### Core Tables

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA MODEL                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  components (Global - Tenant Agnostic)                                       │
│  ├── id (UUID PK)                                                            │
│  ├── purl (UNIQUE) - e.g., "pkg:npm/express@4.18.0"                         │
│  ├── name, version, ecosystem                                                │
│  ├── vulnerability_count (cached)                                            │
│  └── metadata (JSONB)                                                        │
│                                                                              │
│  asset_components (Tenant Scoped - Asset → Component Links)                  │
│  ├── id (UUID PK)                                                            │
│  ├── tenant_id, asset_id, component_id                                       │
│  ├── dependency_type (direct, transitive, dev, optional)                     │
│  ├── path, manifest_file                                                     │
│  ├── parent_component_id (FK → asset_components.id) ← For tree tracking      │
│  ├── depth (INT) ← 1=direct, 2+=transitive depth                            │
│  └── UNIQUE(asset_id, component_id, path)                                    │
│                                                                              │
│  findings (Tenant Scoped - Vulnerability Instances)                          │
│  ├── id (UUID PK)                                                            │
│  ├── tenant_id, asset_id, branch_id                                          │
│  ├── component_id → components.id (DIRECT LINK)                              │
│  ├── vulnerability_id → vulnerabilities.id                                   │
│  └── severity, status, source, tool_name                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Relationship Flow

```
CURRENT (Industry-Aligned):

Finding.component_id ──────────────────────► components.id (direct)
                                                 │
                                                 ▼
Asset ──► asset_components ──────────────► components.id
              │
              ├── parent_component_id ──► asset_components.id (tree)
              └── depth (1=direct, 2+=transitive)
```

## Key Design Decisions

### 1. Direct Finding → Component Link

**Why?** Industry standards (CycloneDX, SPDX, Dependency-Track) all use direct references.

**Benefits:**
- Simpler queries (1 JOIN instead of 2)
- Correct semantic: finding relates to a COMPONENT (package version)
- Component context preserved even if asset_component is deleted
- Faster aggregations (e.g., "how many findings per component")

**Query Example:**
```sql
-- Get component with finding count (direct join)
SELECT c.name, c.version, c.purl, COUNT(f.id) as finding_count
FROM components c
LEFT JOIN findings f ON f.component_id = c.id
WHERE f.tenant_id = $1
GROUP BY c.id;
```

### 2. Parent Component Tracking

**Why?** CycloneDX, GitHub, and Snyk all track "where did this transitive dep come from?"

**Benefits:**
- Query "lodash is transitive OF express"
- Build dependency tree visualization
- Better remediation: "update express to fix lodash vulnerability"

**Query Example:**
```sql
-- What dependencies did express pull in?
SELECT c.name, c.version, ac.dependency_type, ac.depth
FROM asset_components ac
JOIN components c ON ac.component_id = c.id
WHERE ac.parent_component_id = (
    SELECT ac2.id FROM asset_components ac2
    JOIN components c2 ON ac2.component_id = c2.id
    WHERE c2.purl = 'pkg:npm/express@4.18.0' AND ac2.asset_id = $1
);

-- Where did lodash come from? (recursive tree)
WITH RECURSIVE dep_chain AS (
    SELECT ac.*, 0 as chain_depth
    FROM asset_components ac
    JOIN components c ON ac.component_id = c.id
    WHERE c.name = 'lodash' AND ac.asset_id = $1
    UNION ALL
    SELECT parent.*, dc.chain_depth + 1
    FROM asset_components parent
    JOIN dep_chain dc ON dc.parent_component_id = parent.id
    WHERE dc.chain_depth < 20  -- Prevent infinite loops
)
SELECT c.name, c.version, dc.dependency_type, dc.chain_depth
FROM dep_chain dc
JOIN components c ON dc.component_id = c.id
ORDER BY dc.chain_depth;
```

### 3. Depth Tracking for Risk Scoring

**Why?** Snyk and GitHub prioritize direct dependencies over deep transitive ones.

**Benefits:**
- Risk scoring: direct deps = higher priority
- Query optimization: "show me vulnerabilities in direct deps first"
- Compliance: some policies only care about depth 1-2

**Query Example:**
```sql
-- Risk-weighted vulnerability count by depth
SELECT
    ac.depth,
    COUNT(DISTINCT f.id) as finding_count,
    CASE ac.depth
        WHEN 1 THEN COUNT(DISTINCT f.id) * 1.0  -- Direct: full weight
        WHEN 2 THEN COUNT(DISTINCT f.id) * 0.7  -- 1st transitive: 70%
        ELSE COUNT(DISTINCT f.id) * 0.5         -- Deep transitive: 50%
    END as weighted_risk
FROM asset_components ac
JOIN findings f ON f.component_id = ac.component_id
WHERE ac.asset_id = $1
GROUP BY ac.depth
ORDER BY ac.depth;

-- Get all direct dependencies with vulnerabilities (priority remediation)
SELECT c.name, c.version, c.purl, COUNT(f.id) as vuln_count
FROM asset_components ac
JOIN components c ON ac.component_id = c.id
JOIN findings f ON f.component_id = c.id
WHERE ac.asset_id = $1 AND ac.depth = 1
GROUP BY c.id
ORDER BY vuln_count DESC;
```

## Migrations

### Migration 133: Fix Finding → Component Direct Link

```sql
-- Add direct reference to components table
ALTER TABLE findings
ADD COLUMN component_id_direct UUID REFERENCES components(id) ON DELETE SET NULL;

-- Migrate existing data
UPDATE findings f
SET component_id_direct = ac.component_id
FROM asset_components ac
WHERE f.component_id = ac.id AND f.component_id IS NOT NULL;

-- Replace old column
ALTER TABLE findings DROP COLUMN component_id;
ALTER TABLE findings RENAME COLUMN component_id_direct TO component_id;

-- Add indexes
CREATE INDEX idx_findings_component_id ON findings(component_id);
CREATE INDEX idx_findings_component_tenant ON findings(component_id, tenant_id)
WHERE component_id IS NOT NULL;
```

### Migration 134: Add Parent Tracking & Depth

```sql
-- Add parent tracking
ALTER TABLE asset_components
ADD COLUMN parent_component_id UUID REFERENCES asset_components(id) ON DELETE SET NULL;

-- Add depth for risk scoring
ALTER TABLE asset_components
ADD COLUMN depth INTEGER NOT NULL DEFAULT 1;

-- Prevent circular dependencies
ALTER TABLE asset_components
ADD CONSTRAINT chk_no_self_parent
  CHECK (parent_component_id IS NULL OR parent_component_id != id);

-- Add indexes
CREATE INDEX idx_asset_components_parent ON asset_components(parent_component_id)
WHERE parent_component_id IS NOT NULL;
CREATE INDEX idx_asset_components_depth ON asset_components(asset_id, depth);
```

## Ingestion Flow

### Two-Pass Processing (CycloneDX Pattern)

```go
// Pass 1: Create all components first
componentIDMap := make(map[string]shared.ID) // PURL → component ID
for _, dep := range report.Dependencies {
    compID := createOrUpdateComponent(dep)
    componentIDMap[dep.PURL] = compID
}

// Pass 2: Link with parent tracking
for _, dep := range report.Dependencies {
    parentID := lookupParent(dep.DependsOn, componentIDMap)
    depth := calculateDepth(dep, parentID)
    linkAssetWithParent(dep, parentID, depth)
}
```

### Depth Calculation

```go
// Direct dependencies: depth = 1
// Transitive with parent: depth = parent.depth + 1
// Transitive without parent info: depth = 2 (default)

if depType == DependencyTypeDirect {
    assetDep.SetDepth(1)
} else if parentDepID != nil {
    assetDep.SetDepth(parentDepth + 1)
} else {
    assetDep.SetDepth(2) // Default transitive depth
}
```

## API Response Examples

### GET /api/v1/assets/{id}/dependencies

```json
{
  "data": [
    {
      "id": "dep-uuid-1",
      "component": {
        "id": "comp-uuid-1",
        "name": "express",
        "version": "4.18.0",
        "purl": "pkg:npm/express@4.18.0",
        "ecosystem": "npm"
      },
      "dependency_type": "direct",
      "depth": 1,
      "parent_component_id": null,
      "finding_count": 2
    },
    {
      "id": "dep-uuid-2",
      "component": {
        "id": "comp-uuid-2",
        "name": "lodash",
        "version": "4.17.21",
        "purl": "pkg:npm/lodash@4.17.21",
        "ecosystem": "npm"
      },
      "dependency_type": "transitive",
      "depth": 2,
      "parent_component_id": "dep-uuid-1",
      "finding_count": 1
    }
  ]
}
```

### GET /api/v1/assets/{id}/dependency-tree

```json
{
  "data": {
    "component": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "children": [
      {
        "component": {
          "name": "express",
          "version": "4.18.0",
          "purl": "pkg:npm/express@4.18.0"
        },
        "depth": 1,
        "dependency_type": "direct",
        "finding_count": 2,
        "children": [
          {
            "component": {
              "name": "lodash",
              "version": "4.17.21",
              "purl": "pkg:npm/lodash@4.17.21"
            },
            "depth": 2,
            "dependency_type": "transitive",
            "finding_count": 1,
            "children": []
          }
        ]
      }
    ]
  }
}
```

## Limitations & Future Improvements

### Current Limitations

1. **Single Parent Only**: `parent_component_id` only tracks one parent. Cannot represent "lodash pulled in by BOTH express AND webpack" (diamond dependency).

2. **No Full Path Storage**: Unlike Snyk's `dependency_path` array, we only store immediate parent.

### Future Improvements (If Needed)

**Option: Add dependency_edges table for multiple parents:**

```sql
CREATE TABLE dependency_edges (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    parent_component_id UUID NOT NULL REFERENCES components(id),
    child_component_id UUID NOT NULL REFERENCES components(id),
    path TEXT, -- "express/body-parser/lodash"
    depth INTEGER NOT NULL,
    UNIQUE(asset_id, parent_component_id, child_component_id)
);
```

This would enable:
- Multiple paths to same component
- Full path display like Snyk
- Complex graph queries

**Current approach is sufficient for 90% of use cases.** Consider this enhancement only if users request "show all paths to vulnerable package" functionality.

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [SPDX 3.0 Standard](https://spdx.dev/learn/overview/)
- [Dependency-Track Documentation](https://docs.dependencytrack.org/)
- [GitHub Dependency Graph](https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph)
- [Snyk Vulnerability Database](https://docs.snyk.io/scan-with-snyk/snyk-open-source/manage-vulnerabilities/snyk-vulnerability-database)
