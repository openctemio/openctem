# Component-Dependency System: Full Stack Evaluation

## Executive Summary

| Layer | Status | Issues Found | Priority |
|-------|--------|--------------|----------|
| **Agent SDK** | ⚠️ Partial | Missing depth field, format mismatch risk | HIGH |
| **API Ingest** | ⚠️ Partial | Depth hardcoded to 2, parent lookup fragile | HIGH |
| **API Handlers** | ❌ Incomplete | DTOs missing depth/parent fields | HIGH |
| **UI** | ⚠️ Partial | Types ready, visualization missing | MEDIUM |

---

## 1. Agent SDK Analysis

### What Works ✅
- EIS `Dependency` struct includes `DependsOn []string` field
- `Relationship` field supports "direct", "indirect", "transit"
- PURL and ecosystem correctly captured
- Two-pass approach in processor handles parent lookup

### Issues Found ❌

| Issue | Severity | Description |
|-------|----------|-------------|
| **No depth in EIS** | HIGH | SDK doesn't calculate or send depth |
| **DependsOn format varies** | HIGH | Scanner provides IDs, we lookup by PURL - mismatch risk |
| **No metrics in response** | MEDIUM | IngestResponse missing DependenciesCreated/Updated |

### Code Location
- `/home/ubuntu/exploopio/sdk/pkg/eis/dependency_types.go`
- `/home/ubuntu/exploopio/sdk/pkg/scanners/trivy/parser.go`

---

## 2. API Ingest Processor Analysis

### What Works ✅
- Two-pass processing (CycloneDX pattern)
- Parent component ID stored in `asset_components`
- Finding → Component uses direct `components.id` reference

### Issues Found ❌

| Issue | Severity | Description |
|-------|----------|-------------|
| **Depth hardcoded to 2** | HIGH | All transitive deps get depth=2, regardless of actual chain |
| **DependsOn key mismatch** | HIGH | Scanner sends IDs, lookup uses PURL - parent may not be found |
| **Silent parent failures** | MEDIUM | No logging when parent lookup fails |
| **Only first parent used** | MEDIUM | Diamond dependencies lose other parents |

### Critical Code (processor_components.go:234-235)
```go
// Comment says "parent's depth + 1" but code just sets 2
assetDep.SetDepth(2)  // ← ALWAYS 2, never reads parent's actual depth
```

### Expected vs Actual
```
Dependency Chain:    express → lodash → lodash-es

Expected:
  express    depth=1 (direct)
  lodash     depth=2 (transitive from express)
  lodash-es  depth=3 (transitive from lodash)

Actual:
  express    depth=1 ✅
  lodash     depth=2 ✅
  lodash-es  depth=2 ❌ (should be 3)
```

---

## 3. API Handler Analysis

### What Works ✅
- Database schema has `depth` and `parent_component_id`
- Repository queries include these fields
- ListDependencies orders by depth

### Issues Found ❌

| Issue | Severity | Description |
|-------|----------|-------------|
| **ComponentResponse missing fields** | HIGH | No `depth`, `parent_component_id` in response |
| **FindingResponse missing component** | HIGH | Only `component_id`, no component details |
| **No tree endpoint** | MEDIUM | Cannot get dependency hierarchy |
| **No depth filtering** | LOW | Cannot query `?depth=1` for direct only |

### Handler Code Location
- `/home/ubuntu/exploopio/api/internal/infra/http/handler/component_handler.go` (lines 34-54)
- `/home/ubuntu/exploopio/api/internal/infra/http/handler/vulnerability_handler.go` (lines 224-320)

---

## 4. UI Analysis

### What Works ✅
- TypeScript types include `depth`, `isDirect`, `dependencyPath`
- Tooltip shows "Transitive dependency (depth: X)"
- `DependencyGraph` type defined (nodes, edges)

### Issues Found ❌

| Issue | Severity | Description |
|-------|----------|-------------|
| **No tree visualization** | MEDIUM | DependencyGraph type unused |
| **Depth only in tooltip** | LOW | Not visible in table column |
| **No component-finding link** | MEDIUM | Findings and components are siloed |

### UI Files
- `/home/ubuntu/exploopio/ui/src/features/components/components/component-table.tsx`
- `/home/ubuntu/exploopio/ui/src/features/components/types/component.types.ts`

---

## 5. Data Flow Issues

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Agent SDK     │     │  API Ingest     │     │  API Handler    │     │      UI         │
│                 │     │                 │     │                 │     │                 │
│ ✅ DependsOn    │────▶│ ⚠️ Depth=2     │────▶│ ❌ No depth    │────▶│ ⚠️ Types only  │
│ ✅ Relationship │     │    always       │     │    in response  │     │    no visual    │
│ ❌ No depth     │     │ ⚠️ Key mismatch│     │ ❌ No parent   │     │                 │
│                 │     │    risk         │     │    in response  │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## 6. Best Implementation Plan

### Phase 1: Fix Critical Issues (HIGH PRIORITY)

#### 1.1 Fix Depth Calculation in Processor
**File:** `api/internal/app/ingest/processor_components.go`

```go
// BEFORE (line 234-235):
assetDep.SetDepth(2)

// AFTER:
if parentDepID, ok := assetDepIDMap[parentKey]; ok {
    // Fetch parent's depth from database or cache
    parentDep, err := p.repo.GetDependency(ctx, parentDepID)
    if err == nil && parentDep != nil {
        assetDep.SetDepth(parentDep.Depth() + 1)
    } else {
        assetDep.SetDepth(2) // Fallback
    }
}
```

**Better approach - track depth in map:**
```go
// Add depth tracking in pass 2
assetDepDepthMap := make(map[string]int) // PURL → depth

// When linking:
parentDepth := 1
if parentKey != "" {
    if d, ok := assetDepDepthMap[parentKey]; ok {
        parentDepth = d
    }
}
assetDep.SetDepth(parentDepth + 1)
assetDepDepthMap[key] = assetDep.Depth()
```

#### 1.2 Add Fields to API Response DTOs
**File:** `api/internal/infra/http/handler/component_handler.go`

```go
type ComponentResponse struct {
    ID                 string  `json:"id"`
    Name               string  `json:"name"`
    Version            string  `json:"version"`
    Ecosystem          string  `json:"ecosystem"`
    PURL               string  `json:"purl"`
    // NEW FIELDS:
    Depth              int     `json:"depth"`
    ParentComponentID  *string `json:"parent_component_id,omitempty"`
    DependencyType     string  `json:"dependency_type"`
    IsDirect           bool    `json:"is_direct"`
}
```

#### 1.3 Fix DependsOn Key Matching
**File:** `api/internal/app/ingest/processor_components.go`

```go
// Build multiple lookup keys for parent
func (p *ComponentProcessor) findParentID(dependsOn []string, assetDepIDMap map[string]shared.ID) *shared.ID {
    for _, parentRef := range dependsOn {
        // Try exact match first
        if id, ok := assetDepIDMap[parentRef]; ok {
            return &id
        }
        // Try PURL format
        if id, ok := assetDepIDMap["pkg:"+parentRef]; ok {
            return &id
        }
        // Try name@version format
        if id, ok := assetDepIDMap[parentRef]; ok {
            return &id
        }
    }
    return nil
}
```

### Phase 2: Enhance API (MEDIUM PRIORITY)

#### 2.1 Add Dependency Tree Endpoint
**File:** `api/internal/infra/http/handler/component_handler.go`

```go
// GET /api/v1/assets/{id}/components/tree
func (h *ComponentHandler) GetDependencyTree(c *gin.Context) {
    assetID := c.Param("id")

    // Get all dependencies ordered by depth
    deps, _ := h.repo.ListDependencies(ctx, assetID, pagination.All())

    // Build tree structure
    tree := buildDependencyTree(deps)

    c.JSON(200, tree)
}

type DependencyTreeNode struct {
    Component    ComponentResponse      `json:"component"`
    Children     []DependencyTreeNode   `json:"children"`
    FindingCount int                    `json:"finding_count"`
}
```

#### 2.2 Add Depth Filter
```go
// GET /api/v1/assets/{id}/components?depth=1 (direct only)
// GET /api/v1/assets/{id}/components?depth=2+ (transitive only)
```

### Phase 3: UI Enhancements (LOW PRIORITY)

#### 3.1 Add Tree Visualization Component
```tsx
// New component: DependencyTreeView.tsx
import { Tree } from '@tanstack/react-table' // or similar

function DependencyTreeView({ assetId }: { assetId: string }) {
    const { data } = useDependencyTree(assetId);

    return (
        <TreeView
            data={data}
            renderNode={(node) => (
                <div className="flex items-center gap-2">
                    <EcosystemBadge ecosystem={node.ecosystem} />
                    <span>{node.name}@{node.version}</span>
                    {node.findingCount > 0 && (
                        <Badge variant="destructive">{node.findingCount} vulns</Badge>
                    )}
                </div>
            )}
        />
    );
}
```

#### 3.2 Add Depth Column to Table
```tsx
// component-table.tsx
const columns = [
    // ... existing columns
    {
        id: 'depth',
        header: 'Depth',
        cell: ({ row }) => (
            <Badge variant={row.original.depth === 1 ? 'default' : 'secondary'}>
                {row.original.depth === 1 ? 'Direct' : `Depth ${row.original.depth}`}
            </Badge>
        ),
    },
];
```

---

## 7. Priority Matrix

| Task | Effort | Impact | Priority |
|------|--------|--------|----------|
| Fix depth calculation | Low | High | P0 |
| Add depth/parent to DTO | Low | High | P0 |
| Fix DependsOn key matching | Medium | High | P1 |
| Add tree endpoint | Medium | Medium | P2 |
| Add depth filtering | Low | Medium | P2 |
| UI tree visualization | High | Medium | P3 |

---

## 8. Files to Modify

### Immediate (P0-P1)
```
api/internal/app/ingest/processor_components.go     # Fix depth calculation
api/internal/infra/http/handler/component_handler.go # Add DTO fields
api/internal/infra/http/handler/vulnerability_handler.go # Add component to finding response
```

### Short-term (P2)
```
api/internal/infra/http/routes/assets.go           # Add tree endpoint
api/internal/infra/postgres/component_repository.go # Add depth filter
```

### Medium-term (P3)
```
ui/src/features/components/components/dependency-tree.tsx # New component
ui/src/features/components/api/component-api.types.ts     # Update types
ui/src/features/components/components/component-table.tsx # Add depth column
```

---

## 9. Verification Checklist

After implementation:

- [ ] Depth correctly calculated for nested transitive deps
- [ ] API response includes `depth` and `parent_component_id`
- [ ] Parent lookup works with different DependsOn formats
- [ ] Tree endpoint returns hierarchical structure
- [ ] UI displays depth in table
- [ ] UI shows dependency tree visualization

---

## 10. Conclusion

**Root Cause:** Depth is hardcoded to 2 in processor, and API DTOs don't expose hierarchy fields.

**Quick Win:** Fix depth calculation + update DTOs = significant improvement with low effort.

**Full Solution:** Add tree endpoint + UI visualization for complete dependency chain analysis.
