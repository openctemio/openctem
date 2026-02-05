# Component Ingestion: Edge Cases Analysis

## Câu hỏi gốc

> Agent gửi lên dependencies cho 1 asset nhưng component đã có từ trước (từ asset khác),
> nhưng asset chưa có component đó thì đang thực hiện như thế nào?

## Kết luận: Flow Hiện tại ĐÃ ĐÚNG ✅

### Flow chi tiết

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SCENARIO: Agent gửi lodash@4.17.21 cho Asset B                              │
│           Component lodash@4.17.21 đã tồn tại từ Asset A                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ State trước khi ingest:                                                     │
│   components: [ { id: "abc123", purl: "pkg:npm/lodash@4.17.21" } ]         │
│   asset_components: [ { asset_id: A, component_id: "abc123" } ]            │
│                                                                             │
│ Step 1: repo.Upsert(comp)                                                   │
│   SQL:                                                                      │
│     INSERT INTO components (id, purl, name, version, ...)                  │
│     VALUES ('new-uuid', 'pkg:npm/lodash@4.17.21', 'lodash', '4.17.21', ...)│
│     ON CONFLICT (purl) DO UPDATE SET                                       │
│         metadata = components.metadata || EXCLUDED.metadata,               │
│         updated_at = NOW()                                                 │
│     RETURNING id                                                           │
│                                                                             │
│   Result: id = "abc123" (ID CŨ được trả về, không phải new-uuid)           │
│                                                                             │
│ Step 2: repo.LinkAsset(assetDep)                                           │
│   assetDep = { asset_id: B, component_id: "abc123", ... }                  │
│                                                                             │
│   SQL:                                                                      │
│     INSERT INTO asset_components (id, asset_id, component_id, ...)         │
│     VALUES ('link-uuid', 'B', 'abc123', ...)                               │
│     ON CONFLICT (asset_id, component_id, path) DO UPDATE SET ...           │
│                                                                             │
│   Result: Tạo link mới giữa Asset B và Component abc123                    │
│                                                                             │
│ State sau khi ingest:                                                       │
│   components: [ { id: "abc123", purl: "pkg:npm/lodash@4.17.21" } ] ← KHÔNG ĐỔI│
│   asset_components: [                                                       │
│     { asset_id: A, component_id: "abc123" },                               │
│     { asset_id: B, component_id: "abc123" }  ← MỚI                         │
│   ]                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Edge Cases Analysis

### Edge Case 1: Component đã tồn tại, Asset chưa có
**Status:** ✅ Handled correctly

| Step | Action | Result |
|------|--------|--------|
| Upsert | `ON CONFLICT (purl) DO UPDATE` | Update metadata, return existing ID |
| LinkAsset | INSERT new row | Create asset_components link |

### Edge Case 2: Component đã tồn tại, Asset đã có component
**Status:** ✅ Handled correctly

| Step | Action | Result |
|------|--------|--------|
| Upsert | `ON CONFLICT (purl) DO UPDATE` | Update metadata, return existing ID |
| LinkAsset | `ON CONFLICT (asset_id, component_id, path) DO UPDATE` | Update dependency_type, depth |

### Edge Case 3: Component mới, Asset mới
**Status:** ✅ Handled correctly

| Step | Action | Result |
|------|--------|--------|
| Upsert | INSERT new row | Create component, return new ID |
| LinkAsset | INSERT new row | Create asset_components link |

### Edge Case 4: Same component, different paths
**Status:** ✅ Handled correctly

Unique constraint: `(asset_id, component_id, path)`

```
asset_components:
  { asset_id: A, component_id: lodash, path: "package.json" }      ← OK
  { asset_id: A, component_id: lodash, path: "packages/ui/package.json" }  ← OK (different path)
```

### Edge Case 5: Agent rescan - metadata merge
**Status:** ✅ Handled correctly

```sql
ON CONFLICT (purl) DO UPDATE SET
    metadata = components.metadata || EXCLUDED.metadata  -- JSONB merge
```

Metadata được merge, không overwrite. Thông tin mới được thêm vào, thông tin cũ giữ nguyên.

### Edge Case 5b: Rescan với child mới phụ thuộc parent từ scan trước
**Status:** ✅ FIXED (Hybrid approach implemented)

**Scenario:**
```
Scan 1: express@4.18.0 (direct, depth=1) được tạo
Scan 2: Chỉ gửi body-parser@1.20.0 (transitive, depends_on: express)
        express KHÔNG được gửi lại trong batch
```

**Solution:** Hybrid approach - In-memory lookup first, DB fallback second

```go
// processor_components.go
// Try to find parent in current batch first (fast)
parentID, parentDepth, found := p.findParentInMaps(dep.DependsOn, assetDepIDMap, assetDepDepthMap)

// Fallback: If not found, query DB for parent from previous scan
if !found {
    parentID, parentDepth, found = p.findParentInDB(ctx, assetID, dep.DependsOn)
}
```

**Flow:**
1. `findParentInMaps()` - O(1) lookup trong in-memory maps
2. Nếu không tìm thấy → `findParentInDB()` - Query `asset_components` by PURL
3. Nếu vẫn không tìm thấy → depth = 2 (default), parent_component_id = NULL

**Benefits:**
- ✅ Không yêu cầu agent gửi full tree mỗi lần scan
- ✅ Performance tối ưu (DB query chỉ khi cần)
- ✅ Backward compatible với agent cũ

### Edge Case 6: PURL không có, chỉ có name+version
**Status:** ✅ FIXED

```go
// NewComponent tự động build PURL
c.purl = BuildPURL(ecosystem, "", name, version)
// Result: "pkg:npm/lodash@4.17.21"

// Nếu agent gửi PURL, nó sẽ override PURL generated
if dep.PURL != "" {
    comp.SetPURL(dep.PURL)  // Override with agent's PURL
}
```

**Fix applied:** `SetPURL()` method added to entity, processor now prefers agent's PURL.

### Edge Case 7: Vulnerability count sync
**Status:** ✅ FIXED

```sql
-- Current (after fix):
ON CONFLICT (purl) DO UPDATE SET
    description = EXCLUDED.description,
    homepage = EXCLUDED.homepage,
    -- Note: vulnerability_count is NOT updated from agent data.
    -- It should only be updated by background jobs that count findings.
    metadata = components.metadata || EXCLUDED.metadata,
    updated_at = NOW()
```

**Fix applied:** Removed `vulnerability_count = EXCLUDED.vulnerability_count` from UPSERT query.

### Edge Case 8: License conflict
**Status:** ✅ Handled correctly

Licenses được link qua `component_licenses` table, không overwrite.
```go
// Link licenses to component (additive, not replace)
linked, err := p.repo.LinkLicenses(ctx, compID, dep.Licenses)
```

## Minor Issue Found

### Issue: ComponentsCreated vs ComponentsUpdated tracking sai

```go
// processor_components.go:250-255
if comp.ID() == compID {
    output.ComponentsCreated++
} else {
    output.ComponentsUpdated++
}
```

**Problem:** Logic này ĐÚNG nhưng confusing:
- `comp.ID()` = UUID mới tạo trong `NewComponent()`
- `compID` = UUID trả về từ DB

Khi INSERT thành công (component mới):
- DB dùng UUID mới → `RETURNING id` trả về UUID mới
- `comp.ID() == compID` → TRUE → `ComponentsCreated++` ✅

Khi UPDATE (component đã có):
- DB dùng UUID cũ → `RETURNING id` trả về UUID cũ
- `comp.ID() != compID` → FALSE → `ComponentsUpdated++` ✅

**Conclusion:** Logic đúng, nhưng có thể thêm comment để clarify.

## Recommendations

### 1. ~~Không update vulnerability_count từ agent~~ ✅ IMPLEMENTED

```sql
-- Fixed: vulnerability_count removed from UPDATE clause
ON CONFLICT (purl) DO UPDATE SET
    description = EXCLUDED.description,
    homepage = EXCLUDED.homepage,
    -- vulnerability_count: NOT updated, managed by background job
    metadata = components.metadata || EXCLUDED.metadata,
    updated_at = NOW()
```

### 2. ~~Prefer agent's PURL over generated PURL~~ ✅ IMPLEMENTED

```go
// Fixed: SetPURL() method added, processor updated
comp, err := component.NewComponent(dep.Name, dep.Version, ecosystem)
if dep.PURL != "" {
    comp.SetPURL(dep.PURL)  // Override with agent's more accurate PURL
}
```

### 3. Add clarifying comment (Low Priority)

```go
// Track if created or updated
// Note: comp.ID() is the UUID generated in NewComponent()
// compID is the UUID returned from DB (may be existing component's ID on conflict)
// If they match, it means INSERT was successful (new component)
// If they differ, it means UPDATE happened (existing component found via PURL conflict)
if comp.ID() == compID {
    output.ComponentsCreated++
} else {
    output.ComponentsUpdated++
}
```

## Summary

| Aspect | Status | Notes |
|--------|--------|-------|
| Component reuse | ✅ | PURL-based deduplication works |
| Asset linking | ✅ | Correctly links existing component to new asset |
| Metadata merge | ✅ | JSONB `||` operator merges |
| License linking | ✅ | Additive, not replace |
| Depth tracking | ✅ | Parent depth + 1 |
| Vulnerability count | ✅ | Fixed: Not updated from agent (managed by background job) |
| PURL handling | ✅ | Fixed: Agent's PURL preferred over generated PURL |

**Overall:** Flow hoạt động đúng. Cả 2 improvements đã được implement.
