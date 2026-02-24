# Component Ingestion: Edge Cases Analysis

## Original Question

> An agent sends dependencies for an asset, but the component already exists (from another asset),
> and the asset does not yet have that component -- how is this currently handled?

## Conclusion: Current Flow is CORRECT ✅

### Detailed Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SCENARIO: Agent sends lodash@4.17.21 for Asset B                             │
│           Component lodash@4.17.21 already exists from Asset A               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│ State before ingest:                                                        │
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
│   Result: id = "abc123" (OLD ID returned, not new-uuid)                    │
│                                                                             │
│ Step 2: repo.LinkAsset(assetDep)                                           │
│   assetDep = { asset_id: B, component_id: "abc123", ... }                  │
│                                                                             │
│   SQL:                                                                      │
│     INSERT INTO asset_components (id, asset_id, component_id, ...)         │
│     VALUES ('link-uuid', 'B', 'abc123', ...)                               │
│     ON CONFLICT (asset_id, component_id, path) DO UPDATE SET ...           │
│                                                                             │
│   Result: Creates new link between Asset B and Component abc123             │
│                                                                             │
│ State after ingest:                                                         │
│   components: [ { id: "abc123", purl: "pkg:npm/lodash@4.17.21" } ] ← UNCHANGED│
│   asset_components: [                                                       │
│     { asset_id: A, component_id: "abc123" },                               │
│     { asset_id: B, component_id: "abc123" }  ← NEW                         │
│   ]                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Edge Cases Analysis

### Edge Case 1: Component already exists, Asset does not have it
**Status:** ✅ Handled correctly

| Step | Action | Result |
|------|--------|--------|
| Upsert | `ON CONFLICT (purl) DO UPDATE` | Update metadata, return existing ID |
| LinkAsset | INSERT new row | Create asset_components link |

### Edge Case 2: Component already exists, Asset already has the component
**Status:** ✅ Handled correctly

| Step | Action | Result |
|------|--------|--------|
| Upsert | `ON CONFLICT (purl) DO UPDATE` | Update metadata, return existing ID |
| LinkAsset | `ON CONFLICT (asset_id, component_id, path) DO UPDATE` | Update dependency_type, depth |

### Edge Case 3: New component, new asset
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

Metadata is merged, not overwritten. New information is added, and existing information is preserved.

### Edge Case 5b: Rescan with new child depending on parent from previous scan
**Status:** ✅ FIXED (Hybrid approach implemented)

**Scenario:**
```
Scan 1: express@4.18.0 (direct, depth=1) was created
Scan 2: Only sends body-parser@1.20.0 (transitive, depends_on: express)
        express is NOT resent in the batch
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
1. `findParentInMaps()` - O(1) lookup in in-memory maps
2. If not found -> `findParentInDB()` - Query `asset_components` by PURL
3. If still not found -> depth = 2 (default), parent_component_id = NULL

**Benefits:**
- Does not require the agent to send the full tree on every scan
- Optimized performance (DB query only when needed)
- Backward compatible with older agents

### Edge Case 6: No PURL provided, only name+version
**Status:** ✅ FIXED

```go
// NewComponent automatically builds PURL
c.purl = BuildPURL(ecosystem, "", name, version)
// Result: "pkg:npm/lodash@4.17.21"

// If the agent sends a PURL, it will override the generated PURL
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

Licenses are linked via the `component_licenses` table, not overwritten.
```go
// Link licenses to component (additive, not replace)
linked, err := p.repo.LinkLicenses(ctx, compID, dep.Licenses)
```

## Minor Issue Found

### Issue: ComponentsCreated vs ComponentsUpdated tracking is misleading

```go
// processor_components.go:250-255
if comp.ID() == compID {
    output.ComponentsCreated++
} else {
    output.ComponentsUpdated++
}
```

**Problem:** The logic is CORRECT but confusing:
- `comp.ID()` = UUID newly created in `NewComponent()`
- `compID` = UUID returned from DB

When INSERT succeeds (new component):
- DB uses the new UUID -> `RETURNING id` returns the new UUID
- `comp.ID() == compID` -> TRUE -> `ComponentsCreated++` ✅

When UPDATE occurs (existing component):
- DB uses the old UUID -> `RETURNING id` returns the old UUID
- `comp.ID() != compID` -> FALSE -> `ComponentsUpdated++` ✅

**Conclusion:** Logic is correct, but a comment could be added to clarify.

## Recommendations

### 1. ~~Do not update vulnerability_count from agent~~ ✅ IMPLEMENTED

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

**Overall:** The flow works correctly. Both improvements have been implemented.
