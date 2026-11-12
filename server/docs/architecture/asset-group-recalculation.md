# Asset Group Stats Recalculation

## Overview

Asset groups maintain cached statistics (`asset_count`, `risk_score`, `finding_count`, etc.) that are automatically recalculated when assets change.

## Scenarios

| Scenario | Trigger |
|----------|---------|
| Create group with assets | `AssetGroupService.CreateAssetGroup` |
| Add assets to group | `AssetGroupService.AddAssetsToGroup` |
| Remove assets from group | `AssetGroupService.RemoveAssetsFromGroup` |
| Update asset | `AssetService.UpdateAsset` |
| Delete asset | `AssetService.DeleteAsset` |

## Architecture

```mermaid
graph TD
    A[AssetService] -->|UpdateAsset| B[recalculateAffectedGroups]
    A -->|DeleteAsset| B
    B -->|GetGroupIDsByAssetID| C[AssetGroupRepository]
    B -->|RecalculateCounts| C
    C -->|UPDATE| D[(PostgreSQL)]

    E[AssetGroupService] -->|AddAssets/RemoveAssets| F[RecalculateCounts]
    F -->|UPDATE| D
```

## Flow: Remove Assets from Group

```mermaid
sequenceDiagram
    participant UI as Frontend
    participant API as AssetGroupHandler
    participant SVC as AssetGroupService
    participant DB as PostgreSQL

    UI->>API: POST /asset-groups/{id}/assets/remove
    API->>SVC: RemoveAssetsFromGroup(groupID, assetIDs)
    SVC->>DB: DELETE FROM asset_group_members
    SVC->>DB: RecalculateCounts(groupID)
    Note over DB: UPDATE asset_groups SET<br/>asset_count, risk_score, ...
    SVC-->>API: nil (success)
    API->>SVC: GetAssetGroup(groupID)
    SVC-->>API: Updated AssetGroup
    API-->>UI: AssetGroupResponse (with new counts)
```

## Flow: Update Asset

```mermaid
sequenceDiagram
    participant UI as Frontend
    participant API as AssetHandler
    participant SVC as AssetService
    participant REPO as AssetGroupRepository
    participant DB as PostgreSQL

    UI->>API: PATCH /assets/{id}
    API->>SVC: UpdateAsset(assetID, input)
    SVC->>DB: UPDATE assets
    SVC->>SVC: recalculateAffectedGroups(assetID)
    SVC->>REPO: GetGroupIDsByAssetID(assetID)
    REPO-->>SVC: []groupIDs
    loop For each groupID
        SVC->>REPO: RecalculateCounts(groupID)
        REPO->>DB: UPDATE asset_groups SET ...
    end
    SVC-->>API: Updated Asset
    API-->>UI: AssetResponse
```

## Implementation Details

### Key Components

- **`AssetGroupRepository.RecalculateCounts`**: Updates all cached stats using SQL aggregations
- **`AssetGroupRepository.GetGroupIDsByAssetID`**: Finds groups containing a specific asset
- **`AssetService.recalculateAffectedGroups`**: Helper that triggers recalculation for all affected groups

### Cached Fields

```sql
asset_count        -- Total assets in group
domain_count       -- Assets of type 'domain'
website_count      -- Assets of type 'website'
service_count      -- Assets of type 'api' or 'service'
repository_count   -- Assets of type 'repository'
cloud_count        -- Assets of type 'cloud' or 'container'
credential_count   -- Assets of type 'credential'
risk_score         -- AVG(asset.risk_score)
finding_count      -- SUM(asset.finding_count)
```
