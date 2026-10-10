/**
 * Assets Hooks - Barrel Export
 */

export {
  // Basic CRUD hooks
  useAssets,
  useAsset,
  useAssetsByType,
  useAssetStats,
  getAsset,
  createAsset,
  updateAsset,
  deleteAsset,
  bulkDeleteAssets,
  // Repository extension hooks
  useAssetWithRepository,
  useRepositoryExtension,
  useRepositoryAssets,
  createRepositoryAsset,
  updateRepositoryExtension,
  // Status operations
  activateAsset,
  deactivateAsset,
  archiveAsset,
} from './use-assets'
export type { AssetStatsData, AssetSearchFilters } from './use-assets'

export { useAssetTags } from './use-asset-tags'

// Asset ownership hooks
export {
  useAssetOwners,
  addAssetOwner,
  updateAssetOwner,
  removeAssetOwner,
} from './use-asset-owners'

// Asset relationship hooks
export {
  useAssetRelationships,
  addAssetRelationship,
  addAssetRelationshipBatch,
  updateAssetRelationship,
  removeAssetRelationship,
} from './use-asset-relationships'

// Asset identity hooks (identifiers + renames)
export { useAssetIdentifiers, useAssetRenames } from './use-asset-identity'
export type { AssetRename } from './use-asset-identity'

// Asset attribution (RFC-036): state, evidence and a person's decision
export { useAssetAttribution, useDecideAttribution } from './use-asset-attribution'

// Where asset values come from (RFC-069)
export {
  useAttributeSources,
  useAttributeLock,
  useReconciliationSettings,
  saveReconciliationSettings,
  previewReconciliationSettings,
} from './use-attribute-sources'
