// API types
export type {
  ApiAssetType,
  ApiAssetTypeCategory,
  ApiAssetTypeListResponse,
  AssetTypeFilter,
} from './api/asset-type-api.types'

// API hooks
export {
  useAssetTypes,
  useActiveAssetTypes,
  useAssetType,
  useScopeTypeConfigs,
  assetTypeToScopeConfig,
} from './api/use-asset-type-api'

// Asset type registry (RFC-042): classes, lenses and per-type schemas
export { useAssetTypeRegistry, ASSET_TYPE_REGISTRY_ENDPOINT } from './api/use-asset-type-registry'
export {
  classOfAsset,
  lensOfClass,
  classLabel,
  lensLabel,
  classAndLensLabel,
  type AssetTypeRegistry,
} from './lib/asset-registry'
export type { AssetClass, AssetLens, LegacyAssetCategory } from './registry.generated'
