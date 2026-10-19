/**
 * Asset Group Transformers
 *
 * Utilities for transforming between API types (snake_case) and frontend types (camelCase)
 */

import type { AssetGroup, CreateAssetGroupInput, UpdateAssetGroupInput } from '../types'
import type {
  Criticality,
  Environment,
  ApiAssetGroup,
  CreateAssetGroupApiInput,
  CreateAssetInGroupApiInput,
  UpdateAssetGroupApiInput,
  ApiGroupAsset,
  ApiGroupFinding,
} from '../api'
import type { GroupAsset, GroupFinding } from '../types'
import { FINDINGS_OPEN_STATUSES } from '@/features/findings/lib/list-defaults'

// ============================================
// API Response -> Frontend Type
// ============================================

/**
 * Transform API AssetGroup to frontend AssetGroup
 */
export function transformApiAssetGroup(api: ApiAssetGroup): AssetGroup {
  // Every field of the generated wire type is optional — swag emits no
  // `required` list for response structs, so the contract permits any of them
  // to be absent. This transformer is already the API-to-view-model boundary,
  // so the defaults belong here rather than in a type that just asserted the
  // fields are always present.
  return {
    id: api.id ?? '',
    name: api.name ?? '',
    description: api.description,
    environment: (api.environment ?? 'production') as Environment,
    criticality: (api.criticality ?? 'medium') as Criticality,

    // Business Context
    businessUnit: api.business_unit,
    owner: api.owner,
    ownerEmail: api.owner_email,
    tags: api.tags,

    // Asset counts
    assetCount: api.asset_count ?? 0,
    domainCount: api.domain_count ?? 0,
    websiteCount: api.website_count ?? 0,
    serviceCount: api.service_count ?? 0,
    repositoryCount: api.repository_count ?? 0,
    projectCount: api.repository_count ?? 0, // @deprecated, same as repositoryCount
    cloudCount: api.cloud_count ?? 0,
    credentialCount: api.credential_count ?? 0,

    // Risk metrics
    riskScore: api.risk_score ?? 0,
    findingCount: api.finding_count ?? 0,

    // Timestamps
    createdAt: api.created_at ?? '',
    updatedAt: api.updated_at ?? '',
  }
}

/**
 * Transform API GroupAsset to frontend GroupAsset. The type is the stored
 * asset type as is (subdomain, application, ip_address, ...): the page labels
 * it from the asset type registry.
 */
export function transformApiGroupAsset(api: ApiGroupAsset): GroupAsset {
  return {
    id: api.id ?? '',
    name: api.name ?? '',
    type: api.type || 'unknown',
    status: api.status ?? 'active',
    riskScore: api.risk_score ?? 0,
    findingCount: api.finding_count ?? 0,
    lastSeen: api.last_seen ?? '',
  }
}

const OPEN_STATUSES: ReadonlySet<string> = new Set(FINDINGS_OPEN_STATUSES)

/**
 * Transform API GroupFinding to frontend GroupFinding. The status is kept as
 * stored; `open` uses the findings' open statuses, the set the group's
 * finding count counts.
 */
export function transformApiGroupFinding(api: ApiGroupFinding): GroupFinding {
  const status = api.status ?? 'new'
  return {
    id: api.id ?? '',
    title: api.title ?? '',
    severity: (api.severity ?? 'info') as GroupFinding['severity'],
    status,
    open: OPEN_STATUSES.has(status) || status === 'open',
    assetName: api.asset_name ?? '',
    discoveredAt: api.discovered_at ?? '',
  }
}

// ============================================
// Frontend Type -> API Input
// ============================================

/**
 * Transform frontend CreateAssetGroupInput to API input
 */
export function transformCreateAssetGroupInput(
  input: CreateAssetGroupInput
): CreateAssetGroupApiInput {
  return {
    name: input.name,
    description: input.description,
    environment: input.environment,
    criticality: input.criticality,

    // Business Context
    business_unit: input.businessUnit,
    owner: input.owner,
    owner_email: input.ownerEmail,
    tags: input.tags,

    // Assets
    existing_asset_ids: input.existingAssetIds,
    new_assets: input.newAssets?.map((asset) => ({
      type: asset.type as CreateAssetInGroupApiInput['type'],
      name: asset.name,
      description: asset.description,
      tags: asset.tags,
    })),
  }
}

/**
 * Transform frontend UpdateAssetGroupInput to API input
 */
export function transformUpdateAssetGroupInput(
  input: UpdateAssetGroupInput
): UpdateAssetGroupApiInput {
  return {
    name: input.name,
    description: input.description,
    environment: input.environment,
    criticality: input.criticality,

    // Business Context
    business_unit: input.businessUnit,
    owner: input.owner,
    owner_email: input.ownerEmail,
    tags: input.tags,
  }
}

// ============================================
// List Transformers
// ============================================

/**
 * Transform API AssetGroup list to frontend list
 */
export function transformApiAssetGroups(apiList: ApiAssetGroup[]): AssetGroup[] {
  return apiList.map(transformApiAssetGroup)
}

/**
 * Transform API GroupAsset list to frontend list
 */
export function transformApiGroupAssets(apiList: ApiGroupAsset[]): GroupAsset[] {
  return apiList.map(transformApiGroupAsset)
}

/**
 * Transform API GroupFinding list to frontend list
 */
export function transformApiGroupFindings(apiList: ApiGroupFinding[]): GroupFinding[] {
  return apiList.map(transformApiGroupFinding)
}
