/**
 * The inventory filter as query text, and back. The page's URL keeps its own
 * parameter names (so no link breaks); the list and the search box speak the
 * API's (the list query contract). This file is the bridge:
 *
 * - `textParams` is the filter part of the page as list params, for
 *   POST /query/parse to print as text;
 * - `applyTextResult` writes a checked text back: a filter chips can show
 *   becomes the page's filters again, anything else (an OR across fields, a
 *   group, a field the page cannot hold) is kept whole as `fq`, never
 *   flattened or partly dropped.
 *
 * What the text never holds: the lens (the open view), the tab (a locked type
 * condition), the default attribution, sort and paging.
 */

import type { ParseResult } from '@/features/query/api/query-api'
import { buildAssetQueryParams } from '../hooks/use-assets'
import { isCoverageCause } from './coverage-cause'
import { isExtraParam, type InventoryFilters } from './inventory-url'
import { openTab } from './inventory-tabs'
import { ASSET_LENSES } from '@/features/asset-types/registry.generated'
import type { AssetLens } from '@/features/asset-types/registry.generated'

/** The filter part of the page, as list params (without the tab, the lens, page state and any fq). */
export function textParams(filters: InventoryFilters): string {
  const params = buildAssetQueryParams({
    search: filters.search,
    types: filters.tab ? undefined : filters.types,
    subType: filters.tab ? undefined : filters.subType,
    minRiskScore: filters.minRiskScore,
    criticalities: filters.criticalities,
    statuses: filters.statuses,
    scopes: filters.scopes,
    exposures: filters.exposures,
    tags: filters.tags,
    tagsMode: filters.tagsMode,
    excludeTags: filters.excludeTags,
    dataClassifications: filters.dataClassifications,
    environments: filters.environments,
    providers: filters.providers,
    businessUnitIds: filters.businessUnitIds,
    hasOwner: filters.hasOwner,
    isControlPlane: filters.isControlPlane,
    isInternetFacing: filters.isInternetFacing,
    isCrownJewel: filters.isCrownJewel,
    isPrimary: filters.isPrimary,
    programAssets: filters.programAssets,
    freshness: filters.freshness,
    resolution: filters.resolution,
    coverage: filters.coverage,
    coverageCause: filters.coverageCause,
    technologies: filters.technologies,
    technologyCategories: filters.technologyCategories,
    technologyVersion: filters.technologyVersion,
    hasFindings: filters.hasFindings,
    lastSeenBefore: filters.lastSeenBefore,
    lastSeenAfter: filters.lastSeenAfter,
    expiresAfter: filters.expiresAfter,
    expiresBefore: filters.expiresBefore,
    // The default attribution is the list's own, not the viewer's condition.
    attribution: filters.attribution,
    scopeStatus: filters.scopeStatus,
    monitoringState: filters.monitoringState,
    liveness: filters.liveness,
    discoveredBy: filters.discoveredBy,
    firstSeenAfter: filters.firstSeenAfter,
    firstSeenBefore: filters.firstSeenBefore,
    extra: filters.extra,
  })
  return new URLSearchParams(params).toString()
}

type ListKey =
  | 'types'
  | 'criticalities'
  | 'statuses'
  | 'scopes'
  | 'exposures'
  | 'tags'
  | 'excludeTags'
  | 'dataClassifications'
  | 'environments'
  | 'providers'
  | 'businessUnitIds'
  | 'attribution'
  | 'scopeStatus'
  | 'monitoringState'
  | 'liveness'
  | 'discoveredBy'
  | 'technologies'
  | 'technologyCategories'
type FlagKey = 'hasOwner' | 'isControlPlane' | 'isInternetFacing' | 'isCrownJewel' | 'hasFindings'
type TextKey =
  | 'search'
  | 'subType'
  | 'programAssets'
  | 'freshness'
  | 'resolution'
  | 'coverage'
  | 'lastSeenBefore'
  | 'lastSeenAfter'
  | 'expiresBefore'
  | 'expiresAfter'
  | 'firstSeenAfter'
  | 'firstSeenBefore'

const LIST_NAMES: Record<string, ListKey> = {
  type: 'types',
  criticality: 'criticalities',
  status: 'statuses',
  scope: 'scopes',
  exposure: 'exposures',
  tag: 'tags',
  tag_not: 'excludeTags',
  data_classification: 'dataClassifications',
  environment: 'environments',
  provider: 'providers',
  business_unit: 'businessUnitIds',
  attribution: 'attribution',
  scope_status: 'scopeStatus',
  monitoring_state: 'monitoringState',
  liveness: 'liveness',
  discovered_by: 'discoveredBy',
  technology: 'technologies',
  technology_category: 'technologyCategories',
}
const FLAG_NAMES: Record<string, FlagKey> = {
  has_owner: 'hasOwner',
  control_plane: 'isControlPlane',
  internet_facing: 'isInternetFacing',
  crown_jewel: 'isCrownJewel',
  has_findings: 'hasFindings',
}
const TEXT_NAMES: Record<string, TextKey> = {
  q: 'search',
  sub_type: 'subType',
  program_assets: 'programAssets',
  freshness: 'freshness',
  resolution: 'resolution',
  coverage: 'coverage',
  last_seen_lte: 'lastSeenBefore',
  last_seen_gte: 'lastSeenAfter',
  expires_lt: 'expiresBefore',
  expires_gt: 'expiresAfter',
  created_at_gte: 'firstSeenAfter',
  created_at_lte: 'firstSeenBefore',
}

const splitList = (v: string) =>
  v
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)

/**
 * The page's filters for list params the search box returned, or null when the
 * page has no control for one of them (the text is then kept whole as fq).
 */
export function filtersFromParams(params: Record<string, string>): InventoryFilters | null {
  const out: InventoryFilters = {}
  const rec = out as Record<string, unknown>
  for (const [name, value] of Object.entries(params)) {
    if (value === '') return null
    if (name in LIST_NAMES) {
      const list = splitList(value)
      if (list.length === 0) return null
      rec[LIST_NAMES[name]] = list
    } else if (name === 'tag_all') {
      if (out.tags) return null
      out.tags = splitList(value)
      out.tagsMode = 'all'
    } else if (name in FLAG_NAMES) {
      if (value !== 'true' && value !== 'false') return null
      rec[FLAG_NAMES[name]] = value === 'true'
    } else if (name === 'primary') {
      if (value !== 'true') return null
      out.isPrimary = true
    } else if (name === 'risk_score_gte') {
      const n = Number(value)
      if (!Number.isInteger(n) || n < 0 || n > 100) return null
      out.minRiskScore = n
    } else if (name === 'coverage_cause') {
      if (!isCoverageCause(value)) return null
      out.coverageCause = value
    } else if (name === 'technology_version') {
      out.technologyVersion = value
    } else if (name === 'lens') {
      const lens = value as AssetLens
      if (!ASSET_LENSES.some((l) => l.id === lens)) return null
      out.lens = lens
    } else if (name in TEXT_NAMES) {
      rec[TEXT_NAMES[name]] = value
    } else if (isExtraParam(name)) {
      ;(out.extra ??= {})[name] = value
    } else {
      return null
    }
  }
  // A version belongs to one technology; the page cannot hold it alone.
  if (out.technologyVersion !== undefined && !out.technologies?.length) return null
  // Any-of and every-of tags together are an OR the chips cannot show.
  return out
}

/** The state of the page that the text does not replace. */
function pageState(filters: InventoryFilters): InventoryFilters {
  return {
    lens: filters.lens,
    tab: filters.tab,
    sort: filters.sort,
    pageSize: filters.pageSize,
    group: filters.group,
    view: filters.view,
  }
}

/**
 * The page's filters after a checked text: the text replaces the filter, the
 * lens, tab, sort, page size, grouping and open view stay. Attribute filters
 * (`propertiesFilter`) stay beside a text chips can show; a text kept whole
 * runs as one document, which has no room for them, so they go with it.
 */
export function applyTextResult(filters: InventoryFilters, result: ParseResult): InventoryFilters {
  const base = pageState(filters)
  if (result.text === '') return base
  if (!result.advanced && result.params) {
    const parsed = filtersFromParams(result.params)
    if (parsed) {
      const next: InventoryFilters = {
        ...base,
        ...parsed,
        propertiesFilter: filters.propertiesFilter,
      }
      // A tab locks the type: a type in the text cannot widen or contradict it.
      if (openTab(filters)) {
        delete next.types
        delete next.subType
      }
      if (parsed.lens) next.lens = parsed.lens
      return next
    }
  }
  return { ...base, advanced: result.text }
}
