/**
 * URL <-> filter-state codec for the unified All-Assets inventory.
 *
 * Every filter lives in the query string so an inventory view is deep-linkable
 * and shareable (scoped to the viewer's own tenant + permissions — the URL
 * carries the *filter*, never data). Reading the URL on load fully restores the
 * filter state; writing replaces the URL without a history push so the back
 * button still leaves the page rather than unwinding each keystroke.
 *
 * Saved views (persisting a named filter set server-side) are intentionally out
 * of scope here — that is a v2 concern.
 */

import type { SortingState } from '@tanstack/react-table'
import { isPropertyKey } from '@/features/asset-types/lib/property-schema'
import { ASSET_LENSES, type AssetLens } from '@/features/asset-types/registry.generated'
import type { AssetSearchFilters } from '../hooks/use-assets'
import type { AssetType, Criticality, ExposureLevel, AssetScope } from '../types/asset.types'

/** The subset of AssetSearchFilters the inventory page drives + syncs to the URL. */
export type InventoryFilters = Pick<
  AssetSearchFilters,
  | 'search'
  | 'types'
  | 'minRiskScore'
  | 'subType'
  | 'propertiesFilter'
  | 'criticalities'
  | 'statuses'
  | 'scopes'
  | 'exposures'
  | 'tags'
  | 'dataClassifications'
  | 'environments'
  | 'providers'
  | 'businessUnitIds'
  | 'hasOwner'
  | 'isControlPlane'
  | 'isInternetAccessible'
  | 'isCrownJewel'
  | 'programAssets'
  | 'hasFindings'
  | 'lastSeenBefore'
  | 'lastSeenAfter'
  | 'expiresBefore'
  | 'expiresAfter'
  | 'attribution'
  | 'sort'
  | 'page'
  | 'pageSize'
> & {
  /** One registry lens (`?lens=code`): every type of it, aliases included. */
  lens?: AssetLens
}

/** The risk score from which an asset counts as high risk (the API's high_risk_count). */
export const HIGH_RISK_SCORE = 70

const LENS_PARAM = 'lens'
const MIN_RISK_PARAM = 'min_risk_score'

function isLens(v: string): v is AssetLens {
  return ASSET_LENSES.some((l) => l.id === v)
}

// Array-valued filter keys and their URL param names.
const ARRAY_PARAMS = {
  types: 'types',
  criticalities: 'criticalities',
  statuses: 'statuses',
  scopes: 'scopes',
  exposures: 'exposures',
  tags: 'tags',
  dataClassifications: 'data_classifications',
  environments: 'environments',
  providers: 'providers',
  businessUnitIds: 'business_unit_ids',
  attribution: 'attribution',
} as const

// Boolean-valued filter keys and their URL param names.
const BOOL_PARAMS = {
  hasOwner: 'has_owner',
  isControlPlane: 'is_control_plane',
  isInternetAccessible: 'is_internet_accessible',
  isCrownJewel: 'is_crown_jewel',
  hasFindings: 'has_findings',
} as const

// String-valued filter keys and their URL param names.
const STRING_PARAMS = {
  search: 'q',
  subType: 'sub_type',
  sort: 'sort',
  lastSeenBefore: 'last_seen_before',
  lastSeenAfter: 'last_seen_after',
  expiresBefore: 'expires_before',
  expiresAfter: 'expires_after',
  programAssets: 'program_assets',
} as const

type ArrayKey = keyof typeof ARRAY_PARAMS
type BoolKey = keyof typeof BOOL_PARAMS
type StringKey = keyof typeof STRING_PARAMS

/** Parse the current URLSearchParams into an InventoryFilters object. */
export function parseInventoryFilters(sp: URLSearchParams): InventoryFilters {
  const out: InventoryFilters = {}

  for (const key of Object.keys(ARRAY_PARAMS) as ArrayKey[]) {
    const raw = sp.get(ARRAY_PARAMS[key])
    if (raw) {
      const vals = raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
      if (vals.length > 0) {
        // The filter fields are typed string[] under different unions; a single
        // cast at the boundary keeps the codec generic without per-key noise.
        ;(out as Record<string, unknown>)[key] = vals
      }
    }
  }

  for (const key of Object.keys(BOOL_PARAMS) as BoolKey[]) {
    const raw = sp.get(BOOL_PARAMS[key])
    if (raw === 'true') out[key] = true
    else if (raw === 'false') out[key] = false
  }

  for (const key of Object.keys(STRING_PARAMS) as StringKey[]) {
    const raw = sp.get(STRING_PARAMS[key])
    if (raw) out[key] = raw
  }

  const props = parsePropertiesParam(sp.get(PROPERTIES_PARAM))
  if (props) out.propertiesFilter = props

  // An unknown lens would only ever match nothing: drop it.
  const lens = sp.get(LENS_PARAM)
  if (lens && isLens(lens)) out.lens = lens
  const minRisk = Number(sp.get(MIN_RISK_PARAM))
  if (sp.get(MIN_RISK_PARAM) && Number.isInteger(minRisk) && minRisk >= 0 && minRisk <= 100) {
    out.minRiskScore = minRisk
  }

  const page = Number(sp.get('page'))
  if (Number.isFinite(page) && page > 0) out.page = page
  const perPage = Number(sp.get('per_page'))
  if (Number.isFinite(perPage) && perPage > 0) out.pageSize = perPage

  return out
}

/** Serialize InventoryFilters back into a URLSearchParams (stable key order). */
export function serializeInventoryFilters(f: InventoryFilters): URLSearchParams {
  const sp = new URLSearchParams()

  for (const key of Object.keys(ARRAY_PARAMS) as ArrayKey[]) {
    const vals = f[key] as string[] | undefined
    if (vals && vals.length > 0) sp.set(ARRAY_PARAMS[key], vals.join(','))
  }
  for (const key of Object.keys(BOOL_PARAMS) as BoolKey[]) {
    const v = f[key]
    if (v !== undefined) sp.set(BOOL_PARAMS[key], String(v))
  }
  for (const key of Object.keys(STRING_PARAMS) as StringKey[]) {
    const v = f[key]
    if (v) sp.set(STRING_PARAMS[key], v)
  }
  const props = serializePropertiesParam(f.propertiesFilter)
  if (props) sp.set(PROPERTIES_PARAM, props)
  if (f.lens) sp.set(LENS_PARAM, f.lens)
  if (f.minRiskScore !== undefined) sp.set(MIN_RISK_PARAM, String(f.minRiskScore))
  if (f.page && f.page > 1) sp.set('page', String(f.page))
  if (f.pageSize && f.pageSize !== DEFAULT_PAGE_SIZE) sp.set('per_page', String(f.pageSize))

  return sp
}

/**
 * Attribute filters, as the API takes them: `properties=key:value,key:value`
 * (repeat a key for OR). Only schema keys are kept: a key outside the
 * registry can never match and is dropped from the URL.
 */
export const PROPERTIES_PARAM = 'properties'

function parsePropertiesParam(raw: string | null): Record<string, string[]> | undefined {
  if (!raw) return undefined
  const out: Record<string, string[]> = {}
  for (const pair of raw.split(',')) {
    const i = pair.indexOf(':')
    if (i <= 0) continue
    const key = pair.slice(0, i).trim()
    const value = pair.slice(i + 1).trim()
    if (!value || !isPropertyKey(key)) continue
    const list = (out[key] ??= [])
    if (!list.includes(value)) list.push(value)
  }
  return Object.keys(out).length > 0 ? out : undefined
}

function serializePropertiesParam(p: Record<string, string[]> | undefined): string | undefined {
  if (!p) return undefined
  const parts: string[] = []
  for (const key of Object.keys(p).sort()) {
    for (const v of p[key] ?? []) parts.push(`${key}:${v}`)
  }
  return parts.length > 0 ? parts.join(',') : undefined
}

/** The filter with one attribute value toggled (a key with no value left is removed). */
export function togglePropertyFilter(
  f: InventoryFilters,
  key: string,
  value: string
): InventoryFilters {
  const current = { ...(f.propertiesFilter ?? {}) }
  const values = current[key] ?? []
  const next = values.includes(value) ? values.filter((v) => v !== value) : [...values, value]
  if (next.length > 0) current[key] = next
  else delete current[key]
  return {
    ...f,
    propertiesFilter: Object.keys(current).length > 0 ? current : undefined,
    page: 1,
  }
}

/**
 * Attribution values the inventory offers (RFC-036). With none selected the
 * inventory shows only assets that are the organisation's: confirmed
 * (including assets with no attribution record), dependency and monitor only
 * (the API alias `approved`). Names awaiting review and rejected names are
 * hidden until asked for.
 */
export const ATTRIBUTION_FILTER_VALUES = [
  'confirmed',
  'unknown',
  'needs_review',
  'candidate',
  'dependency',
  'monitor_only',
  'rejected',
] as const

/** What the inventory asks the API for when no attribution is selected. */
export const DEFAULT_ATTRIBUTION = ['approved']

/** The attribution query for the current filters. */
export function attributionQuery(f: InventoryFilters): string[] {
  return f.attribution?.length ? f.attribution : DEFAULT_ATTRIBUTION
}

/** Same default as the other server-paginated lists (Findings). */
export const DEFAULT_PAGE_SIZE = 20

/** True when no filter (other than pagination/sort) is active. */
export function isInventoryFilterEmpty(f: InventoryFilters): boolean {
  const arraysEmpty = (Object.keys(ARRAY_PARAMS) as ArrayKey[]).every(
    (k) => !(f[k] as string[] | undefined)?.length
  )
  const boolsEmpty = (Object.keys(BOOL_PARAMS) as BoolKey[]).every((k) => f[k] === undefined)
  return (
    arraysEmpty &&
    boolsEmpty &&
    !f.search &&
    !f.subType &&
    !f.lens &&
    f.minRiskScore === undefined &&
    !f.propertiesFilter &&
    !f.lastSeenBefore &&
    !f.lastSeenAfter &&
    !f.expiresBefore &&
    !f.expiresAfter
  )
}

/** Count of active filter dimensions (for the "N filters" affordance). */
export function countActiveFilters(f: InventoryFilters): number {
  let n = 0
  for (const k of Object.keys(ARRAY_PARAMS) as ArrayKey[]) {
    n += (f[k] as string[] | undefined)?.length ?? 0
  }
  for (const k of Object.keys(BOOL_PARAMS) as BoolKey[]) {
    if (f[k] !== undefined) n += 1
  }
  if (f.search) n += 1
  if (f.subType) n += 1
  if (f.lens) n += 1
  if (f.minRiskScore !== undefined) n += 1
  for (const values of Object.values(f.propertiesFilter ?? {})) n += values.length
  if (f.lastSeenBefore || f.lastSeenAfter) n += 1
  if (f.expiresBefore || f.expiresAfter) n += 1
  return n
}

/**
 * Inventory table column id → API sort field (asset AllowedSortFields). A
 * column absent here is not sortable. The URL keeps the API form ("-risk_score"),
 * so links made before the columns were renamed still sort the same way.
 */
export const SORT_FIELDS: Record<string, string> = {
  name: 'name',
  type: 'type',
  criticality: 'criticality',
  exposure: 'exposure',
  risk: 'risk_score',
  findings: 'finding_count',
  last_seen: 'last_seen',
}

/** URL sort ("-risk_score") → table sorting state. Unknown fields are ignored. */
export function sortToSorting(sort?: string): SortingState {
  if (!sort) return []
  const desc = sort.startsWith('-')
  const field = desc ? sort.slice(1) : sort
  const id = Object.keys(SORT_FIELDS).find((k) => SORT_FIELDS[k] === field)
  return id ? [{ id, desc }] : []
}

/** Table sorting state → URL sort, or undefined when unsorted / not sortable. */
export function sortingToSort(sorting: SortingState): string | undefined {
  const first = sorting[0]
  const field = first ? SORT_FIELDS[first.id] : undefined
  if (!first || !field) return undefined
  return first.desc ? `-${field}` : field
}

// Re-exported so consumers building typed multi-selects don't re-derive them.
export type { AssetType, Criticality, ExposureLevel, AssetScope }
