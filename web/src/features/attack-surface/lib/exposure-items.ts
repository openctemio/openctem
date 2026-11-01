/**
 * Attack surface > Exposure items: request URLs, the default filters and the
 * CSV of the exposure list (GET /attack-surface/exposures, the list query
 * contract). Pure, so the filters a page sends and the file it exports are
 * tested without a network. Titles, summaries and asset names are scan
 * output: text only.
 */
import { buildCsv } from '@/hooks/use-csv-export'
import {
  EXPOSURE_DISPLAY_CATEGORIES,
  type ExposureDisplayCategory,
  type ExposureEvent,
  type ExposureSeverity,
  type ExposureState,
} from '@/lib/api/exposure-types'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { isMonitoringState, type MonitoringState } from '@/features/assets/lib/monitoring-state'

export const EXPOSURE_ITEMS_URL = '/api/v1/attack-surface/exposures'

export const ITEM_SEVERITIES: readonly ExposureSeverity[] = SEVERITY_LEVELS
export const ITEM_STATES: readonly ExposureState[] = [
  'active',
  'in_progress',
  'resolved',
  'accepted',
  'false_positive',
]

/** The open states: the default view is the work still to do. */
export const OPEN_STATES: readonly ExposureState[] = ['active', 'in_progress']

/** URL value meaning "no filter" for a filter whose default is not empty. */
export const ANY = 'all'

/** The URL defaults of the page: open exposures on monitored assets. */
export const DEFAULT_STATE_PARAM = OPEN_STATES.join(',')
export const DEFAULT_MONITORING_PARAM: MonitoringState = 'monitored'

/** One row of GET /attack-surface/exposures. */
export interface ExposureItemRow extends ExposureEvent {
  /** The asset the exposure is on (absent for an exposure without one). */
  asset_id?: string
  asset_name?: string
  asset_type?: string
  asset_monitoring_state?: string
  asset_primary: boolean
}

/** GET /attack-surface/exposures/stats. */
export interface ExposureItemStats {
  total: number
  by_severity: Partial<Record<ExposureSeverity, number>>
  by_category: Partial<Record<ExposureDisplayCategory, number>>
  by_state: Partial<Record<ExposureState, number>>
}

/** One row of GET /attack-surface/exposures/assets. */
export interface ExposureAssetGroupRow {
  asset_id: string
  asset_name: string
  asset_type: string
  asset_monitoring_state: string
  asset_primary: boolean
  total: number
  by_severity: Partial<Record<ExposureSeverity, number>>
  top_severity?: ExposureSeverity
  first_seen_at: string
  last_seen_at: string
}

export interface ExposureItemFilters {
  q?: string
  severities?: ExposureSeverity[]
  /** Empty = every state. */
  states?: ExposureState[]
  categories?: ExposureDisplayCategory[]
  /** Undefined = every asset (and exposures without one). */
  monitoring?: MonitoringState
  primaryOnly?: boolean
  assetId?: string
}

function pick<T extends string>(raw: string, allowed: readonly T[]): T[] {
  if (!raw || raw === ANY) return []
  const out: T[] = []
  for (const v of raw.split(',')) {
    if ((allowed as readonly string[]).includes(v) && !out.includes(v as T)) out.push(v as T)
  }
  return out
}

const CATEGORY_KEYS = EXPOSURE_DISPLAY_CATEGORIES.map((c) => c.key)
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** The URL filter values of the page, read into typed filters (unknown values dropped). */
export function filtersFromParams(p: {
  q?: string
  severity: string
  state: string
  category: string
  monitoring: string
  primary: string
  asset: string
}): ExposureItemFilters {
  return {
    q: p.q,
    severities: pick(p.severity, ITEM_SEVERITIES),
    states: pick(p.state, ITEM_STATES),
    categories: pick(p.category, CATEGORY_KEYS),
    monitoring: isMonitoringState(p.monitoring) ? p.monitoring : undefined,
    primaryOnly: p.primary === 'true',
    assetId: UUID.test(p.asset) ? p.asset : undefined,
  }
}

export function exposureItemParams(f: ExposureItemFilters): URLSearchParams {
  const p = new URLSearchParams()
  const q = f.q?.trim()
  if (q) p.set('q', q)
  if (f.severities?.length) p.set('severity', f.severities.join(','))
  if (f.states?.length) p.set('state', f.states.join(','))
  if (f.categories?.length) p.set('category', f.categories.join(','))
  if (f.monitoring) p.set('asset_monitoring_state', f.monitoring)
  if (f.primaryOnly) p.set('primary', 'true')
  if (f.assetId) p.set('asset_id', f.assetId)
  return p
}

function withPage(p: URLSearchParams, page: { page: number; perPage: number }): string {
  p.set('page', String(page.page))
  p.set('per_page', String(page.perPage))
  return p.toString()
}

export function exposureItemsUrl(
  f: ExposureItemFilters,
  page: { page: number; perPage: number },
  sort?: string
): string {
  const p = exposureItemParams(f)
  if (sort) p.set('sort', sort)
  return `${EXPOSURE_ITEMS_URL}?${withPage(p, page)}`
}

export function exposureAssetGroupsUrl(
  f: ExposureItemFilters,
  page: { page: number; perPage: number }
): string {
  return `${EXPOSURE_ITEMS_URL}/assets?${withPage(exposureItemParams(f), page)}`
}

/**
 * The counts behind the summary strips: the same filters minus severity and
 * category, so the strips show the whole set the user narrows from.
 */
export function exposureItemStatsUrl(f: ExposureItemFilters): string {
  const p = exposureItemParams({ ...f, severities: [], categories: [] }).toString()
  return p ? `${EXPOSURE_ITEMS_URL}/stats?${p}` : `${EXPOSURE_ITEMS_URL}/stats`
}

/** Toggle one value in a list filter (add when absent, remove when present). */
export function toggleValue<T extends string>(list: readonly T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v]
}

/** The display categories to show in the by-type summary: produced ones, plus any with exposures. */
export function visibleCategories(
  counts: ExposureItemStats['by_category'] | undefined
): ExposureDisplayCategory[] {
  return EXPOSURE_DISPLAY_CATEGORIES.filter((c) => c.produced || (counts?.[c.key] ?? 0) > 0).map(
    (c) => c.key
  )
}

/** CSV of exposure rows; cells go through buildCsv (formula injection safe). */
export function exposureItemsCsv(
  rows: ExposureItemRow[],
  headers: string[],
  label: {
    category: (c: string) => string
    severity: (s: ExposureSeverity) => string
    state: (s: ExposureState) => string
    summary: (row: ExposureItemRow) => string
  }
): string {
  return buildCsv(
    headers,
    rows.map((r) => [
      r.title,
      label.summary(r),
      label.category(r.display_category ?? 'other'),
      label.severity(r.severity),
      r.severity_override ? label.severity(r.severity_override.reported_severity) : '',
      label.state(r.state),
      r.asset_name ?? '',
      r.asset_primary ? 'yes' : '',
      r.asset_monitoring_state ?? '',
      r.source,
      r.first_seen_at,
      r.last_seen_at,
    ])
  )
}
