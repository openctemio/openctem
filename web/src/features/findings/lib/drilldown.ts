import type { GroupByDimension } from '../api/use-finding-groups'

/**
 * Drill-down from a findings group to the list (research 24 P0-1).
 *
 * A group row's "View" is a NEW destination, not a refinement: it is pushed
 * onto the browser history, so Back returns to the grouped view with its
 * filters. Every other filter in the URL is kept; the group's own filter is
 * added; `from=group:<dimension>` records where the user came from, so the
 * breadcrumb can be rebuilt from the URL alone (no session state, a shared
 * link shows the same trail).
 *
 * Every one of the nine group dimensions maps to a list filter of the
 * findings registry, so "View" exists on all of them (never a dead button):
 * owner rows use `asset_owner_id` (the asset's primary owner, the grouping's
 * own rule), and the "Unassigned" owner row uses `asset_owner_id_null=true`.
 */

/** The `from` value of a drill-down URL. */
export const DRILL_FROM_PREFIX = 'group:'

/** The group key the API uses for findings whose asset has no primary owner. */
export const UNASSIGNED_OWNER_KEY = 'unassigned'

/** The list URL parameter each group dimension drills into. */
export const DRILL_PARAM: Record<GroupByDimension, string> = {
  cve_id: 'cve_id',
  rule_id: 'rule_id',
  asset_id: 'asset_id',
  owner_id: 'asset_owner_id',
  severity: 'severity',
  source: 'source',
  component_id: 'component_id',
  finding_type: 'finding_type',
  family: 'family',
}

/** Parameters that describe the page, not the filter; dropped on drill-down. */
const PAGE_PARAMS = ['group', 'page', 'from']

/**
 * The search of the list a group drills into: the current filters, minus the
 * grouping and the page, plus the group's filter and `from`.
 */
export function buildDrillDownSearch(
  current: URLSearchParams,
  groupBy: GroupByDimension,
  groupKey: string
): URLSearchParams {
  const next = new URLSearchParams(current)
  for (const p of PAGE_PARAMS) next.delete(p)
  if (groupBy === 'owner_id' && groupKey === UNASSIGNED_OWNER_KEY) {
    next.delete('asset_owner_id')
    next.set('asset_owner_id_null', 'true')
  } else {
    if (groupBy === 'owner_id') next.delete('asset_owner_id_null')
    // A multi-value filter (severity, source) narrows to this one value.
    next.set(DRILL_PARAM[groupBy], groupKey)
  }
  next.set('from', DRILL_FROM_PREFIX + groupBy)
  return next
}

/** The group dimension a drilled list came from, or null. */
export function drillOrigin(
  params: URLSearchParams,
  dimensions: readonly GroupByDimension[]
): GroupByDimension | null {
  const from = params.get('from') ?? ''
  if (!from.startsWith(DRILL_FROM_PREFIX)) return null
  const dim = from.slice(DRILL_FROM_PREFIX.length) as GroupByDimension
  if (!dimensions.includes(dim)) return null
  // Only while the drilled filter is still on: removing its chip ends the
  // drill-down, and the breadcrumb goes with it.
  const param = DRILL_PARAM[dim]
  const on =
    dim === 'owner_id' ? params.has(param) || params.has('asset_owner_id_null') : params.has(param)
  return on ? dim : null
}

/** The drilled value shown in the breadcrumb (the raw key; callers escape it). */
export function drillValue(params: URLSearchParams, dim: GroupByDimension): string {
  if (dim === 'owner_id' && params.get('asset_owner_id_null') === 'true') return 'Unassigned'
  return params.get(DRILL_PARAM[dim]) ?? ''
}

/**
 * The search of the grouped view a drilled list came from: the same filters,
 * minus the drilled one and `from`, grouped by the origin dimension again.
 */
export function buildGroupedSearch(
  params: URLSearchParams,
  dim: GroupByDimension
): URLSearchParams {
  const next = new URLSearchParams(params)
  next.delete(DRILL_PARAM[dim])
  if (dim === 'owner_id') next.delete('asset_owner_id_null')
  next.delete('from')
  next.delete('page')
  next.set('group', dim)
  return next
}

/**
 * Remove one filter parameter (a chip's ✕): only that parameter goes, every
 * other filter stays. When it is the drilled filter, `from` goes with it.
 */
export function removeFilterParam(params: URLSearchParams, param: string): URLSearchParams {
  const next = new URLSearchParams(params)
  next.delete(param)
  next.delete('page')
  const from = next.get('from') ?? ''
  if (from.startsWith(DRILL_FROM_PREFIX)) {
    const dim = from.slice(DRILL_FROM_PREFIX.length) as GroupByDimension
    const drilled = DRILL_PARAM[dim]
    if (drilled === param || (dim === 'owner_id' && param === 'asset_owner_id_null')) {
      next.delete('from')
    }
  }
  return next
}
