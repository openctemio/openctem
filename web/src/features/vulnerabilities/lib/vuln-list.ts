/**
 * The vulnerabilities list's URL model (api/docs/architecture/vulnerability-page.md,
 * "The list"). The page URL uses the API's own params, so a view is a link
 * and the request is a reading of the address bar: only the params below are
 * forwarded, each checked against its shape, so a stray or hand-edited param
 * never turns the list into a 400.
 */

import type { SortingState } from '@tanstack/react-table'
import { SEVERITY_LEVELS } from '@/lib/severity'
import type { VulnListItem } from '../types/list'

export const VULN_LIST_PAGE_SIZES = [25, 50, 100]
export const VULN_LIST_DEFAULT_PER_PAGE = 25

/** The findings lens: Open by default, as on the findings list. */
export const VULN_LIST_STATES = ['open', 'fixed', 'dispositioned', 'all'] as const
export type VulnListState = (typeof VULN_LIST_STATES)[number]
export const VULN_LIST_DEFAULT_STATE: VulnListState = 'open'

export const VULN_LIST_SEVERITIES = SEVERITY_LEVELS
export const VULN_LIST_PRIORITIES = ['P0', 'P1', 'P2', 'P3'] as const
export const VULN_LIST_SOURCES = [
  'sca',
  'va',
  'dast',
  'easm',
  'container',
  'sast',
  'pentest',
] as const
/** EPSS thresholds offered by the facet (probability of exploitation in 30 days). */
export const VULN_LIST_EPSS = ['0.01', '0.1', '0.5'] as const

/** Sort keys the API takes; a leading "-" flips the natural direction. */
export const VULN_LIST_SORTS = [
  'risk',
  'epss',
  'cvss',
  'assets',
  'findings',
  'kev_due',
  'last_seen',
  'first_seen',
  'cve',
] as const
export type VulnListSortKey = (typeof VULN_LIST_SORTS)[number]

/** Keys whose natural direction is descending (largest or newest first). */
const NATURAL_DESC: ReadonlySet<string> = new Set([
  'epss',
  'cvss',
  'assets',
  'findings',
  'last_seen',
  'first_seen',
])

/** The boolean filters, as the API names them. */
export const VULN_LIST_FLAGS = ['kev', 'exploit', 'emerging', 'past_sla', 'has_fix'] as const
export type VulnListFlag = (typeof VULN_LIST_FLAGS)[number]

const LIST_PARAMS = ['severity', 'priority_class', 'source', 'asset_group_id', 'cve_id'] as const
/** A CVE id, the key of a row (and of a bulk selection). */
export const CVE_ID = /^CVE-\d{4}-\d{4,19}$/
/** The most rows one bulk action takes (the API's cap). */
export const VULN_SELECTION_MAX = 100
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MAX_SEARCH = 200

function allowedList(key: (typeof LIST_PARAMS)[number], raw: string | null): string[] {
  const values = (raw ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
  switch (key) {
    case 'severity':
      return values.filter((v) => (VULN_LIST_SEVERITIES as readonly string[]).includes(v))
    case 'priority_class':
      return values.filter((v) => (VULN_LIST_PRIORITIES as readonly string[]).includes(v))
    case 'source':
      return values.filter((v) => (VULN_LIST_SOURCES as readonly string[]).includes(v))
    case 'asset_group_id':
      return values.filter((v) => UUID.test(v)).slice(0, 20)
    case 'cve_id':
      return values
        .map((v) => v.toUpperCase())
        .filter((v) => CVE_ID.test(v))
        .slice(0, VULN_SELECTION_MAX)
  }
}

/** The list param's values, cleaned (unknown values dropped). */
export function readList(params: URLSearchParams, key: (typeof LIST_PARAMS)[number]): string[] {
  return allowedList(key, params.get(key))
}

export function readState(params: URLSearchParams): VulnListState {
  const raw = params.get('state')
  return (VULN_LIST_STATES as readonly string[]).includes(raw ?? '')
    ? (raw as VulnListState)
    : VULN_LIST_DEFAULT_STATE
}

export function readFlag(params: URLSearchParams, flag: VulnListFlag): boolean | undefined {
  const raw = params.get(flag)
  return raw === 'true' ? true : raw === 'false' ? false : undefined
}

export function readEpss(params: URLSearchParams): string | undefined {
  const raw = params.get('epss_gte')
  return (VULN_LIST_EPSS as readonly string[]).includes(raw ?? '') ? (raw as string) : undefined
}

export interface VulnListSort {
  key: VulnListSortKey
  flipped: boolean
}

export function readSort(params: URLSearchParams): VulnListSort {
  const raw = (params.get('sort') ?? '').trim()
  const flipped = raw.startsWith('-')
  const key = raw.replace(/^-/, '')
  if ((VULN_LIST_SORTS as readonly string[]).includes(key)) {
    return { key: key as VulnListSortKey, flipped: flipped && key !== 'risk' }
  }
  return { key: 'risk', flipped: false }
}

export function readPage(params: URLSearchParams): { page: number; perPage: number } {
  const page = Math.min(10000, Math.max(1, parseInt(params.get('page') ?? '1', 10) || 1))
  const per = parseInt(params.get('per_page') ?? '', 10)
  return {
    page,
    perPage: VULN_LIST_PAGE_SIZES.includes(per) ? per : VULN_LIST_DEFAULT_PER_PAGE,
  }
}

export function readSearch(params: URLSearchParams): string {
  return (params.get('q') ?? '').trim().slice(0, MAX_SEARCH)
}

/** The API query for the page URL: only known params, each in its shape. */
export function buildVulnListQuery(params: URLSearchParams): URLSearchParams {
  const out = new URLSearchParams()
  const view = readViewId(params)
  if (view) {
    // A saved view is the base the API applies; only what the URL sets
    // overrides it, so its own lens stays unless the URL names one.
    out.set('view', view)
    if (params.has('state')) out.set('state', readState(params))
  } else {
    out.set('state', readState(params))
  }
  for (const key of LIST_PARAMS) {
    const values = readList(params, key)
    if (values.length) out.set(key, values.join(','))
  }
  for (const flag of VULN_LIST_FLAGS) {
    const v = readFlag(params, flag)
    if (v !== undefined) out.set(flag, String(v))
  }
  const epss = readEpss(params)
  if (epss) out.set('epss_gte', epss)
  const q = readSearch(params)
  if (q) out.set('q', q)
  const sort = readSort(params)
  if (sort.key !== 'risk') out.set('sort', `${sort.flipped ? '-' : ''}${sort.key}`)
  const { page, perPage } = readPage(params)
  out.set('page', String(page))
  out.set('per_page', String(perPage))
  return out
}

/** The saved view the URL opens (`view=<id>`), if any. */
export function readViewId(params: URLSearchParams): string | undefined {
  const raw = params.get('view')
  return raw && UUID.test(raw) ? raw : undefined
}

/**
 * The list's query for a bulk action or an export: its filters and saved
 * view without paging. The API resolves the findings from it as the
 * signed-in person; it never carries a tenant or a scope.
 */
export function vulnActionParams(params: URLSearchParams): URLSearchParams {
  const out = buildVulnListQuery(params)
  out.delete('page')
  out.delete('per_page')
  return out
}

/** How many filters are on (facets and flags; search, sort and lens not counted). */
export function activeFilterCount(params: URLSearchParams): number {
  let n = 0
  for (const key of LIST_PARAMS) n += readList(params, key).length
  for (const flag of VULN_LIST_FLAGS) if (readFlag(params, flag) !== undefined) n++
  if (readEpss(params)) n++
  return n
}

/** The table's sort state for the URL sort (risk has no column: empty). */
export function sortToSorting(sort: VulnListSort): SortingState {
  if (sort.key === 'risk') return []
  const desc = NATURAL_DESC.has(sort.key) !== sort.flipped
  return [{ id: sort.key, desc }]
}

/** The URL sort for a table sort change; no column means the risk order. */
export function sortingToSort(sorting: SortingState): string {
  const s = sorting[0]
  if (!s || !(VULN_LIST_SORTS as readonly string[]).includes(s.id) || s.id === 'risk') return ''
  const flipped = NATURAL_DESC.has(s.id) !== s.desc
  return `${flipped ? '-' : ''}${s.id}`
}

const DAY = 24 * 60 * 60 * 1000

/** Days to a KEV due date (negative when past due), or undefined. */
export function kevDueDays(due: string | undefined, now: number = Date.now()): number | undefined {
  if (!due) return undefined
  const t = Date.parse(due)
  if (Number.isNaN(t)) return undefined
  return Math.floor((t - now) / DAY)
}

export type RemediationState = 'closed' | 'untracked' | 'partial' | 'tracked'

/** How much of the open work is already in a remediation task. */
export function remediationState(
  item: Pick<VulnListItem, 'open_findings' | 'in_task'>
): RemediationState {
  if (item.open_findings === 0) return 'closed'
  if (item.in_task === 0) return 'untracked'
  return item.in_task >= item.open_findings ? 'tracked' : 'partial'
}

/** The fix to show: the first known fixed version. */
export function headlineFixVersion(item: Pick<VulnListItem, 'fixed_versions'>): string | undefined {
  return item.fixed_versions.find((v) => v.trim() !== '')
}

/** The findings list for a row, with the list's own filters (scope parity). */
export function rowFindingsHref(
  cve: string,
  params: URLSearchParams,
  extra: Record<string, string> = {}
): string {
  const q = new URLSearchParams({ cve_id: cve, state: readState(params) })
  for (const key of LIST_PARAMS) {
    if (key === 'cve_id') continue
    const values = readList(params, key)
    if (values.length) q.set(key, values.join(','))
  }
  for (const [k, v] of Object.entries(extra)) q.set(k, v)
  return `/findings?${q}`
}
