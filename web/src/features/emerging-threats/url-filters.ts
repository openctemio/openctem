/**
 * The emerging-threat list's filters in the page URL, so a view can be linked
 * to (a dashboard level opens `/emerging-threats?level=immediate&state=open`)
 * and survives a reload. The parameter names are the list API's own (`level`,
 * `state`, `tier`, `exposure=internet`, `search`, `page`, `per_page`), so the
 * address bar and the request agree. A value the API would refuse (an unknown
 * level, a page that is not a positive number) falls back to the default, and
 * a default value is left out of the URL.
 */

import { DEFAULT_PER_PAGE } from './api'
import {
  LEVELS,
  STATE_FILTERS,
  type AlertLevel,
  type AlertTier,
  type ListFilters,
  type StateFilter,
} from './types'

export const DEFAULT_STATE: StateFilter = 'open'
const MAX_PER_PAGE = 100
const TIERS: AlertTier[] = ['confirmed', 'possible']
const KEYS = ['level', 'state', 'tier', 'exposure', 'search', 'page', 'per_page'] as const
const DIGITS = /^\d+$/

/** Every filter of the list, defaults filled in. */
export type ListQuery = Required<Omit<ListFilters, 'level' | 'tier'>> &
  Pick<ListFilters, 'level' | 'tier'>

function positive(raw: string | null, max: number, fallback: number): number {
  if (!raw || !DIGITS.test(raw)) return fallback
  const n = Number(raw)
  return n >= 1 && n <= max ? n : fallback
}

/** The list filters a URL query carries. */
export function parseListQuery(params: URLSearchParams): ListQuery {
  const level = params.get('level') as AlertLevel | null
  const state = params.get('state') as StateFilter | null
  const tier = params.get('tier') as AlertTier | null
  return {
    level: level && LEVELS.includes(level) ? level : undefined,
    state: state && STATE_FILTERS.includes(state) ? state : DEFAULT_STATE,
    tier: tier && TIERS.includes(tier) ? tier : undefined,
    internetOnly: params.get('exposure') === 'internet',
    search: params.get('search') ?? '',
    page: positive(params.get('page'), Number.MAX_SAFE_INTEGER, 1),
    perPage: positive(params.get('per_page'), MAX_PER_PAGE, DEFAULT_PER_PAGE),
  }
}

/**
 * `base` with the list's parameters replaced by `q` (other parameters are
 * kept); default values are left out.
 */
export function writeListQuery(base: URLSearchParams, q: ListQuery): URLSearchParams {
  const next = new URLSearchParams(base)
  for (const k of KEYS) next.delete(k)
  if (q.level) next.set('level', q.level)
  if (q.state !== DEFAULT_STATE) next.set('state', q.state)
  if (q.tier) next.set('tier', q.tier)
  if (q.internetOnly) next.set('exposure', 'internet')
  if (q.search) next.set('search', q.search)
  if (q.page > 1) next.set('page', String(q.page))
  if (q.perPage !== DEFAULT_PER_PAGE) next.set('per_page', String(q.perPage))
  return next
}
