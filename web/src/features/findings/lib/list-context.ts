/**
 * The list a finding was opened from (research/236 D2, research/234 C7): the
 * findings page records the query and the ordered ids of the page it shows,
 * so the finding page can say "Findings, Open P0 and P1, 3 of 31" and step
 * to the previous or next finding of the same list.
 *
 * Like triage mode's queue, the context is a query, never a set of rows the
 * client chose: the ids came from list reads, more are read through the same
 * list API (the server applies the caller's tenant and data scope each
 * time), and the finding page itself is read and authorized by id. The tab
 * keeps it in sessionStorage. Pure helpers, unit-tested on their own.
 */

import { safeReturnPath } from './triage-session'

const STORAGE_KEY = 'openctem.findings.listContext'
const ID_RE = /^[0-9a-f-]{8,64}$/i
const PARAM_RE = /^[a-z][a-z0-9_]{0,63}$/
const PAGING_PARAMS = new Set(['page', 'per_page', 'cursor'])
/** The most ids one context keeps (a few pages around the one opened). */
export const LIST_CONTEXT_MAX_IDS = 500
const MAX_LABEL = 120

export interface FindingListContext {
  /** The list API query: filter and sort params, no paging. */
  query: string
  /** What the list is called ("Open P0 and P1", a saved view, "Filtered list"). */
  label: string
  /** The list page to go back to (only /findings with its query). */
  returnPath: string
  /** Ordered ids known so far. */
  ids: string[]
  /** Position of ids[0] in the whole list (0-based). */
  offset: number
  /** The list's page size, used to read neighbouring pages. */
  perPage: number
  /** Findings in the whole list. */
  total: number
}

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>

function storage(): StorageLike | null {
  try {
    return typeof window === 'undefined' ? null : window.sessionStorage
  } catch {
    return null
  }
}

/** The list API query of a list URL or endpoint: filters and sort, never paging. */
export function listQuery(search: string | URLSearchParams): string {
  const raw = typeof search === 'string' ? search.slice(search.indexOf('?') + 1) : search
  const src = typeof raw === 'string' ? new URLSearchParams(raw) : raw
  const out = new URLSearchParams()
  for (const [k, v] of src.entries()) {
    if (PAGING_PARAMS.has(k) || !PARAM_RE.test(k) || v === '' || v.length > 2000) continue
    out.append(k, v)
  }
  return out.toString()
}

function int(v: unknown, min: number, max: number): number | null {
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : null
}

/** Validates stored or caller data; anything malformed is no context. */
export function parseListContext(raw: unknown): FindingListContext | null {
  let v: unknown = raw
  if (typeof raw === 'string') {
    try {
      v = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (!v || typeof v !== 'object') return null
  const o = v as Record<string, unknown>
  const ids = Array.isArray(o.ids)
    ? o.ids.filter((x): x is string => typeof x === 'string' && ID_RE.test(x))
    : []
  const offset = int(o.offset, 0, 1_000_000)
  const perPage = int(o.perPage, 1, 200)
  const total = int(o.total, 0, 100_000_000)
  if (ids.length === 0 || offset === null || perPage === null || total === null) return null
  return {
    query: listQuery(typeof o.query === 'string' ? o.query : ''),
    label: typeof o.label === 'string' ? o.label.slice(0, MAX_LABEL) : '',
    returnPath: safeReturnPath(o.returnPath),
    ids: [...new Set(ids)].slice(0, LIST_CONTEXT_MAX_IDS),
    offset,
    perPage,
    total: Math.max(total, offset + ids.length),
  }
}

export function readListContext(store: StorageLike | null = storage()): FindingListContext | null {
  try {
    return parseListContext(store?.getItem(STORAGE_KEY) ?? null)
  } catch {
    return null
  }
}

export function writeListContext(
  c: FindingListContext,
  store: StorageLike | null = storage()
): void {
  const parsed = parseListContext(c)
  if (!parsed) return
  try {
    store?.setItem(STORAGE_KEY, JSON.stringify(parsed))
  } catch {
    // Storage blocked: the finding page simply shows no list context.
  }
}

export interface ListPosition {
  /** 0-based position in the whole list. */
  index: number
  prevId?: string
  nextId?: string
  /** The previous finding exists but is not loaded: read this page (1-based). */
  loadPage?: { before?: number; after?: number }
}

/** Where a finding sits in its list context; null when it is not in it. */
export function locate(c: FindingListContext, id: string): ListPosition | null {
  const i = c.ids.indexOf(id)
  if (i < 0) return null
  const index = c.offset + i
  const pos: ListPosition = { index, prevId: c.ids[i - 1], nextId: c.ids[i + 1] }
  const loadPage: ListPosition['loadPage'] = {}
  if (!pos.prevId && index > 0) loadPage.before = Math.floor((index - 1) / c.perPage) + 1
  if (!pos.nextId && index + 1 < c.total) loadPage.after = Math.floor((index + 1) / c.perPage) + 1
  if (loadPage.before || loadPage.after) pos.loadPage = loadPage
  return pos
}

/**
 * Adds one page of ids (1-based page, the context's page size) when it sits
 * right before or after the known ids; anything else (an overlapping or
 * distant page, after the list changed) leaves the context as it was.
 */
export function mergePage(
  c: FindingListContext,
  page: number,
  pageIds: string[],
  total: number
): FindingListContext {
  const start = (page - 1) * c.perPage
  const ids = pageIds.filter((x) => ID_RE.test(x))
  if (ids.length === 0) return c
  const end = c.offset + c.ids.length
  let next: FindingListContext | null = null
  if (start === end) next = { ...c, ids: [...c.ids, ...ids] }
  else if (start + ids.length === c.offset) next = { ...c, ids: [...ids, ...c.ids], offset: start }
  if (!next) return c
  const seen = new Set<string>()
  next.ids = next.ids.filter((x) => (seen.has(x) ? false : (seen.add(x), true)))
  if (next.ids.length > LIST_CONTEXT_MAX_IDS) {
    // Keep the end the person is moving towards.
    if (start === end) {
      const drop = next.ids.length - LIST_CONTEXT_MAX_IDS
      next.ids = next.ids.slice(drop)
      next.offset += drop
    } else next.ids = next.ids.slice(0, LIST_CONTEXT_MAX_IDS)
  }
  next.total = Math.max(total, next.offset + next.ids.length)
  return next
}
