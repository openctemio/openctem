'use client'

import { get } from './client'

interface PagedResponse<T> {
  data?: T[]
  total_pages?: number
}

/**
 * Walk every page of a paginated list endpoint and return the concatenated
 * `data` rows. Used by "Export" actions so a CSV covers the whole filtered
 * dataset rather than only the page currently rendered.
 *
 * `buildUrl(page, perPage)` produces the request URL for a given page — pass the
 * list's current filters so the export honors them. Pages at `perPage` (default
 * 100, the common API maximum) with a hard `maxPages` cap to avoid a runaway
 * loop on an unexpected `total_pages`.
 */
export async function fetchAllPages<T>(
  buildUrl: (page: number, perPage: number) => string,
  opts?: {
    perPage?: number
    maxPages?: number
    /** Called when the maxPages cap truncated the result (loaded rows, cap rows). */
    onTruncated?: (loaded: number, cap: number) => void
  }
): Promise<T[]> {
  const perPage = opts?.perPage ?? 100
  const maxPages = opts?.maxPages ?? 500
  const all: T[] = []
  let page = 1
  let hasMore = true

  while (hasMore && page <= maxPages) {
    const resp = await get<PagedResponse<T>>(buildUrl(page, perPage))
    if (resp?.data?.length) {
      all.push(...resp.data)
    }
    hasMore = page < (resp?.total_pages ?? 1)
    page++
  }

  // Stopped at the cap with pages still remaining → the export is incomplete.
  if (hasMore) {
    opts?.onTruncated?.(all.length, maxPages * perPage)
  }

  return all
}

/** The most rows a register view loads; past it the page says it shows the first N of M. */
export const REGISTER_ROW_CAP = 1000

export interface AllPages<T> {
  data: T[]
  /** Rows the API reports in total, which may exceed `data.length` when capped. */
  total: number
}

/**
 * Load a list endpoint in full, page by page, up to `cap` rows, for registers
 * whose counts and pickers must match the list. `firstPageUrl` is the page-1
 * URL including `per_page`; `page=N` is appended for the rest. Stops when the
 * rows reach the API's `total`, on an empty page, or at the cap.
 */
export async function fetchRegisterPages<T>(
  firstPageUrl: string,
  cap: number = REGISTER_ROW_CAP
): Promise<AllPages<T>> {
  const sep = firstPageUrl.includes('?') ? '&' : '?'
  const rows: T[] = []
  let total = 0
  for (let page = 1; rows.length < cap; page++) {
    const url = page === 1 ? firstPageUrl : `${firstPageUrl}${sep}page=${page}`
    const resp = await get<{ data?: T[]; total?: number }>(url)
    const batch = resp?.data ?? []
    total = resp?.total ?? Math.max(total, rows.length + batch.length)
    rows.push(...batch)
    if (batch.length === 0 || rows.length >= total) break
  }
  return { data: rows.slice(0, cap), total }
}
