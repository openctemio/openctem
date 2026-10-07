'use client'

import { useCallback, useMemo } from 'react'
import type { SortingState } from '@tanstack/react-table'
import { replaceUrlSearch, useUrlParams } from './use-url-param'

/**
 * The URL state of one server-paged list: `page` (1-based), `per_page`, `sort`,
 * `q` and the list's own field-named filters. One convention for every list
 * page (owner decision 2026-10-07, research/60 PR-5):
 *
 * - plain names, never prefixed (page, not run_page): a route shows one
 *   list, and an embedded list in a detail page keeps local state instead;
 * - `per_page` is snapped to the offered sizes and `sort` to the allowed
 *   fields, so a hand-edited or stale link falls back to the default view and
 *   nothing the API would refuse is sent;
 * - a filter, search or page-size change returns to page 1;
 * - a value equal to its default is left out of the URL.
 *
 * The names match the API list contract (`page`, `per_page`, `sort=-field`,
 * `q`), so `apiParams` goes to the request as it is.
 */
export interface ListParamsOptions<F extends string> {
  /** Offered page sizes; the first entry is not implied, see defaultPageSize. */
  pageSizes?: readonly number[]
  defaultPageSize?: number
  /** Sortable fields (without `-`). Leave out for a list with no server sort. */
  sortFields?: readonly string[]
  /** Default sort, `field` or `-field`. */
  defaultSort?: string
  /** The list's filters and their default values ('' = no filter). */
  filters?: Record<F, string>
}

export interface ListParams<F extends string> {
  page: number
  perPage: number
  sort: string
  q: string
  filters: Record<F, string>
  /** 0-based table pagination for DataTable's manual pagination. */
  pagination: { pageIndex: number; pageSize: number }
  setPagination: (next: { pageIndex: number; pageSize: number }) => void
  sorting: SortingState
  setSorting: (next: SortingState) => void
  setPage: (page: number) => void
  setSearch: (q: string) => void
  setFilter: (name: F, value: string) => void
  /** Clear search and filters (back to page 1). */
  reset: () => void
  /** The query for the list request: only non-default values. */
  apiParams: Record<string, string | number>
}

export const DEFAULT_PAGE_SIZES = [10, 20, 50, 100] as const

const DIGITS = /^\d+$/

/** A sort value (`field` / `-field`) when `field` is allowed, else null. */
export function parseListSort(raw: string | null, allowed: readonly string[]): string | null {
  const value = (raw ?? '').trim()
  if (!value || value.includes(',')) return null
  const field = value.startsWith('-') ? value.slice(1) : value
  return allowed.includes(field) ? value : null
}

export function useListParams<F extends string = never>(
  options: ListParamsOptions<F> = {}
): ListParams<F> {
  const {
    pageSizes = DEFAULT_PAGE_SIZES,
    defaultPageSize = 20,
    sortFields,
    defaultSort = '',
    filters: filterDefaults = {} as Record<F, string>,
  } = options
  const params = useUrlParams()

  const rawPage = params.get('page')
  const page = rawPage && DIGITS.test(rawPage) && Number(rawPage) > 0 ? Number(rawPage) : 1
  const rawSize = Number(params.get('per_page'))
  const perPage = pageSizes.includes(rawSize) ? rawSize : defaultPageSize
  const sort = (sortFields && parseListSort(params.get('sort'), sortFields)) || defaultSort
  const q = params.get('q') ?? ''

  // filterDefaults is a new object each render: key the memos on its value.
  const filterKey = JSON.stringify(filterDefaults)
  const defaults = useMemo(() => JSON.parse(filterKey) as Record<F, string>, [filterKey])
  const filters = useMemo(() => {
    const out = {} as Record<F, string>
    for (const name of Object.keys(defaults) as F[]) {
      out[name] = params.get(name) ?? defaults[name]
    }
    return out
  }, [params, defaults])

  /** Write several keys at once; a default (or empty) value is removed. */
  const write = useCallback(
    (changes: Record<string, string | number | null>) => {
      const next = new URLSearchParams(window.location.search)
      const keyDefaults: Record<string, string> = {
        page: '1',
        per_page: String(defaultPageSize),
        sort: defaultSort,
        q: '',
        ...defaults,
      }
      for (const [key, value] of Object.entries(changes)) {
        const v = value === null ? '' : String(value)
        if (v === '' || v === keyDefaults[key]) next.delete(key)
        else next.set(key, v)
      }
      replaceUrlSearch(next)
    },
    [defaultPageSize, defaultSort, defaults]
  )

  const setPage = useCallback((p: number) => write({ page: p }), [write])
  const setPagination = useCallback(
    (next: { pageIndex: number; pageSize: number }) =>
      next.pageSize !== perPage
        ? write({ per_page: next.pageSize, page: 1 })
        : write({ page: next.pageIndex + 1 }),
    [write, perPage]
  )
  // Stored as typed (a search box must keep the space being typed); the
  // request gets it trimmed.
  const setSearch = useCallback((value: string) => write({ q: value, page: 1 }), [write])
  const setFilter = useCallback(
    (name: F, value: string) => write({ [name]: value, page: 1 }),
    [write]
  )
  const reset = useCallback(() => {
    const cleared: Record<string, null> = { q: null, page: null }
    for (const name of Object.keys(defaults)) cleared[name] = null
    write(cleared)
  }, [write, defaults])

  const sorting = useMemo<SortingState>(() => {
    if (!sort) return []
    return [{ id: sort.replace(/^-/, ''), desc: sort.startsWith('-') }]
  }, [sort])
  const setSorting = useCallback(
    (next: SortingState) => {
      const first = next[0]
      const value =
        first && sortFields?.includes(first.id)
          ? `${first.desc ? '-' : ''}${first.id}`
          : defaultSort
      write({ sort: value, page: 1 })
    },
    [write, sortFields, defaultSort]
  )

  const apiParams = useMemo(() => {
    const out: Record<string, string | number> = { page, per_page: perPage }
    if (sort) out.sort = sort
    if (q.trim()) out.q = q.trim()
    for (const [name, value] of Object.entries(filters) as [F, string][]) {
      if (value && value !== defaults[name]) out[name] = value
    }
    return out
  }, [page, perPage, sort, q, filters, defaults])

  return {
    page,
    perPage,
    sort,
    q,
    filters,
    pagination: { pageIndex: page - 1, pageSize: perPage },
    setPagination,
    sorting,
    setSorting,
    setPage,
    setSearch,
    setFilter,
    reset,
    apiParams,
  }
}
