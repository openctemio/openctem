'use client'

import { useCallback, useMemo } from 'react'
import { useUrlFilter } from './use-url-param'

export interface TablePagination {
  pageIndex: number
  pageSize: number
}

/**
 * Server-side table paging kept in the URL (`?page=` 1-based, `?per_page=`),
 * so a page of a list can be linked and survives a reload.
 *
 * Returns the table's 0-based `pagination` state, a setter for DataTable's
 * `onPaginationChange`, and `offset`/`limit` for APIs that page by offset.
 * Lists that loaded one capped page and paged it in the browser silently hid
 * everything past the cap (23a B20); use this with `manualPagination` instead.
 */
export function useUrlPagination(
  pageSizes: readonly number[] = [10, 20, 50, 100],
  defaultPageSize = 20
) {
  const [pageParam, setPageParam] = useUrlFilter('page', '1')
  const [perPageParam, setPerPageParam] = useUrlFilter('per_page', String(defaultPageSize))

  const pagination = useMemo<TablePagination>(() => {
    const size = parseInt(perPageParam, 10)
    return {
      pageIndex: Math.max(0, (parseInt(pageParam, 10) || 1) - 1),
      pageSize: pageSizes.includes(size) ? size : defaultPageSize,
    }
  }, [pageParam, perPageParam, pageSizes, defaultPageSize])

  const setPagination = useCallback(
    (next: TablePagination) => {
      setPageParam(String(next.pageIndex + 1))
      setPerPageParam(String(next.pageSize))
    },
    [setPageParam, setPerPageParam]
  )

  /** Back to the first page (call when a filter or the search changes). */
  const resetPage = useCallback(() => setPageParam('1'), [setPageParam])

  return {
    pagination,
    setPagination,
    resetPage,
    offset: pagination.pageIndex * pagination.pageSize,
    limit: pagination.pageSize,
  }
}
