/**
 * URL <-> list-state codec for the Scans area (research 20 §4.1).
 *
 * Page, page size and sort live in the query string next to the filters, so a
 * paged, sorted view of scans or runs can be linked and survives a reload. The
 * names follow the API (RFC-048 §3.5: `sort=-last_run_at`, `page`,
 * `per_page`); the Runs tab prefixes its own (`run_page`, ...) because both
 * tabs share one URL. Everything read from the URL is validated here: a
 * hand-edited or stale link falls back to the default view, and nothing the
 * API would refuse is ever sent.
 */

import type { SortingState } from '@tanstack/react-table'

/** Page sizes every scans list offers (style contract §3). */
export const SCAN_PAGE_SIZES = [25, 50, 100] as const
export const DEFAULT_SCAN_PAGE_SIZE = 25

/** Sortable fields of GET /scans (api pkg/domain/scan/list_sort.go). */
export const SCAN_CONFIG_SORT_FIELDS = [
  'name',
  'created_at',
  'last_run_at',
  'next_run_at',
  'total_runs',
] as const
export type ScanConfigSortField = (typeof SCAN_CONFIG_SORT_FIELDS)[number]
export const DEFAULT_SCAN_CONFIG_SORT = 'name'

/** Sortable fields of GET /scan-runs (api pkg/domain/scanrun/run_sort.go). */
export const RUN_SORT_FIELDS = [
  'created_at',
  'started_at',
  'completed_at',
  'total_findings',
] as const
export const DEFAULT_RUN_SORT = '-created_at'

/** A page size from the URL, snapped to the offered sizes. */
export function parsePageSize(value: number): number {
  return (SCAN_PAGE_SIZES as readonly number[]).includes(value) ? value : DEFAULT_SCAN_PAGE_SIZE
}

/**
 * A sort param (`field` or `-field`) → table sorting state. A field outside
 * `allowed` (or more than one key) yields the default sort.
 */
export function parseSortParam(
  raw: string | null | undefined,
  allowed: readonly string[],
  fallback: string
): SortingState {
  const pick = (value: string): SortingState | null => {
    const desc = value.startsWith('-')
    const id = desc ? value.slice(1) : value
    return allowed.includes(id) ? [{ id, desc }] : null
  }
  const value = (raw ?? '').trim()
  return (value && !value.includes(',') ? pick(value) : null) ?? pick(fallback) ?? []
}

/**
 * Table sorting → the sort param. Unsorting a column (tanstack cycles
 * asc → desc → none) returns to the default sort rather than to "no order":
 * a server list always has one.
 */
export function toSortParam(
  sorting: SortingState,
  allowed: readonly string[],
  fallback: string
): string {
  const first = sorting[0]
  if (!first || !allowed.includes(first.id)) return fallback
  return first.desc ? `-${first.id}` : first.id
}
