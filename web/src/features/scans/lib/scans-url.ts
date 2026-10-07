/**
 * List settings of the Scans area (research 20 §4.1): the page sizes and the
 * sortable fields each list offers. The URL state itself is useListParams
 * (plain page, per_page, sort and field-named filters, validated against
 * these lists).
 */

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
