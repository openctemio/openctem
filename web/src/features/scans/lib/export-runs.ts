/**
 * Export of Scans › Runs as CSV (research 20 §5, "scoped export").
 *
 * The export reads exactly the list the table shows: the same endpoint
 * (GET /scan-runs, tenant from the session, the server's own scoping),
 * the same status filter and sort, one page of 100 after another, capped.
 * It never calls a broader endpoint and never builds ids on the client, so it
 * cannot contain anything the viewer could not page through on screen.
 * Cells go through the formula-safe CSV builder (`exportToCsv`).
 */

import { get } from '@/lib/api/client'
import { scanRunEndpoints } from '@/lib/api/endpoints'
import type {
  ScanRun,
  ScanRunListFilters,
  ScanRunListResponse,
} from '@/lib/api/scan-workflow-types'
import type { ExportFieldConfig } from '@/hooks/use-csv-export'
import { elapsedMs } from './run-display'

/** The most runs one export reads. */
export const RUN_EXPORT_CAP = 5000
const EXPORT_PAGE_SIZE = 100

export interface RunExport {
  runs: ScanRun[]
  /** Runs the list holds (the server's total for the filter). */
  total: number
  /** True when the list holds more runs than the export read. */
  capped: boolean
}

/** Every run of the list for `filters` (status and sort), up to `cap`. */
export async function fetchRunsForExport(
  filters: Pick<ScanRunListFilters, 'status' | 'sort'>,
  cap: number = RUN_EXPORT_CAP,
  fetchPage: (url: string) => Promise<ScanRunListResponse> = (url) => get<ScanRunListResponse>(url)
): Promise<RunExport> {
  const runs: ScanRun[] = []
  let total = 0
  for (let page = 1; runs.length < cap; page++) {
    const res = await fetchPage(
      scanRunEndpoints.list({ ...filters, page, per_page: EXPORT_PAGE_SIZE })
    )
    const items = res?.items ?? []
    total = res?.total ?? runs.length + items.length
    runs.push(...items)
    if (items.length < EXPORT_PAGE_SIZE || runs.length >= total) break
  }
  return { runs: runs.slice(0, cap), total, capped: total > cap }
}

/** The columns of the export. */
export const RUN_EXPORT_FIELDS: ExportFieldConfig<ScanRun>[] = [
  { header: 'Run ID', accessor: (r) => r.id },
  {
    header: 'Scan',
    accessor: (r) => (r.scan_id ? (r.scan_name ?? 'Deleted scan') : 'Scan run'),
  },
  { header: 'Scan ID', accessor: (r) => r.scan_id ?? '' },
  { header: 'Status', accessor: (r) => r.status },
  { header: 'Trigger', accessor: (r) => r.trigger_type },
  { header: 'Triggered by', accessor: (r) => r.triggered_by_name ?? '' },
  { header: 'Created', accessor: (r) => r.created_at },
  { header: 'Started', accessor: (r) => r.started_at ?? '' },
  { header: 'Completed', accessor: (r) => r.completed_at ?? '' },
  {
    header: 'Duration (s)',
    accessor: (r) => {
      const ms = elapsedMs(r)
      return ms === undefined ? '' : Math.round(ms / 1000)
    },
  },
  { header: 'Tasks', accessor: (r) => r.task_summary?.total ?? '' },
  { header: 'Tasks completed', accessor: (r) => r.task_summary?.completed ?? '' },
  { header: 'Tasks failed', accessor: (r) => r.task_summary?.failed ?? '' },
  { header: 'Findings', accessor: (r) => r.total_findings },
  { header: 'Message', accessor: (r) => r.error_message ?? '' },
]
