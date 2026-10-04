'use client'

/**
 * Scans › Runs: every run the tenant's scans (and pipelines) started.
 *
 * Reads pipeline runs (GET /api/v1/pipeline-runs, paged on the server) — the
 * table every scan trigger writes. The tab used to read scan sessions, which
 * only CI/sensor-pushed runs create, so it stayed empty while scans ran.
 * Counts come from GET /api/v1/scans/overview-stats (`pipelines`).
 */

import { useCallback, useMemo, useState } from 'react'
import Link from 'next/link'
import type { ColumnDef, SortingState } from '@tanstack/react-table'

import {
  DataTable,
  DataTableColumnHeader,
  MetricStrip,
  type MetricStripItem,
  RunStatusBadge,
  TruncatedText,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useUrlFilter, useUrlFilterNumber } from '@/hooks/use-url-param'
import { Can, Permission } from '@/lib/permissions'
import { usePipelineRuns, useScanManagementStats } from '@/lib/api/pipeline-hooks'
import type { PipelineRun, PipelineRunListFilters } from '@/lib/api/pipeline-types'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import { elapsedMs, runTaskProgress } from '@/features/scans/lib/run-display'
import {
  DEFAULT_RUN_SORT,
  DEFAULT_SCAN_PAGE_SIZE,
  RUN_SORT_FIELDS,
  SCAN_PAGE_SIZES,
  parsePageSize,
  parseSortParam,
  toSortParam,
} from '@/features/scans/lib/scans-url'
import { RunDetailSheet } from './run-detail-sheet'
import { Download, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { exportToCsv } from '@/hooks/use-csv-export'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  RUN_EXPORT_CAP,
  RUN_EXPORT_FIELDS,
  fetchRunsForExport,
} from '@/features/scans/lib/export-runs'

/** Run statuses as the API stores them (pipeline.RunStatus). */
export const RUN_STATUS_FILTERS = [
  { value: 'all', label: 'All statuses' },
  { value: 'running', label: 'Running' },
  { value: 'pending', label: 'Pending' },
  { value: 'completed', label: 'Completed' },
  { value: 'partial', label: 'Partial' },
  { value: 'failed', label: 'Failed' },
  { value: 'timeout', label: 'Timed out' },
  { value: 'canceled', label: 'Canceled' },
] as const

type RunStatusFilterValue = (typeof RUN_STATUS_FILTERS)[number]['value']

export const RUNS_PAGE_SIZE = DEFAULT_SCAN_PAGE_SIZE

export function ScanRunsTab() {
  return (
    <Can
      permission={Permission.PipelinesRead}
      fallback={
        <p className="mt-5 rounded-md border p-6 text-sm text-muted-foreground">
          Viewing scan runs needs the &quot;View pipelines&quot; permission.
        </p>
      }
    >
      <ScanRunsTable />
    </Can>
  )
}

function ScanRunsTable() {
  const [statusFilter, setStatusFilter] = useUrlFilter('run_status', 'all') as [
    RunStatusFilterValue,
    (v: RunStatusFilterValue) => void,
  ]
  // Page, page size and sort live in the URL (prefixed: the Configurations
  // tab shares it) so a paged, sorted view of runs can be linked.
  const [pageParam, setPageParam] = useUrlFilterNumber('run_page', 1)
  const [perPageParam, setPerPageParam] = useUrlFilterNumber('run_per_page', RUNS_PAGE_SIZE)
  const perPage = parsePageSize(perPageParam)
  const [sortParam, setSortParam] = useUrlFilter('run_sort', DEFAULT_RUN_SORT)
  const sorting = useMemo<SortingState>(
    () => parseSortParam(sortParam, RUN_SORT_FIELDS, DEFAULT_RUN_SORT),
    [sortParam]
  )
  const pagination = { pageIndex: pageParam - 1, pageSize: perPage }
  const [openRunId, setOpenRunId] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)

  const swrConfig = useMemo(
    () => ({ revalidateOnFocus: false, refreshInterval: 30000, dedupingInterval: 5000 }),
    []
  )

  // The web's PipelineRunStatus spells canceled "cancelled"; the API filter
  // takes the stored value, so the status goes through as a string.
  const filters = {
    status: statusFilter === 'all' ? undefined : statusFilter,
    sort: toSortParam(sorting, RUN_SORT_FIELDS, DEFAULT_RUN_SORT),
    page: pageParam,
    per_page: perPage,
  } as PipelineRunListFilters

  const { data, isLoading, error } = usePipelineRuns(filters, swrConfig)
  const { data: overview, isLoading: isLoadingStats } = useScanManagementStats(swrConfig)
  const runs = data?.items ?? []
  const counts = overview?.pipelines

  const setStatus = useCallback(
    (v: RunStatusFilterValue) => {
      setStatusFilter(v)
      setPageParam(1)
    },
    [setStatusFilter, setPageParam]
  )
  const toggleStatus = (v: RunStatusFilterValue) => setStatus(statusFilter === v ? 'all' : v)

  const columns: ColumnDef<PipelineRun>[] = useMemo(
    () => [
      {
        id: 'scan',
        header: 'Scan',
        enableSorting: false,
        cell: ({ row }) => {
          const run = row.original
          if (!run.scan_id) {
            return <span className="text-muted-foreground">Pipeline run</span>
          }
          // Named by the server (quick scans and every page included); a run
          // whose scan was deleted keeps its row.
          if (!run.scan_name) {
            return <span className="text-muted-foreground">Deleted scan</span>
          }
          return (
            <Link
              href={`/scans/${encodeURIComponent(run.scan_id)}`}
              className="font-medium hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {run.scan_name}
            </Link>
          )
        },
      },
      {
        accessorKey: 'status',
        header: 'Status',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <RunStatusBadge status={row.original.status} />
            {row.original.error_message && (
              <TruncatedText
                value={row.original.error_message}
                label="Run message"
                className="max-w-[260px] text-xs text-muted-foreground"
              />
            )}
          </div>
        ),
      },
      {
        id: 'tasks',
        header: 'Tasks',
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const progress = runTaskProgress(r.task_summary)
          if (!progress) {
            // No task summary (nothing dispatched yet, or an older API): steps.
            return (
              <span className="text-sm tabular-nums">
                {r.completed_steps}/{r.total_steps} steps
                {r.failed_steps > 0 && (
                  <span className="ms-1 text-destructive">({r.failed_steps} failed)</span>
                )}
              </span>
            )
          }
          return (
            <div className="space-y-0.5">
              <span className="text-sm tabular-nums">{progress.label}</span>
              {progress.details.length > 0 && (
                <p className="text-xs text-muted-foreground tabular-nums">
                  {progress.details.map((d, i) => (
                    <span key={d.key} className={d.key === 'failed' ? 'text-destructive' : ''}>
                      {i > 0 && ' · '}
                      {d.count} {d.key}
                    </span>
                  ))}
                </p>
              )}
            </div>
          )
        },
      },
      {
        id: 'total_findings',
        accessorKey: 'total_findings',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Findings" />,
        cell: ({ row }) =>
          row.original.total_findings > 0 ? (
            <span className="tabular-nums">{row.original.total_findings}</span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'duration',
        header: 'Duration',
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const finished = !!r.completed_at
          const ms = elapsedMs(r)
          if (ms === undefined) {
            return (
              <span className="text-xs text-muted-foreground">
                {r.status === 'pending' ? 'Not started' : '-'}
              </span>
            )
          }
          const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
          return finished ? (
            <span className="text-sm tabular-nums">{label}</span>
          ) : (
            <span className="text-sm text-muted-foreground tabular-nums">{label} so far</span>
          )
        },
      },
      {
        id: 'started_at',
        accessorKey: 'started_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Started" />,
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatScanDate(row.original.started_at || row.original.created_at)}
          </span>
        ),
      },
      {
        id: 'trigger',
        header: 'Triggered by',
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {row.original.triggered_by_name || row.original.trigger_type}
          </span>
        ),
      },
    ],
    []
  )

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: 'Runs',
      value: counts?.total ?? 0,
      onClick: () => setStatus('all'),
      active: statusFilter === 'all',
    },
    {
      key: 'running',
      label: 'Running',
      value: counts?.running ?? 0,
      onClick: () => toggleStatus('running'),
      active: statusFilter === 'running',
    },
    {
      key: 'pending',
      label: 'Pending',
      value: counts?.pending ?? 0,
      onClick: () => toggleStatus('pending'),
      active: statusFilter === 'pending',
    },
    {
      key: 'completed',
      label: 'Completed',
      value: counts?.completed ?? 0,
      onClick: () => toggleStatus('completed'),
      active: statusFilter === 'completed',
    },
    {
      key: 'partial',
      label: 'Partial',
      value: counts?.partial ?? 0,
      onClick: () => toggleStatus('partial'),
      active: statusFilter === 'partial',
    },
    // The API counts timed-out runs as failed here; the status filter keeps
    // them apart, so this tile does not filter.
    { key: 'failed', label: 'Failed or timed out', value: counts?.failed ?? 0, tone: 'danger' },
    {
      key: 'canceled',
      label: 'Canceled',
      value: counts?.canceled ?? 0,
      onClick: () => toggleStatus('canceled'),
      active: statusFilter === 'canceled',
    },
  ]

  const toolbarStart = (
    <Select value={statusFilter} onValueChange={(v) => setStatus(v as RunStatusFilterValue)}>
      <SelectTrigger className="h-9 w-auto min-w-36" aria-label="Filter runs by status">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {RUN_STATUS_FILTERS.map((f) => (
          <SelectItem key={f.value} value={f.value}>
            {f.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  const filtered = statusFilter !== 'all'

  // Exports the list as filtered and sorted, through the same endpoint.
  const exportRuns = async () => {
    setExporting(true)
    try {
      const {
        runs: all,
        total,
        capped,
      } = await fetchRunsForExport({
        status: filters.status,
        sort: filters.sort,
      })
      if (exportToCsv(all, RUN_EXPORT_FIELDS, 'scan-runs') && capped) {
        toast.info(
          `Exported the first ${RUN_EXPORT_CAP} of ${total} runs. Narrow the filter to export the rest.`
        )
      }
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not export the runs'))
    } finally {
      setExporting(false)
    }
  }

  const toolbarEnd = (
    <Button
      variant="outline"
      size="sm"
      className="h-9"
      onClick={() => void exportRuns()}
      disabled={exporting || !data?.total}
      aria-busy={exporting}
    >
      {exporting ? (
        <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none sm:me-2" />
      ) : (
        <Download className="h-4 w-4 sm:me-2" />
      )}
      <span className="hidden sm:inline">Export CSV</span>
      <span className="sr-only sm:hidden">Export CSV</span>
    </Button>
  )

  return (
    <>
      <MetricStrip loading={isLoadingStats} items={metrics} />

      <div className="mt-5">
        {error ? (
          <div className="rounded-md border p-6 text-sm">
            <p className="font-medium">Could not load scan runs.</p>
            <Button variant="link" className="h-auto p-0" onClick={() => window.location.reload()}>
              Reload
            </Button>
          </div>
        ) : (
          <DataTable
            columns={columns}
            data={runs}
            isLoading={isLoading && !data}
            showSearch={false}
            toolbarStart={toolbarStart}
            toolbarEnd={toolbarEnd}
            getRowId={(r) => r.id}
            onRowClick={(r) => setOpenRunId(r.id)}
            manualPagination
            rowCount={data?.total ?? 0}
            pageCount={data?.total_pages}
            pagination={pagination}
            onPaginationChange={(next) => {
              if (next.pageSize !== perPage) {
                setPerPageParam(next.pageSize)
                setPageParam(1)
              } else {
                setPageParam(next.pageIndex + 1)
              }
            }}
            pageSize={perPage}
            pageSizeOptions={[...SCAN_PAGE_SIZES]}
            sorting={sorting}
            onSortingChange={(next) => {
              setSortParam(toSortParam(next, RUN_SORT_FIELDS, DEFAULT_RUN_SORT))
              setPageParam(1)
            }}
            paginationNoun="runs"
            emptyMessage={filtered ? 'No runs with this status' : 'No scan runs yet'}
            emptyDescription={
              filtered
                ? 'Try another status.'
                : 'Runs appear here once a scan configuration or quick scan starts.'
            }
          />
        )}
      </div>

      <RunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />
    </>
  )
}
