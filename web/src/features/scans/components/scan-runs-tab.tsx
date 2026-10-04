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
import type { ColumnDef } from '@tanstack/react-table'

import {
  DataTable,
  DataTableColumnHeader,
  MetricStrip,
  type MetricStripItem,
  RunStatusBadge,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Can, Permission } from '@/lib/permissions'
import { usePipelineRuns, useScanManagementStats } from '@/lib/api/pipeline-hooks'
import type { PipelineRun, PipelineRunListFilters } from '@/lib/api/pipeline-types'
import { useScanConfigs } from '@/lib/api/scan-hooks'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import { elapsedMs, runTaskProgress } from '@/features/scans/lib/run-display'
import { RunDetailSheet } from './run-detail-sheet'

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

export const RUNS_PAGE_SIZE = 25

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
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: RUNS_PAGE_SIZE })
  const [openRunId, setOpenRunId] = useState<string | null>(null)

  const swrConfig = useMemo(
    () => ({ revalidateOnFocus: false, refreshInterval: 30000, dedupingInterval: 5000 }),
    []
  )

  // The web's PipelineRunStatus spells canceled "cancelled"; the API filter
  // takes the stored value, so the status goes through as a string.
  const filters = {
    status: statusFilter === 'all' ? undefined : statusFilter,
    page: pagination.pageIndex + 1,
    per_page: pagination.pageSize,
  } as PipelineRunListFilters

  const { data, isLoading, error } = usePipelineRuns(filters, swrConfig)
  const { data: overview, isLoading: isLoadingStats } = useScanManagementStats(swrConfig)
  // Names for the Scan column; one page of configurations is enough to label
  // the runs on screen, and an unknown id falls back to "Scan".
  const { data: configs } = useScanConfigs({ per_page: 100 }, { revalidateOnFocus: false })
  const scanNames = useMemo(() => {
    const m = new Map<string, string>()
    for (const c of configs?.items ?? []) m.set(c.id, c.name)
    return m
  }, [configs?.items])

  const runs = data?.items ?? []
  const counts = overview?.pipelines

  const setStatus = useCallback(
    (v: RunStatusFilterValue) => {
      setStatusFilter(v)
      setPagination((p) => ({ ...p, pageIndex: 0 }))
    },
    [setStatusFilter]
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
          return (
            <Link
              href={`/scans/${run.scan_id}`}
              className="font-medium hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {scanNames.get(run.scan_id) ?? 'Scan'}
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
              <p
                className="max-w-[260px] truncate text-xs text-muted-foreground"
                title={row.original.error_message}
              >
                {row.original.error_message}
              </p>
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
        accessorKey: 'total_findings',
        header: 'Findings',
        enableSorting: false,
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
        id: 'started',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Started" />,
        enableSorting: false,
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
    [scanNames]
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
            getRowId={(r) => r.id}
            onRowClick={(r) => setOpenRunId(r.id)}
            manualPagination
            rowCount={data?.total ?? 0}
            pageCount={data?.total_pages}
            pagination={pagination}
            onPaginationChange={setPagination}
            pageSize={pagination.pageSize}
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
