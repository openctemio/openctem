'use client'

/**
 * Scans › Runs: every run the tenant's scans (and workflows) started.
 *
 * Reads workflow runs (GET /api/v1/scan-runs, paged on the server) — the
 * table every scan trigger writes. The tab used to read scan sessions, which
 * only CI/sensor-pushed runs create, so it stayed empty while scans ran.
 * Counts come from GET /api/v1/scans/overview-stats (`workflows`).
 */

import { IntensityBadge } from './intensity-badge'
import { useCallback, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useSWRConfig } from 'swr'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'

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
import { useListParams } from '@/hooks/use-list-params'
import { Can, Permission } from '@/lib/permissions'
import { useScanRuns, useScanManagementStats } from '@/lib/api/scan-workflow-hooks'
import { scanManagementEndpoints } from '@/lib/api/endpoints'
import type { ScanRun, ScanRunListFilters } from '@/lib/api/scan-workflow-types'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import {
  IDLE_RUN_LIST_REFRESH_MS,
  RUN_KIND_FILTERS,
  elapsedMs,
  isRunInProgress,
  liveRunIds,
  runListRefreshInterval,
  runKindLabel,
  runSubjectFindingId,
  runTriggeredByLabel,
  runTaskProgress,
} from '@/features/scans/lib/run-display'
import { replaceUrlSearch } from '@/hooks/use-url-param'
import { useRunChannels } from '@/hooks/use-websocket'
import {
  DEFAULT_RUN_SORT,
  DEFAULT_SCAN_PAGE_SIZE,
  RUN_SORT_FIELDS,
  SCAN_PAGE_SIZES,
} from '@/features/scans/lib/scans-url'
import { RunDetailSheet } from './run-detail-sheet'
import { Download, Loader2, X } from 'lucide-react'
import { toast } from 'sonner'
import { exportToCsv } from '@/hooks/use-csv-export'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  RUN_EXPORT_CAP,
  RUN_EXPORT_FIELDS,
  fetchRunsForExport,
} from '@/features/scans/lib/export-runs'

/** Run statuses as the API stores them (scanrun.RunStatus). */
export const RUN_STATUS_FILTERS = [
  { value: 'all' },
  { value: 'running' },
  { value: 'pending' },
  { value: 'completed' },
  { value: 'partial' },
  { value: 'failed' },
  { value: 'timeout' },
  { value: 'canceled' },
  // Refused before anything was dispatched (scope, freeze, no sensor...).
  { value: 'blocked' },
] as const

type RunStatusFilterValue = (typeof RUN_STATUS_FILTERS)[number]['value']
type RunKindFilterValue = (typeof RUN_KIND_FILTERS)[number]['value']

export const RUNS_PAGE_SIZE = DEFAULT_SCAN_PAGE_SIZE

export function ScanRunsTab() {
  const { t } = useTranslation()
  return (
    <Can
      permission={Permission.ScansRead}
      fallback={
        <p className="mt-5 rounded-md border p-6 text-sm text-muted-foreground">
          {t('scans.runs.noPermission')}
        </p>
      }
    >
      <ScanRunsTable />
    </Can>
  )
}

function ScanRunsTable() {
  const { t } = useTranslation()
  // One list per route (/scans/runs), so plain page / per_page / sort and
  // field-named filters: `status`, and `scan_id` from a scan's "View all runs".
  const list = useListParams({
    pageSizes: SCAN_PAGE_SIZES,
    defaultPageSize: RUNS_PAGE_SIZE,
    sortFields: RUN_SORT_FIELDS,
    defaultSort: DEFAULT_RUN_SORT,
    filters: { status: 'all', scan_id: '', kind: 'all' },
  })
  const statusFilter = (
    RUN_STATUS_FILTERS.some((f) => f.value === list.filters.status) ? list.filters.status : 'all'
  ) as RunStatusFilterValue
  const kindFilter = (
    RUN_KIND_FILTERS.some((f) => f.value === list.filters.kind) ? list.filters.kind : 'all'
  ) as RunKindFilterValue
  const scanFilter = list.filters.scan_id
  const { pagination, sorting, perPage } = list
  // A link to one run (a retest's "View run") opens it: /scans/runs?run=<id>.
  // Opening a row does not touch the list's URL; closing drops ?run.
  const [openRunId, setOpenRunId] = useState<string | null>(() =>
    typeof window === 'undefined' ? null : new URLSearchParams(window.location.search).get('run')
  )
  const closeRun = () => {
    setOpenRunId(null)
    const params = new URLSearchParams(window.location.search)
    if (params.has('run')) {
      params.delete('run')
      replaceUrlSearch(params)
    }
  }
  const [exporting, setExporting] = useState(false)

  // The live runs' change notices (run:{id}) refresh the list and its
  // counts; they poll every 30 s only while a run is live and the notices
  // cannot arrive (socket down), and every 2 min otherwise (new runs).
  const [liveIds, setLiveIds] = useState<string[]>([])
  const { mutate: mutateCache } = useSWRConfig()
  const realtime = useRunChannels(liveIds, () => {
    void mutateCache(
      (key) =>
        typeof key === 'string' &&
        (key.startsWith('/api/v1/scan-runs') || key === scanManagementEndpoints.stats())
    )
  })
  const swrConfig = useMemo(
    () => ({
      revalidateOnFocus: false,
      refreshInterval: runListRefreshInterval(30000, IDLE_RUN_LIST_REFRESH_MS, realtime),
      dedupingInterval: 5000,
      onSuccess: (page: { data?: Array<{ id: string; status: string }> } | undefined) =>
        setLiveIds(liveRunIds(page?.data)),
    }),
    [realtime]
  )

  // Statuses are typed as the API stores them, so the filter value goes
  // through unchanged.
  const filters: ScanRunListFilters = {
    status: statusFilter === 'all' ? undefined : statusFilter,
    scan_id: scanFilter || undefined,
    kind: kindFilter === 'all' ? undefined : kindFilter,
    sort: list.sort,
    page: list.page,
    per_page: perPage,
  }

  const { data, isLoading, error } = useScanRuns(filters, swrConfig)
  const runs = data?.data ?? []
  // The counts follow the list: live while a listed run is live.
  const runsLive = runs.some(isRunInProgress)
  const { data: overview, isLoading: isLoadingStats } = useScanManagementStats({
    revalidateOnFocus: false,
    dedupingInterval: 5000,
    refreshInterval: runsLive && !realtime ? 30000 : IDLE_RUN_LIST_REFRESH_MS,
  })
  const counts = overview?.scan_runs

  const { setFilter } = list
  const setStatus = useCallback((v: RunStatusFilterValue) => setFilter('status', v), [setFilter])
  const toggleStatus = (v: RunStatusFilterValue) => setStatus(statusFilter === v ? 'all' : v)

  const columns: ColumnDef<ScanRun>[] = useMemo(
    () => [
      {
        id: 'scan',
        header: t('scans.runs.colScan'),
        enableSorting: false,
        cell: ({ row }) => {
          const run = row.original
          const findingId = runSubjectFindingId(run)
          if (run.kind && run.kind !== 'scan' && run.kind !== 'quick') {
            return (
              <div className="space-y-0.5">
                <span className="font-medium">{runKindLabel(run.kind, t)}</span>
                {findingId && (
                  <Link
                    href={`/findings/${encodeURIComponent(findingId)}`}
                    className="block text-xs text-muted-foreground hover:underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {t('scans.runs.openFinding')}
                  </Link>
                )}
              </div>
            )
          }
          if (!run.scan_id) {
            return <span className="text-muted-foreground">{t('scans.runs.scanRun')}</span>
          }
          // Named by the server (quick scans and every page included); a run
          // whose scan was deleted keeps its row.
          if (!run.scan_name) {
            return <span className="text-muted-foreground">{t('scans.runs.deletedScan')}</span>
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
        header: t('scans.runs.colStatus'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <div className="flex flex-wrap items-center gap-1">
              <RunStatusBadge status={row.original.status} />
              <IntensityBadge intensity={row.original.intensity} />
            </div>
            {row.original.error_message && (
              <TruncatedText
                value={row.original.error_message}
                label={t('scans.runs.runMessage')}
                className="max-w-[260px] text-xs text-muted-foreground"
              />
            )}
          </div>
        ),
      },
      {
        id: 'tasks',
        header: t('scans.runs.colTasks'),
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const progress = runTaskProgress(r.task_summary, t)
          if (!progress) {
            // No task summary (nothing dispatched yet, or an older API): steps.
            return (
              <span className="text-sm tabular-nums">
                {t('scans.runs.steps', undefined, {
                  done: r.completed_steps,
                  total: r.total_steps,
                })}
                {r.failed_steps > 0 && (
                  <span className="ms-1 text-destructive">
                    {t('scans.runs.stepsFailed', undefined, { count: r.failed_steps })}
                  </span>
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
                      {d.count} {t(`scans.taskState.${d.key}`)}
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
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.runs.colFindings')} />
        ),
        cell: ({ row }) =>
          row.original.total_findings > 0 ? (
            <span className="tabular-nums">{row.original.total_findings}</span>
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'duration',
        header: t('scans.runs.colDuration'),
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const finished = !!r.completed_at
          const ms = elapsedMs(r)
          if (ms === undefined) {
            return (
              <span className="text-xs text-muted-foreground">
                {r.status === 'pending' ? t('scans.runs.notStarted') : '-'}
              </span>
            )
          }
          const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
          return finished ? (
            <span className="text-sm tabular-nums">{label}</span>
          ) : (
            <span className="text-sm text-muted-foreground tabular-nums">
              {t('scans.runs.soFar', undefined, { duration: label })}
            </span>
          )
        },
      },
      {
        id: 'started_at',
        accessorKey: 'started_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.runs.colStarted')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatScanDate(row.original.started_at || row.original.created_at)}
          </span>
        ),
      },
      {
        id: 'trigger',
        header: t('scans.runs.colTriggeredBy'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {runTriggeredByLabel(row.original, t) ?? row.original.trigger_type}
          </span>
        ),
      },
    ],
    [t]
  )

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: t('scans.runs.metricRuns'),
      value: counts?.total ?? 0,
      onClick: () => setStatus('all'),
      active: statusFilter === 'all',
    },
    {
      key: 'running',
      label: t('scans.runStatus.running'),
      value: counts?.running ?? 0,
      onClick: () => toggleStatus('running'),
      active: statusFilter === 'running',
    },
    {
      key: 'pending',
      label: t('scans.runStatus.pending'),
      value: counts?.pending ?? 0,
      onClick: () => toggleStatus('pending'),
      active: statusFilter === 'pending',
    },
    {
      key: 'completed',
      label: t('scans.runStatus.completed'),
      value: counts?.completed ?? 0,
      onClick: () => toggleStatus('completed'),
      active: statusFilter === 'completed',
    },
    {
      key: 'partial',
      label: t('scans.runStatus.partial'),
      value: counts?.partial ?? 0,
      onClick: () => toggleStatus('partial'),
      active: statusFilter === 'partial',
    },
    // The API counts timed-out runs as failed here; the status filter keeps
    // them apart, so this tile does not filter.
    {
      key: 'failed',
      label: t('scans.runs.failedOrTimedOut'),
      value: counts?.failed ?? 0,
      tone: 'danger',
    },
    {
      key: 'canceled',
      label: t('scans.runStatus.canceled'),
      value: counts?.canceled ?? 0,
      onClick: () => toggleStatus('canceled'),
      active: statusFilter === 'canceled',
    },
  ]

  const toolbarStart = (
    <div className="flex flex-wrap items-center gap-2">
      <Select value={statusFilter} onValueChange={(v) => setStatus(v as RunStatusFilterValue)}>
        <SelectTrigger className="h-9 w-auto min-w-36" aria-label={t('scans.runs.filterStatus')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {RUN_STATUS_FILTERS.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {t(`scans.runStatus.${f.value}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={kindFilter} onValueChange={(v) => setFilter('kind', v)}>
        <SelectTrigger className="h-9 w-auto min-w-32" aria-label={t('scans.runs.filterKind')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {RUN_KIND_FILTERS.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {t(`scans.runKindFilter.${f.value}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {scanFilter && (
        <Button
          variant="secondary"
          size="sm"
          className="h-9"
          onClick={() => list.setFilter('scan_id', '')}
          aria-label={t('scans.runs.showAllScans')}
        >
          {t('scans.runs.oneScan')}
          <X className="ms-1.5 h-3.5 w-3.5" aria-hidden />
        </Button>
      )}
    </div>
  )

  const filtered = statusFilter !== 'all' || kindFilter !== 'all'

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
        scan_id: filters.scan_id,
        kind: filters.kind,
        sort: filters.sort,
      })
      if (exportToCsv(all, RUN_EXPORT_FIELDS, 'scan-runs') && capped) {
        toast.info(t('scans.runs.exportedFirst', undefined, { cap: RUN_EXPORT_CAP, total }))
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.runs.exportFailed')))
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
      <span className="hidden sm:inline">{t('scans.runs.exportCsv')}</span>
      <span className="sr-only sm:hidden">{t('scans.runs.exportCsv')}</span>
    </Button>
  )

  return (
    <>
      <MetricStrip loading={isLoadingStats} items={metrics} />

      <div className="mt-5">
        {error ? (
          <div className="rounded-md border p-6 text-sm">
            <p className="font-medium">{t('scans.runs.loadFailed')}</p>
            <Button variant="link" className="h-auto p-0" onClick={() => window.location.reload()}>
              {t('scans.runs.reload')}
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
            onPaginationChange={list.setPagination}
            pageSize={perPage}
            pageSizeOptions={[...SCAN_PAGE_SIZES]}
            sorting={sorting}
            onSortingChange={list.setSorting}
            paginationNoun={t('scans.runs.noun')}
            emptyMessage={filtered ? t('scans.runs.emptyFiltered') : t('scans.runs.empty')}
            emptyDescription={filtered ? t('scans.runs.tryOther') : t('scans.runs.emptyHint')}
          />
        )}
      </div>

      <RunDetailSheet runId={openRunId} onOpenChange={(o) => !o && closeRun()} />
    </>
  )
}
