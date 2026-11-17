'use client'

/**
 * Scans › Runs: every run the tenant's scans (and workflows) started.
 *
 * Reads workflow runs (GET /api/v1/scan-runs, paged on the server) — the
 * table every scan trigger writes. The tab used to read scan sessions, which
 * only CI/sensor-pushed runs create, so it stayed empty while scans ran.
 * Counts come from GET /api/v1/scans/overview-stats (`workflows`).
 *
 * The list has no search field and no Query mode: the run list API takes
 * field filters only.
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
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FilterSheet,
  MetricStrip,
  type MetricStripItem,
  RunStatusBadge,
} from '@/features/shared'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useHeldRows } from '@/hooks/use-held-rows'
import { useListParams } from '@/hooks/use-list-params'
import { useIsMobile } from '@/hooks/use-mobile'
import { accessStateOf } from '@/lib/api/access-state'
import { Can, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useScanRuns, useScanManagementStats } from '@/lib/api/scan-workflow-hooks'
import { scanManagementEndpoints } from '@/lib/api/endpoints'
import type { ScanRun, ScanRunListFilters } from '@/lib/api/scan-workflow-types'
import { findingDetailHref } from '@/features/findings/lib/finding-link'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'
import { scanDetailHref } from '@/features/scans/lib/scan-link'
import {
  DEFAULT_RUN_ORIGIN,
  IDLE_RUN_LIST_REFRESH_MS,
  RUN_KIND_FILTERS,
  RUN_ORIGIN_FILTERS,
  type RunOriginFilterValue,
  elapsedMs,
  isRunInProgress,
  liveRunIds,
  runListRefreshInterval,
  runKindLabel,
  runKindQuery,
  runOriginQuery,
  runSubjectFindingId,
  runTargetNote,
  runTriggeredByLabel,
  runTaskProgress,
} from '@/features/scans/lib/run-display'
import { RunManagedBadge } from '@/features/scans/components/run-managed-badge'
import { COVERAGE_SETTINGS_HREF } from './managed-scan-banner'
import { replaceUrlSearch, useUrlParam } from '@/hooks/use-url-param'
import { useRunChannels } from '@/hooks/use-websocket'
import {
  DEFAULT_RUN_SORT,
  DEFAULT_SCAN_PAGE_SIZE,
  RUN_SORT_FIELDS,
  SCAN_PAGE_SIZES,
} from '@/features/scans/lib/scans-url'
import { LazyRunDetailSheet } from './lazy-dialogs'
import { Download, ListChecks, MoreHorizontal, RefreshCw } from 'lucide-react'
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

/**
 * Column widths (px) and the table-frame width under which a column steps
 * aside (it stays under Display > Columns): Intensity first, then Triggered
 * by. The first four after the scan (Status, Tasks, Findings, Duration) are
 * the fields of the phone card. With the name's floor (200) the whole set fits the frame of a 1440
 * screen (1114) and, without the two, the frame of a 1280 screen (954).
 */
const RUNS_WIDTH = {
  status: 176,
  intensity: 120,
  tasks: 152,
  findings: 88,
  duration: 104,
  started: 132,
  trigger: 136,
}
const RUNS_HIDE_BELOW = { intensity: 1100, trigger: 1000 } as const

const getRunId = (r: ScanRun) => r.id
const NO_RUNS: ScanRun[] = []

export function ScanRunsTab() {
  const { t } = useTranslation()
  return (
    <Can
      permission={Permission.ScansRead}
      fallback={
        <NoAccessState
          title={t('scans.runs.listName', 'the run list')}
          permission={Permission.ScansRead}
        />
      }
    >
      <ScanRunsTable />
    </Can>
  )
}

/**
 * The Scan cell, on one line: the scan's name as a link to the scan, or what
 * the run is when it belongs to no scan (a retest, with its finding), then
 * the mark of a platform-managed scan.
 */
function RunScanCell({ run }: { run: ScanRun }) {
  const { t } = useTranslation()
  const findingId = runSubjectFindingId(run)
  if (run.kind && run.kind !== 'scan' && run.kind !== 'quick') {
    return (
      <div data-slot="run-scan-cell" className="flex min-w-0 items-center gap-2">
        <span className="min-w-16 truncate font-medium">{runKindLabel(run.kind, t)}</span>
        <span className="flex min-w-0 shrink overflow-hidden">
          <RunManagedBadge managedBy={run.managed_by} />
        </span>
        {findingId && (
          <Link
            href={findingDetailHref(findingId)}
            className="shrink-0 text-xs text-muted-foreground hover:underline"
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
  // Named by the server (quick scans and every page included); a run whose
  // scan was deleted keeps its row.
  if (!run.scan_name) {
    return <span className="text-muted-foreground">{t('scans.runs.deletedScan')}</span>
  }
  return (
    <div data-slot="run-scan-cell" className="flex min-w-0 items-center gap-2">
      <Link
        href={scanDetailHref(run.scan_id)}
        dir="auto"
        title={run.scan_name}
        className="min-w-16 truncate rounded-sm font-medium [unicode-bidi:isolate] hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none focus-visible:ring-inset"
        onClick={(e) => e.stopPropagation()}
      >
        {run.scan_name}
      </Link>
      {/* The mark gives way before the name does. */}
      <span className="flex min-w-0 shrink overflow-hidden">
        <RunManagedBadge managedBy={run.managed_by} />
      </span>
    </div>
  )
}

/** A filter value with its count at the row's end (the phone filter sheet). */
function CountedLabel({ label, count }: { label: string; count?: number }) {
  return (
    <span className="flex min-w-0 items-center justify-between gap-2">
      <span className="min-w-0 truncate">{label}</span>
      {count !== undefined && (
        <span className="shrink-0 tabular-nums text-muted-foreground">{count}</span>
      )}
    </span>
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
    filters: { status: 'all', scan_id: '', kind: 'all', origin: DEFAULT_RUN_ORIGIN },
  })
  const statusFilter = (
    RUN_STATUS_FILTERS.some((f) => f.value === list.filters.status) ? list.filters.status : 'all'
  ) as RunStatusFilterValue
  const kindFilter = (
    RUN_KIND_FILTERS.some((f) => f.value === list.filters.kind) ? list.filters.kind : 'all'
  ) as RunKindFilterValue
  const originFilter = (
    RUN_ORIGIN_FILTERS.some((f) => f.value === list.filters.origin)
      ? list.filters.origin
      : DEFAULT_RUN_ORIGIN
  ) as RunOriginFilterValue
  const scanFilter = list.filters.scan_id
  const { pagination, sorting, perPage } = list
  // A link to one run (a retest's "View run") opens it: /scans/runs?run=<id>.
  // Opening a row does not touch the list's URL; closing drops ?run.
  // ?run is read on every render, not once: after an in-app navigation the
  // first render still sees the previous page's URL.
  const runFromUrl = useUrlParam('run')
  const [pickedRunId, setOpenRunId] = useState<string | null>(null)
  const openRunId = pickedRunId ?? runFromUrl
  const closeRun = () => {
    setOpenRunId(null)
    const params = new URLSearchParams(window.location.search)
    if (params.has('run')) {
      params.delete('run')
      replaceUrlSearch(params)
    }
  }
  const [exporting, setExporting] = useState(false)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)

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
      // Another page, filter or sort keeps the rows on screen until the
      // new ones arrive: the table and its toolbar never collapse.
      keepPreviousData: true,
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
    ...runKindQuery(kindFilter),
    ...runOriginQuery(originFilter),
    sort: list.sort,
    page: list.page,
    per_page: perPage,
  }

  const { data, isLoading, isValidating, error, mutate } = useScanRuns(filters, swrConfig)
  const readRuns = data?.data
  // The list re-reads itself while runs are live. Rows under the pointer
  // keep their places through a re-read; a new page, filter or sort (the
  // view key) shows its rows at once.
  const viewKey = [
    statusFilter,
    kindFilter,
    originFilter,
    scanFilter,
    list.sort,
    list.page,
    perPage,
  ].join('\u0000')
  const heldRows = useHeldRows(readRuns ?? NO_RUNS, getRunId, viewKey)
  const runs = heldRows.rows
  // The counts follow the list: live while a listed run is live.
  const runsLive = runs.some(isRunInProgress)
  const {
    data: overview,
    isLoading: isLoadingStats,
    isValidating: isValidatingStats,
    mutate: mutateStats,
  } = useScanManagementStats({
    revalidateOnFocus: false,
    dedupingInterval: 5000,
    refreshInterval: runsLive && !realtime ? 30000 : IDLE_RUN_LIST_REFRESH_MS,
  })
  const counts = overview?.scan_runs
  // The runs the platform started on its own, for the one-line summary while
  // the list shows people's runs: every run the tenant has (the counters)
  // less the people's runs the unfiltered list counts. Read from the two
  // requests the page already makes; a filtered list cannot be subtracted.
  const unfiltered = statusFilter === 'all' && kindFilter === 'all' && !scanFilter
  const systemRunCount =
    originFilter === 'user' && unfiltered && counts && data
      ? Math.max(0, counts.total - data.total)
      : 0

  const { setFilter } = list
  // The same decision the table makes for its cards (under 768 px).
  const isPhone = useIsMobile()
  const setStatus = useCallback((v: RunStatusFilterValue) => setFilter('status', v), [setFilter])
  const toggleStatus = (v: RunStatusFilterValue) => setStatus(statusFilter === v ? 'all' : v)

  const columns: ColumnDef<ScanRun>[] = useMemo(
    () => [
      {
        // Rows are one line. The run's scan names the row: frozen at the
        // start while the table scrolls sideways.
        id: 'scan',
        meta: { kind: 'name', pin: 'start', minWidth: 200, label: t('scans.runs.colScan') },
        enableHiding: false,
        header: t('scans.runs.colScan'),
        enableSorting: false,
        cell: ({ row }) => <RunScanCell run={row.original} />,
      },
      {
        accessorKey: 'status',
        meta: { kind: 'text', width: RUNS_WIDTH.status, label: t('scans.runs.colStatus') },
        header: t('scans.runs.colStatus'),
        enableSorting: false,
        cell: ({ row }) => {
          // The state, then what the targets held back and the run's message
          // (why it failed or was refused) as one muted text cut to the
          // column: whole in the hover text and in the run's sheet. The state
          // word stays one chip that never wraps.
          const note = runTargetNote(row.original, t)
          const message = row.original.error_message
          const more = [note, message].filter(Boolean).join('. ')
          return (
            <div className="flex min-w-0 items-center gap-2" title={more || undefined}>
              <RunStatusBadge status={row.original.status} className="shrink-0" />
              {/* A phone card shows four fields: the intensity rides with the
                  state there, as it has no column of its own. */}
              {isPhone && <IntensityBadge intensity={row.original.intensity} />}
              {more && (
                <span
                  data-slot="run-status-more"
                  className="min-w-0 truncate text-xs text-muted-foreground"
                >
                  {more}
                </span>
              )}
            </div>
          )
        },
      },
      {
        id: 'tasks',
        meta: { kind: 'text', width: RUNS_WIDTH.tasks, label: t('scans.runs.colTasks') },
        header: t('scans.runs.colTasks'),
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const progress = runTaskProgress(r.task_summary, t)
          if (!progress) {
            // No task summary (nothing dispatched yet, or an older API): steps.
            const steps = t('scans.runs.steps', undefined, {
              done: r.completed_steps,
              total: r.total_steps,
            })
            const failed =
              r.failed_steps > 0
                ? t('scans.runs.stepsFailed', undefined, { count: r.failed_steps })
                : ''
            return (
              <span
                className="block truncate text-sm tabular-nums"
                title={failed ? `${steps} ${failed}` : steps}
              >
                {steps}
                {failed && <span className="ms-1 text-destructive">{failed}</span>}
              </span>
            )
          }
          const details = progress.details.map((d) => `${d.count} ${t(`scans.taskState.${d.key}`)}`)
          return (
            <span
              className="block truncate text-sm tabular-nums"
              title={[progress.label, ...details].join(', ')}
            >
              <span>{progress.label}</span>
              {progress.details.map((d, i) => (
                <span key={d.key} className="text-xs text-muted-foreground">
                  {', '}
                  <span className={d.key === 'failed' ? 'text-destructive' : undefined}>
                    {details[i]}
                  </span>
                </span>
              ))}
            </span>
          )
        },
      },
      {
        id: 'total_findings',
        accessorKey: 'total_findings',
        meta: { kind: 'number', width: RUNS_WIDTH.findings, label: t('scans.runs.colFindings') },
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
        meta: { kind: 'text', width: RUNS_WIDTH.duration, label: t('scans.runs.colDuration') },
        header: t('scans.runs.colDuration'),
        enableSorting: false,
        cell: ({ row }) => {
          const r = row.original
          const finished = !!r.completed_at
          const ms = elapsedMs(r)
          if (ms === undefined) {
            return (
              <span className="block truncate text-xs text-muted-foreground">
                {r.status === 'pending' ? t('scans.runs.notStarted') : '-'}
              </span>
            )
          }
          const label = ms < 1000 ? '<1s' : formatScanDuration(ms)
          return finished ? (
            <span className="text-sm tabular-nums">{label}</span>
          ) : (
            <span className="block truncate text-sm text-muted-foreground tabular-nums">
              {t('scans.runs.soFar', undefined, { duration: label })}
            </span>
          )
        },
      },
      {
        id: 'intensity',
        accessorKey: 'intensity',
        meta: {
          kind: 'status',
          width: RUNS_WIDTH.intensity,
          hideBelow: RUNS_HIDE_BELOW.intensity,
          label: t('scans.intensity.label'),
        },
        header: t('scans.intensity.label'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.intensity ? (
            <IntensityBadge intensity={row.original.intensity} />
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'started_at',
        accessorKey: 'started_at',
        meta: { kind: 'date', width: RUNS_WIDTH.started, label: t('scans.runs.colStarted') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.runs.colStarted')} />
        ),
        cell: ({ row }) => (
          <span className="text-sm whitespace-nowrap text-muted-foreground">
            {formatScanDate(row.original.started_at || row.original.created_at)}
          </span>
        ),
      },
      {
        id: 'trigger',
        meta: {
          kind: 'text',
          width: RUNS_WIDTH.trigger,
          hideBelow: RUNS_HIDE_BELOW.trigger,
          label: t('scans.runs.colTriggeredBy'),
        },
        header: t('scans.runs.colTriggeredBy'),
        enableSorting: false,
        cell: ({ row }) => {
          const who = runTriggeredByLabel(row.original, t) ?? row.original.trigger_type
          return (
            <span className="block truncate text-sm text-muted-foreground" title={who}>
              {who}
            </span>
          )
        },
      },
    ],
    [t, isPhone]
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
      tone: 'warning',
      onClick: () => toggleStatus('partial'),
      active: statusFilter === 'partial',
    },
  ]
  // Five tiles, each the shortcut of one Status value (research/244: a tile
  // filters the list below, at most five). Failed, timed out, canceled and
  // blocked are in the Status filter: the overview counts failed and timed
  // out together, so a "Failed" tile could not equal the list it opens.

  /** The counter of a status, for the five the overview counts on their own. */
  const statusCount = (v: RunStatusFilterValue): number | undefined => {
    if (!counts) return undefined
    switch (v) {
      case 'all':
        return counts.total
      case 'running':
        return counts.running
      case 'pending':
        return counts.pending
      case 'completed':
        return counts.completed
      case 'partial':
        return counts.partial
      default:
        return undefined
    }
  }

  // One URL write for several params (two `setFilter` calls in a row would
  // each start from the same URL, and the second would undo the first).
  const patchUrl = (remove: string[]) => {
    const next = new URLSearchParams(window.location.search)
    for (const name of [...remove, 'page']) next.delete(name)
    replaceUrlSearch(next)
  }
  /** The filters that show as chips (Add filter, and the scan a link named). */
  const CHIP_PARAMS = ['kind', 'scan_id']
  const clearChipFilters = () => patchUrl(CHIP_PARAMS)
  /** Everything that narrows the list: the chips and the two selects. */
  const clearFilters = () => patchUrl([...CHIP_PARAMS, 'status', 'origin'])

  // The scan a link narrowed the list to, by its name once a listed run
  // carries it.
  const scanName = scanFilter ? runs.find((r) => r.scan_id === scanFilter)?.scan_name : undefined
  // From 768 px Origin and Status are the toolbar's own selects, so they are
  // not chips; on a phone the selects are in the filter sheet and their
  // values show as chips, so the toolbar holds no control that a chip could
  // push aside.
  const chipList: { key: string; text: string; removeLabel?: string; clear: () => void }[] = [
    ...(isPhone && originFilter !== DEFAULT_RUN_ORIGIN
      ? [
          {
            key: 'origin',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.runs.filterOrigin'),
              value: t(`scans.runOriginFilter.${originFilter}`),
            }),
            clear: () => setFilter('origin', DEFAULT_RUN_ORIGIN),
          },
        ]
      : []),
    ...(isPhone && statusFilter !== 'all'
      ? [
          {
            key: 'status',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.runs.colStatus'),
              value: t(`scans.runStatus.${statusFilter}`),
            }),
            clear: () => setStatus('all'),
          },
        ]
      : []),
    ...(scanFilter
      ? [
          {
            key: 'scan_id',
            text: scanName
              ? t('scans.filter.chip', '{field}: {value}', {
                  field: t('scans.runs.colScan'),
                  value: scanName,
                })
              : t('scans.runs.oneScan'),
            removeLabel: t('scans.runs.showAllScans'),
            clear: () => setFilter('scan_id', ''),
          },
        ]
      : []),
    ...(kindFilter !== 'all'
      ? [
          {
            key: 'kind',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.runs.kind', 'Kind'),
              value: t(`scans.runKindFilter.${kindFilter}`),
            }),
            clear: () => setFilter('kind', 'all'),
          },
        ]
      : []),
  ]
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="runs-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={
              c.removeLabel ??
              t('scans.filter.remove', 'Remove filter {filter}', { filter: c.text })
            }
          />
        ))}
        onClearAll={chipList.length > 1 ? (isPhone ? clearFilters : clearChipFilters) : undefined}
      />
    ) : undefined

  const activeFiltersCount = [
    statusFilter !== 'all',
    kindFilter !== 'all',
    originFilter !== DEFAULT_RUN_ORIGIN,
    scanFilter !== '',
  ].filter(Boolean).length

  // Filters are single-valued in the list's URL, so each section behaves like
  // a radio group: ticking an option replaces the previous one, unticking
  // returns to the default. `withSelects`: the phone sheet also holds Origin
  // and Status (the toolbar's two selects), with the counters of the metric
  // strip; the Add filter popover holds only what the toolbar does not
  // already show.
  const facetPanel = (withSelects: boolean) => (
    <FacetPanel
      activeCount={withSelects ? activeFiltersCount : chipList.length}
      onClearAll={withSelects ? clearFilters : clearChipFilters}
    >
      {withSelects && (
        <FacetSection
          title={t('scans.runs.filterOrigin')}
          selectedCount={originFilter !== DEFAULT_RUN_ORIGIN ? 1 : 0}
        >
          {RUN_ORIGIN_FILTERS.map((f) => (
            <FacetOption
              key={f.value}
              label={t(`scans.runOriginFilter.${f.value}`)}
              checked={originFilter === f.value}
              onCheckedChange={(on) => setFilter('origin', on ? f.value : DEFAULT_RUN_ORIGIN)}
            />
          ))}
        </FacetSection>
      )}
      {withSelects && (
        <FacetSection
          title={t('scans.runs.colStatus')}
          selectedCount={statusFilter !== 'all' ? 1 : 0}
        >
          {RUN_STATUS_FILTERS.filter((f) => f.value !== 'all').map((f) => (
            <FacetOption
              key={f.value}
              label={
                <CountedLabel
                  label={t(`scans.runStatus.${f.value}`)}
                  count={statusCount(f.value)}
                />
              }
              checked={statusFilter === f.value}
              onCheckedChange={(on) => setStatus(on ? f.value : 'all')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('scans.runs.kind', 'Kind')}
        selectedCount={kindFilter !== 'all' ? 1 : 0}
      >
        {RUN_KIND_FILTERS.filter((f) => f.value !== 'all').map((f) => (
          <FacetOption
            key={f.value}
            label={t(`scans.runKindFilter.${f.value}`)}
            checked={kindFilter === f.value}
            onCheckedChange={(on) => setFilter('kind', on ? f.value : 'all')}
          />
        ))}
      </FacetSection>
    </FacetPanel>
  )

  // The toolbar row: Add filter (it never changes size), then the list's two
  // fixed selects, each in a box as wide as its longest value, so choosing a
  // value moves nothing.
  const selects = (
    <>
      <FilterSelect<RunOriginFilterValue>
        clearable={false}
        foldLabel
        label={t('scans.runs.filterOrigin')}
        value={originFilter}
        options={RUN_ORIGIN_FILTERS.map((f) => ({
          value: f.value,
          label: t(`scans.runOriginFilter.${f.value}`),
        }))}
        onChange={(v) => setFilter('origin', v || DEFAULT_RUN_ORIGIN)}
      />
      <FilterSelect<RunStatusFilterValue>
        clearable={false}
        foldLabel
        label={t('scans.runs.colStatus')}
        value={statusFilter}
        options={RUN_STATUS_FILTERS.map((f) => ({
          value: f.value,
          label: t(`scans.runStatus.${f.value}`),
          count: statusCount(f.value),
        }))}
        onChange={(v) => setStatus(v || 'all')}
      />
    </>
  )

  const toolbarStart = (
    <>
      <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
      {!isPhone && selects}
    </>
  )

  // People's runs are the default view, not a filter someone set; an
  // empty list there with runs on the counters still says "no match".
  const filtered =
    statusFilter !== 'all' ||
    kindFilter !== 'all' ||
    originFilter !== DEFAULT_RUN_ORIGIN ||
    scanFilter !== ''
  // The counters count every run the tenant has; a list that is empty while
  // they are not (a filter held back by the URL, a page past the end) must
  // not claim that no run ever started.
  const hasRuns = (counts?.total ?? 0) > 0
  const emptyIsFiltered = filtered || hasRuns

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
        origin: filters.origin,
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

  const refresh = () => {
    void mutate()
    void mutateStats()
  }
  const refreshing = isValidating || isValidatingStats
  const refreshLabel = t('scans.runs.refresh', 'Refresh')
  const exportLabel = t('scans.runs.exportCsv')
  const nothingToExport = !data?.total
  // The list's own actions. From 768 px: Refresh and Export as buttons. On a
  // phone the same two are the items of one More, so the row keeps its room
  // for the view name and the count.
  const moreItems: ActionMenuEntry[] = [
    { id: 'refresh', label: refreshLabel, icon: RefreshCw, onSelect: refresh },
    {
      id: 'export',
      label: exportLabel,
      icon: Download,
      disabledReason: exporting
        ? t('scans.runs.exportRunning', 'The export is already running.')
        : nothingToExport
          ? t('scans.runs.exportNothing', 'There are no runs to export.')
          : undefined,
      onSelect: () => void exportRuns(),
    },
  ]
  const viewTitle = t(`scans.runs.view.${originFilter}`)
  // One name whatever the view: the button is the same control in every view.
  const moreLabel = t('scans.runs.more', 'More actions')

  const noAccess = accessStateOf(error) === 'no_access'
  const strip = <MetricStrip loading={isLoadingStats} items={metrics} />
  const total = data?.total ?? 0

  return (
    // Fragment: the strip, the title row and the table are blocks of the
    // page's PageStack, which owns the gaps between them (research/244).
    <>
      {/* On a phone the list comes first: the strip follows it, and the
          same counts are beside each Status value in the filter sheet. */}
      {!isPhone && strip}

      <ListTitleRow
        title={viewTitle}
        count={
          <ListCount
            total={total}
            loading={!data}
            label={t('scans.runs.total', '{count, plural, one {# run} other {# runs}}', {
              count: total,
            })}
          />
        }
      >
        <div className="flex items-center gap-2 max-md:hidden">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                onClick={refresh}
                disabled={refreshing}
                aria-label={refreshLabel}
              >
                <RefreshCw
                  className={cn('h-4 w-4', refreshing && 'animate-spin motion-reduce:animate-none')}
                  aria-hidden
                />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{refreshLabel}</TooltipContent>
          </Tooltip>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void exportRuns()}
            disabled={exporting || nothingToExport}
            aria-busy={exporting}
          >
            <Download
              className={cn('h-4 w-4', exporting && 'animate-pulse motion-reduce:animate-none')}
              aria-hidden
            />
            {exportLabel}
          </Button>
        </div>
        <div className="md:hidden">
          <ActionMenu
            title={viewTitle}
            label={moreLabel}
            items={moreItems}
            trigger={
              <Button variant="outline" size="icon" aria-label={moreLabel}>
                <MoreHorizontal aria-hidden />
              </Button>
            }
          />
        </div>
      </ListTitleRow>

      {noAccess ? (
        <NoAccessState title={t('scans.runs.listName', 'the run list')} />
      ) : (
        <div
          data-slot="runs-list"
          data-held={heldRows.held ? 'true' : undefined}
          {...heldRows.bind}
        >
          <DataTable
            columns={columns}
            data={runs}
            // A failed read keeps the toolbar and filters; the error takes
            // the rows' place with a Retry (one message, no toast).
            error={error}
            onRetry={() => void mutate()}
            errorTitle={t('scans.runs.listName', 'the run list')}
            // The first read: skeleton rows under a toolbar that stays mounted.
            isLoading={isLoading && !data}
            isRefreshing={isValidating && !!data}
            refreshingLabel={t('scans.runs.refreshing', 'Refreshing runs')}
            showSearch={false}
            // One filter entry per width: Add filter from 768, this button
            // on a phone, where it opens every filter in a sheet.
            filterToggle={{
              open: false,
              onToggle: () => setFilterSheetOpen(true),
              onOpenSheet: () => setFilterSheetOpen(true),
              activeCount: activeFiltersCount,
              controlsId: 'scan-run-filters',
              label: t('scans.runs.filtersLabel', 'Run filters'),
              sheetOnly: true,
            }}
            toolbarStart={toolbarStart}
            toolbarBelow={chipsRow}
            getRowId={getRunId}
            onRowClick={(r) => setOpenRunId(r.id)}
            manualPagination
            rowCount={total}
            pageCount={data?.total_pages}
            pagination={pagination}
            onPaginationChange={list.setPagination}
            pageSize={perPage}
            sorting={sorting}
            onSortingChange={list.setSorting}
            paginationNoun={t('scans.runs.noun')}
            isFiltered={emptyIsFiltered}
            // Nothing to clear when the default view is empty while the
            // counters show runs (the platform's own): the words say so.
            onClearFilters={filtered ? clearFilters : undefined}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={ListChecks}
                  title={t('scans.runs.empty')}
                  description={t('scans.runs.emptyHint')}
                />
              ),
              noMatch: {
                title: t('scans.runs.emptyFiltered'),
                hint: t('scans.runs.tryOther'),
              },
            }}
          />
        </div>
      )}

      {isPhone && strip}

      {/* Under the list, so the list's header never moves when a filter
          hides or shows this line. */}
      {systemRunCount > 0 && (
        <p
          className="text-sm text-muted-foreground"
          role="status"
          data-testid="coverage-runs-summary"
        >
          {t('scans.runs.coverageSummary', undefined, { count: systemRunCount })}{' '}
          <Button
            variant="link"
            className="h-auto p-0 text-sm"
            onClick={() => setFilter('origin', 'system')}
          >
            {t('scans.runs.showSystemRuns')}
          </Button>{' '}
          <Link
            href={COVERAGE_SETTINGS_HREF}
            className="text-primary underline-offset-4 hover:underline"
          >
            {t('scans.runs.openCoverage')}
          </Link>
        </p>
      )}

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title={t('scans.runs.filtersLabel', 'Run filters')}
      >
        {facetPanel(true)}
      </FilterSheet>

      <LazyRunDetailSheet runId={openRunId} onOpenChange={(o) => !o && closeRun()} />
    </>
  )
}
