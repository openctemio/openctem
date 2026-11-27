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
  CellText,
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
import { formatScanDate } from '@/features/scans/lib/format'
import {
  DEFAULT_RUN_ORIGIN,
  IDLE_RUN_LIST_REFRESH_MS,
  RUN_KIND_FILTERS,
  RUN_ORIGIN_FILTERS,
  type RunOriginFilterValue,
  isRunInProgress,
  liveRunIds,
  runListRefreshInterval,
  runKindQuery,
  runOriginQuery,
  runTriggeredByLabel,
  runTriggerTypeLabel,
} from '@/features/scans/lib/run-display'
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
import { RunScanCell, RunStateLine, RunTasksText, runDurationText } from './scan-run-cells'
import { ScanRunMobileCard } from './scan-run-mobile-card'
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
 * by, then Tasks, then Duration (both are on the run's own sheet). A phone
 * shows `ScanRunMobileCard` instead. With the name's floor (200) the whole set
 * fits the frame of a 1440 screen (1114); without the first two, the frame of
 * a 1280 screen (954); without Tasks, a 1024 screen with the sidebar closed;
 * without Duration too, a 768 tablet and a 1024 screen with the sidebar open,
 * so the table never scrolls sideways.
 */
const RUNS_WIDTH = {
  status: 176,
  intensity: 120,
  tasks: 152,
  findings: 88,
  duration: 104,
  // "Nov 25, 09:58 AM" whole at 14px, plus the cell padding.
  started: 152,
  // Who started it wraps (an e-mail at its separators, two lines at most):
  // room for a whole address on a wide frame, down to 116 on a narrow one.
  trigger: 208,
}
const RUNS_HIDE_BELOW = { intensity: 1100, trigger: 1000, tasks: 900, duration: 780 } as const

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
        // The state, then why (what the targets held back, the run's
        // message), cut to the column.
        cell: ({ row }) => <RunStateLine run={row.original} />,
      },
      {
        id: 'tasks',
        meta: {
          kind: 'text',
          width: RUNS_WIDTH.tasks,
          hideBelow: RUNS_HIDE_BELOW.tasks,
          label: t('scans.runs.colTasks'),
        },
        header: t('scans.runs.colTasks'),
        enableSorting: false,
        cell: ({ row }) => <RunTasksText run={row.original} />,
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
        meta: {
          kind: 'text',
          width: RUNS_WIDTH.duration,
          hideBelow: RUNS_HIDE_BELOW.duration,
          label: t('scans.runs.colDuration'),
        },
        header: t('scans.runs.colDuration'),
        enableSorting: false,
        cell: ({ row }) => {
          const d = runDurationText(row.original, t)
          if (!d || d.state === 'waiting')
            return <CellText className="text-xs text-muted-foreground">{d ? d.text : '-'}</CellText>
          return d.state === 'live' ? (
            <CellText className="text-sm text-muted-foreground tabular-nums">{d.text}</CellText>
          ) : (
            <span className="text-sm tabular-nums">{d.text}</span>
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
          minWidth: 116,
          hideBelow: RUNS_HIDE_BELOW.trigger,
          label: t('scans.runs.colTriggeredBy'),
        },
        header: t('scans.runs.colTriggeredBy'),
        enableSorting: false,
        cell: ({ row }) => {
          const who =
            runTriggeredByLabel(row.original, t) ??
            runTriggerTypeLabel(row.original.trigger_type, t)
          return <CellText className="text-sm text-muted-foreground">{who}</CellText>
        },
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
  // The list's own actions. From 768 px: Refresh and Export as buttons in the
  // title row. On a phone the same two are the items of one More at the end
  // of the toolbar row.
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
  const strip = <MetricStrip loading={isLoadingStats} items={metrics} listFirst />
  const total = data?.total ?? 0

  return (
    // Fragment: the strip, the title row and the table are blocks of the
    // page's PageStack, which owns the gaps between them (research/244).
    <>
      {/* On a phone the list comes first: the strip follows it (CSS order,
          so it never jumps after hydration), and the same counts are beside
          each Status value in the filter sheet. */}
      {strip}

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
            // Phone: Refresh and Export are one More beside Filters, so the
            // title row keeps the view name and the count only.
            toolbarEnd={
              isPhone ? (
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
              ) : undefined
            }
            toolbarBelow={chipsRow}
            getRowId={getRunId}
            onRowClick={(r) => setOpenRunId(r.id)}
            // A phone card with fixed slots (state and reason on one line),
            // not the automatic label/value card.
            mobileRow={(r, selection) => (
              <ScanRunMobileCard
                run={r}
                selection={selection}
                onOpen={(run) => setOpenRunId(run.id)}
              />
            )}
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
