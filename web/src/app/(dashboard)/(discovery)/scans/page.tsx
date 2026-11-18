'use client'

import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { IntensityBadge } from '@/features/scans/components/intensity-badge'
import * as React from 'react'
import { useState, useMemo, useCallback, useEffect } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import { ErrorState } from '@/features/shared/components/error-state'
import { SensorOptInBanner } from '@/features/sensors/components/sensor-opt-in-banner'
import { ScanWindowsBanner } from '@/features/scan-windows'
import {
  MetricStrip,
  type MetricStripItem,
  PageStack,
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  FacetPanel,
  FacetSection,
  FacetOption,
  FilterSheet,
} from '@/features/shared'
import type { DataTableBulk } from '@/features/shared/components/data-table/data-table-selection'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import {
  ConfirmDialog,
  ConfirmSample,
  irreversibleTypeToConfirm,
} from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { ScheduleOnConfirm } from '@/features/scans/components/schedule-on-confirm'
import { useTranslation } from '@/context/i18n-provider'
import { toast } from 'sonner'
import {
  MoreHorizontal,
  Eye,
  Pause,
  Play,
  Trash2,
  XCircle,
  Copy,
  Pencil,
  Tag,
  Loader2,
  Radar,
  RefreshCw,
  SearchX,
} from 'lucide-react'
import { accessStateOf } from '@/lib/api/access-state'
import { cn } from '@/lib/utils'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useListParams } from '@/hooks/use-list-params'
import { replaceUrlSearch, useUrlParams } from '@/hooks/use-url-param'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  useScanConfigs,
  useScanConfigStats,
  useBulkActivateScanConfigs,
  useBulkPauseScanConfigs,
  useBulkDisableScanConfigs,
  useBulkDeleteScanConfigs,
  invalidateScanConfigsCache,
} from '@/lib/api/scan-hooks'
import { post, del } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { scanEndpoints } from '@/lib/api/endpoints'
// Note: useAssetGroups can be imported when CreateConfigDialog is implemented
// import { useAssetGroups } from "@/lib/api/security-hooks";
import { SCHEDULE_TYPES } from '@/lib/api/scan-types'
import type {
  ScanConfig,
  ScanConfigStatus,
  ScanOrigin,
  ScanType as ApiScanType,
  ScheduleType,
} from '@/lib/api/scan-types'
import {
  LazyCloneScanDialog,
  LazyEditScanDialog,
  LazyRunDetailSheet,
} from '@/features/scans/components/lazy-dialogs'
import {
  ScanCreateActions,
  ScansPageHeader,
  ScansSectionTabs,
} from '@/features/scans/components/scans-section-tabs'
import { ScanConfigDetailSheet } from '@/features/scans/components/scan-config-detail-sheet'
import { LastRunCell } from '@/features/scans/components/last-run-cell'
import { ManagedScansSection } from '@/features/scans/components/managed-scans-section'
import { RunHistory } from '@/features/scans/components/run-history'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { ScanMobileCard } from '@/features/scans/components/scan-mobile-card'
import { ScanNameCell } from '@/features/scans/components/scan-name-cell'
import { ScheduleCell } from '@/features/scans/components/schedule-cell'
import { scheduleTypeName } from '@/features/scans/lib/labels'
import { isManagedScan, lastRunOf, scanTypeLabel } from '@/features/scans/lib/scan-status'
import { useScanTrigger } from '@/features/scans/hooks/use-scan-trigger'
import { ScanQueryChip, useScanQueryMode } from '@/features/scans/components/scan-query-bar'
import {
  DEFAULT_SCAN_CONFIG_SORT,
  DEFAULT_SCAN_PAGE_SIZE,
  SCAN_CONFIG_SORT_FIELDS,
  SCAN_PAGE_SIZES,
} from '@/features/scans/lib/scans-url'

// ============================================
// CONFIGURATIONS TAB TYPES
// ============================================

type ConfigStatusFilter = ScanConfigStatus | 'all'
// Whose scans: people's, or the platform's managed ones (continuous coverage).
type ConfigOriginFilter = ScanOrigin | 'all'
type ConfigTypeFilter = ApiScanType | 'all'

// The configuration's state, not a run state: an enabled scan runs on its
// schedule (if it has one), a paused one only when someone runs it. The
// labels are the metric strip's.
const CONFIG_STATES: { value: ScanConfigStatus; labelKey: string }[] = [
  { value: 'active', labelKey: 'scans.configs.metricEnabled' },
  { value: 'paused', labelKey: 'scans.configs.metricPaused' },
  { value: 'disabled', labelKey: 'scans.configs.metricDisabled' },
]

const CONFIG_ORIGINS: { value: ScanOrigin; labelKey: string }[] = [
  { value: 'user', labelKey: 'scans.origin.user' },
  { value: 'system', labelKey: 'scans.origin.system' },
]

const CONFIG_TYPES: { value: ApiScanType; labelKey: string }[] = [
  { value: 'workflow', labelKey: 'scans.scanType.workflow' },
  { value: 'single', labelKey: 'scans.scanType.single' },
]

type ConfigScheduleFilter = ScheduleType | 'all'

/**
 * Column widths (px) and the table-frame width under which a column steps
 * aside (it stays under Display > Columns): Intensity first, then Recent
 * runs. The name, the type, the latest run, the run count and the schedule
 * always show, and with the name's floor (200) they fit the frame of a 1280
 * screen (954), so the row menu is on screen without scrolling sideways.
 */
const SCANS_WIDTH = { type: 160, intensity: 120, lastRun: 200, recentRuns: 136, schedule: 208 }
const SCANS_HIDE_BELOW = { intensity: 1220, recentRuns: 1090 } as const

// ============================================
// MAIN PAGE COMPONENT
// ============================================

export default function ScansPage() {
  return (
    <Main>
      {/* PageStack owns every gap (research/244): an optional banner that
          renders nothing leaves no gap, so the strip sits 20px under the tabs
          on every Scans tab. */}
      <PageStack>
        <ScansPageHeader>
          <ScanCreateActions />
        </ScansPageHeader>
        <ScansSectionTabs />
        <ScanWindowsBanner />
        <SensorOptInBanner />
        <ConfigurationsTab />
      </PageStack>
    </Main>
  )
}

// ============================================
// CONFIG ACTIONS CELL (simplified - no hooks to prevent re-renders)
// ============================================

type ConfigAction = 'trigger' | 'pause' | 'activate' | 'delete' | 'clone' | 'edit'

interface ConfigActionsCellProps {
  config: ScanConfig
  onAction: (action: ConfigAction, config: ScanConfig) => void
  /** This scan's trigger is in flight: a second click must not start another run. */
  triggering?: boolean
}

function ConfigActionsCell({ config, onAction, triggering = false }: ConfigActionsCellProps) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  // A platform policy owns a managed scan: nothing to edit, run, pause or
  // delete here. View it, or clone it into a scan of your own.
  const managed = isManagedScan(config)
  const canWrite = can(Permission.ScansWrite)
  const items: ActionMenuEntry[] = [
    {
      id: 'view',
      label: t('scans.row.view'),
      icon: Eye,
      href: `/scans/${config.id}`,
    },
    ...(!managed && canWrite
      ? [
          {
            id: 'edit',
            label: t('scans.row.edit'),
            icon: Pencil,
            onSelect: () => onAction('edit', config),
          },
        ]
      : []),
    // Trigger, clone, pause and resume all need scans:write.
    ...(canWrite && !managed
      ? [
          {
            id: 'run',
            label: triggering ? t('scans.row.starting') : t('scans.row.run'),
            icon: triggering ? Loader2 : Play,
            disabledReason: triggering
              ? t('scans.row.startingReason', 'This scan is already starting.')
              : undefined,
            onSelect: () => onAction('trigger', config),
          },
        ]
      : []),
    ...(canWrite
      ? [
          {
            id: 'clone',
            label: managed ? t('scans.managed.clone') : t('scans.row.clone'),
            icon: Copy,
            onSelect: () => onAction('clone', config),
          },
        ]
      : []),
    ...(canWrite && !managed && config.status === 'active'
      ? [
          {
            id: 'pause',
            section: 'state',
            label: t('scans.row.pause'),
            icon: Pause,
            onSelect: () => onAction('pause', config),
          },
        ]
      : []),
    ...(canWrite && !managed && config.status === 'paused'
      ? [
          {
            id: 'resume',
            section: 'state',
            label: t('scans.row.resume'),
            icon: Play,
            onSelect: () => onAction('activate', config),
          },
        ]
      : []),
    ...(!managed && can(Permission.ScansDelete)
      ? [
          {
            id: 'delete',
            label: t('scans.row.delete'),
            icon: Trash2,
            destructive: true,
            onSelect: () => onAction('delete', config),
          },
        ]
      : []),
  ]
  const label = t('common.actionMenu.label', 'Actions for {name}', { name: config.name })
  return (
    <ActionMenu
      title={config.name}
      label={label}
      items={items}
      trigger={
        <Button variant="ghost" size="icon-sm" className="p-0" aria-label={label}>
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      }
    />
  )
}

// ============================================
// CONFIGURATIONS TAB
// ============================================

function ConfigurationsTab() {
  const [selectedConfig, setSelectedConfig] = useState<ScanConfig | null>(null)
  // The whole view lives in the URL so a filtered list can be shared or
  // bookmarked: plain page / per_page / sort / q and field-named filters
  // (useListParams). Paged and sorted on the server.
  const list = useListParams({
    pageSizes: SCAN_PAGE_SIZES,
    defaultPageSize: DEFAULT_SCAN_PAGE_SIZE,
    sortFields: SCAN_CONFIG_SORT_FIELDS,
    defaultSort: DEFAULT_SCAN_CONFIG_SORT,
    filters: {
      status: 'all',
      type: 'all',
      schedule: 'all',
      origin: 'all',
      tag: '',
      one_off: '',
      fq: '',
    },
  })
  const urlParams = useUrlParams()
  // A filter the controls cannot show, as query text (the scans query bar).
  const fqFilter = list.filters.fq
  const searchQuery = list.q
  const setSearchQuery = list.setSearch
  const debouncedSearch = useSearchQuery(searchQuery).term
  const statusFilter = list.filters.status as ConfigStatusFilter
  const setStatusFilter = (v: ConfigStatusFilter) => list.setFilter('status', v)
  const typeFilter = list.filters.type as ConfigTypeFilter
  const setTypeFilter = (v: ConfigTypeFilter) => list.setFilter('type', v)
  const scheduleFilter = list.filters.schedule as ConfigScheduleFilter
  const setScheduleFilter = (v: ConfigScheduleFilter) => list.setFilter('schedule', v)
  const originFilter = list.filters.origin as ConfigOriginFilter
  const setOriginFilter = (v: ConfigOriginFilter) => list.setFilter('origin', v)
  const tagFilter = list.filters.tag
  const setTagFilter = (v: string) => list.setFilter('tag', v)
  const debouncedTag = useSearchQuery(tagFilter, { minChars: 1 }).term
  // One-off (quick) scans are hidden unless asked for.
  const oneOffParam = list.filters.one_off
  const setOneOffParam = (v: string) => list.setFilter('one_off', v)
  const showOneOff = oneOffParam === '1'
  const { page: pageParam, setPage: setPageParam, perPage, sorting } = list
  // Selection is owned by the DataTable; we mirror the selected ids for the
  // bulk-action bar and bump the epoch to clear the table's own checkboxes.
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectedIds([])
    setSelectionEpoch((e) => e + 1)
  }, [])
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const { can } = usePermissions()
  const canWrite = can(Permission.ScansWrite)
  const canDelete = can(Permission.ScansDelete)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [bulkDeleteConfirmOpen, setBulkDeleteConfirmOpen] = useState(false)
  const [bulkDisableConfirmOpen, setBulkDisableConfirmOpen] = useState(false)
  // Bulk Activate / Pause ask first (activate starts scans, pause is bulk).
  const [bulkConfirm, setBulkConfirm] = useState<'activate' | 'pause' | null>(null)
  // Resume from the row menu starts scheduled scans: ask first.
  const [configToResume, setConfigToResume] = useState<ScanConfig | null>(null)
  const { t } = useTranslation()
  const [configToDelete, setConfigToDelete] = useState<ScanConfig | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [configToClone, setConfigToClone] = useState<ScanConfig | null>(null)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [configToEdit, setConfigToEdit] = useState<ScanConfig | null>(null)
  // Opened from the "a run is already in progress" question.
  const [openRunId, setOpenRunId] = useState<string | null>(null)
  const {
    trigger: triggerScan,
    isTriggering,
    dialog: triggerDialog,
  } = useScanTrigger({ onViewRun: setOpenRunId })

  // Memoize filter object to prevent unnecessary re-renders
  const filters = useMemo(
    () => ({
      status: statusFilter !== 'all' ? statusFilter : undefined,
      scan_type: typeFilter !== 'all' ? typeFilter : undefined,
      schedule_type: scheduleFilter !== 'all' ? scheduleFilter : undefined,
      origin: originFilter !== 'all' ? originFilter : undefined,
      tag: debouncedTag || undefined,
      q: debouncedSearch || undefined,
      fq: fqFilter || undefined,
      include_ad_hoc: showOneOff || undefined,
      sort: list.sort,
      page: pageParam,
      per_page: perPage,
    }),
    [
      statusFilter,
      typeFilter,
      scheduleFilter,
      originFilter,
      debouncedTag,
      debouncedSearch,
      fqFilter,
      showOneOff,
      list.sort,
      pageParam,
      perPage,
    ]
  )

  // API hooks with stable configuration
  const swrConfig = useMemo(
    () => ({
      revalidateOnFocus: false,
      revalidateOnReconnect: false,
      refreshInterval: 0,
      dedupingInterval: 5000,
      // Keep the current page on screen while the next one loads.
      keepPreviousData: true,
    }),
    []
  )

  const {
    data: configsResponse,
    isLoading: isLoadingConfigs,
    isValidating: isValidatingConfigs,
    error: configsError,
    mutate: retryConfigs,
  } = useScanConfigs(filters, swrConfig)
  const {
    data: stats,
    isLoading: isLoadingStats,
    error: statsError,
    mutate: retryStats,
  } = useScanConfigStats(swrConfig)

  // Bulk operation hooks
  const { trigger: bulkActivate, isMutating: isActivating } = useBulkActivateScanConfigs()
  const { trigger: bulkPause, isMutating: isPausing } = useBulkPauseScanConfigs()
  const { trigger: bulkDisable, isMutating: isDisabling } = useBulkDisableScanConfigs()
  const { trigger: bulkDelete, isMutating: isBulkDeleting } = useBulkDeleteScanConfigs()
  const isBulkOperating = isActivating || isPausing || isDisabling || isBulkDeleting

  // Memoize configs array with stable reference
  const configs = useMemo((): ScanConfig[] => {
    return configsResponse?.data ?? []
  }, [configsResponse?.data])

  // Sync selectedConfig with latest data from API
  // This ensures the detail popup shows updated status after actions
  useEffect(() => {
    if (selectedConfig && configs.length > 0) {
      const updatedConfig = configs.find((c) => c.id === selectedConfig.id)
      if (updatedConfig && updatedConfig.status !== selectedConfig.status) {
        setSelectedConfig(updatedConfig)
      }
    }
  }, [configs, selectedConfig])

  // A page past the end (the last scan on it was deleted, or a stale link)
  // goes to the last page that exists.
  const totalPages = configsResponse?.total_pages ?? 0
  useEffect(() => {
    if (configsResponse && pageParam > 1 && configsResponse.data.length === 0) {
      setPageParam(Math.max(1, totalPages))
    }
  }, [configsResponse, pageParam, totalPages, setPageParam])

  // The search field's Query mode (the same filter as query text).
  const queryMode = useScanQueryMode(urlParams, replaceUrlSearch, configsResponse?.total)

  // Narrowing the list starts again at page 1 (page 3 of the old result may
  // not exist in the new one). Skipped on mount so a shared link keeps its page.
  const filterKey = [
    statusFilter,
    typeFilter,
    scheduleFilter,
    originFilter,
    debouncedTag,
    debouncedSearch,
    fqFilter,
    oneOffParam,
  ].join('\u0000')
  const lastFilterKey = React.useRef(filterKey)
  useEffect(() => {
    if (lastFilterKey.current === filterKey) return
    lastFilterKey.current = filterKey
    setPageParam(1)
  }, [filterKey, setPageParam])

  // A selection belongs to the rows on screen: another page, filter or sort
  // clears it.
  useEffect(() => {
    clearSelection()
  }, [filters, clearSelection])

  // The Schedule column's switch: pause turns the schedule off, resume on.
  const handleToggle = useCallback(
    async (action: 'pause' | 'activate', config: ScanConfig) => {
      const endpoint =
        action === 'pause' ? scanEndpoints.pause(config.id) : scanEndpoints.activate(config.id)
      try {
        await post(endpoint, {})
      } catch (error) {
        toast.error(
          getErrorMessage(error, t('scans.toast.scheduleFailed', undefined, { name: config.name }))
        )
        throw error
      }
      toast.success(
        t(action === 'pause' ? 'scans.toast.scheduleOff' : 'scans.toast.scheduleOn', undefined, {
          name: config.name,
        })
      )
      await invalidateScanConfigsCache()
    },
    [t]
  )

  const handleAction = useCallback(
    async (action: ConfigAction, config: ScanConfig) => {
      // For delete, show confirmation dialog first
      if (action === 'delete') {
        setConfigToDelete(config)
        setDeleteConfirmOpen(true)
        return
      }

      // For clone, show clone dialog
      if (action === 'clone') {
        setConfigToClone(config)
        setCloneDialogOpen(true)
        return
      }

      // For edit, show edit dialog
      if (action === 'edit') {
        setConfigToEdit(config)
        setEditDialogOpen(true)
        return
      }

      // Resume turns the schedule on, which starts scans: ask first.
      if (action === 'activate') {
        setConfigToResume(config)
        return
      }

      // Trigger asks first (and again when a run is already in progress) and
      // ignores a second click while the first is in flight (useScanTrigger).
      if (action === 'trigger') {
        await triggerScan(config)
        return
      }

      try {
        switch (action) {
          case 'pause':
            await post(scanEndpoints.pause(config.id), {})
            toast.success(t('scans.toast.paused', undefined, { name: config.name }))
            break
        }
        // Invalidate caches to refresh the list
        await invalidateScanConfigsCache()
      } catch (error) {
        console.error(`Failed to ${action} scan:`, error)
        toast.error(
          getErrorMessage(error, t('scans.toast.pauseFailed', undefined, { name: config.name }))
        )
      }
    },
    [triggerScan, t]
  )

  // Confirmed Resume (row menu): the same call the schedule switch makes.
  const confirmResume = useCallback(async () => {
    const config = configToResume
    if (!config) return
    try {
      await post(scanEndpoints.activate(config.id), {})
      toast.success(t('scans.toast.activated', undefined, { name: config.name }))
      await invalidateScanConfigsCache()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('scans.toast.activateFailed', undefined, { name: config.name }))
      )
    }
  }, [configToResume, t])

  const handleConfirmDelete = useCallback(async () => {
    if (!configToDelete) return

    setIsDeleting(true)
    try {
      await del(scanEndpoints.delete(configToDelete.id))
      toast.success(t('scans.toast.deleted', undefined, { name: configToDelete.name }))
      setSelectedConfig(null)
      await invalidateScanConfigsCache()
    } catch (error) {
      console.error('Failed to delete scan:', error)
      toast.error(
        getErrorMessage(
          error,
          t('scans.toast.deleteFailed', undefined, { name: configToDelete.name })
        )
      )
    } finally {
      setIsDeleting(false)
      setDeleteConfirmOpen(false)
      setConfigToDelete(null)
    }
  }, [configToDelete, t])

  // The names behind the selected ids that are on the current page, for the
  // confirmation samples (the selection can include other pages).
  const selectedNames = useMemo(() => {
    const picked = new Set(selectedIds)
    return configs.filter((c) => picked.has(c.id)).map((c) => c.name)
  }, [configs, selectedIds])

  // "<Verb> {count} scans" or its one-scan form (key + 'One').
  const bulkCountText = (key: string) =>
    selectedIds.length === 1 ? t(`${key}One`) : t(key, undefined, { count: selectedIds.length })

  // One runner for the four bulk operations: same guard, toast and cleanup.
  const runBulk = useCallback(
    async (
      op: (arg: { scan_ids: string[] }) => Promise<{ message: string } | undefined>,
      failure: string
    ) => {
      if (selectedIds.length === 0) return
      try {
        const result = await op({ scan_ids: selectedIds })
        if (result) {
          toast.success(result.message)
          clearSelection()
          await invalidateScanConfigsCache()
        }
      } catch (error) {
        toast.error(getErrorMessage(error, failure))
      }
    },
    [selectedIds, clearSelection]
  )

  // Table columns - memoized to prevent infinite re-renders
  const columns: ColumnDef<ScanConfig>[] = useMemo(
    () => [
      // Rows are one line. The checkbox column is the table's own (`bulk`).
      {
        accessorKey: 'name',
        // The row's identity: frozen at the start while the table scrolls sideways.
        meta: { kind: 'name', pin: 'start', minWidth: 200, label: t('scans.col.name') },
        enableHiding: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.col.name')} />
        ),
        cell: ({ row }) => (
          <ScanNameCell config={row.original} onOpen={() => setSelectedConfig(row.original)} />
        ),
      },
      {
        accessorKey: 'scan_type',
        meta: { kind: 'text', width: SCANS_WIDTH.type, label: t('scans.col.type') },
        header: t('scans.col.type'),
        enableSorting: false,
        cell: ({ row }) => {
          // What the scan runs (the workflow's name, or a single check's
          // tool), then its kind; the intensity has its own column.
          const { label, kind } = scanTypeLabel(row.original, t)
          const kindLabel =
            kind === 'workflow' ? t('scans.scanType.workflow') : t('scans.scanType.single')
          return (
            <div
              className="flex min-w-0 items-baseline gap-2 whitespace-nowrap"
              title={`${label} (${kindLabel})`}
            >
              <span className="min-w-0 truncate text-sm">{label}</span>
              <span className="shrink-0 text-xs text-muted-foreground">{kindLabel}</span>
            </div>
          )
        },
      },
      {
        id: 'intensity',
        accessorKey: 'intensity',
        meta: {
          kind: 'status',
          width: SCANS_WIDTH.intensity,
          hideBelow: SCANS_HIDE_BELOW.intensity,
          label: t('scans.intensity.label'),
        },
        header: t('scans.intensity.label'),
        enableSorting: false,
        cell: ({ row }) => <IntensityBadge intensity={row.original.intensity} />,
      },
      {
        // The real latest run, never the configuration's enabled flag.
        id: 'last_run_at',
        accessorKey: 'last_run_at',
        meta: {
          kind: 'text',
          width: SCANS_WIDTH.lastRun,
          sortFirst: 'desc',
          label: t('scans.col.lastRun'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.col.lastRun')} />
        ),
        cell: ({ row }) => (
          <LastRunCell run={lastRunOf(row.original)} onOpen={setOpenRunId} showHint inline />
        ),
      },
      {
        // The latest runs as glyphs and the success rate over them: partial
        // runs (coverage gaps on the target side) count as successes, blocked
        // and canceled runs are left out (lib/run-history.ts).
        id: 'recent_runs',
        meta: {
          kind: 'text',
          width: SCANS_WIDTH.recentRuns,
          hideBelow: SCANS_HIDE_BELOW.recentRuns,
          label: t('scans.col.recentRuns'),
        },
        header: t('scans.col.recentRuns'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.total_runs > 0 ? (
            <RunHistory runs={row.original.recent_runs} />
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        accessorKey: 'total_runs',
        meta: { kind: 'number', label: t('scans.col.runs') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scans.col.runs')} />
        ),
        cell: ({ row }) => <span className="text-sm tabular-nums">{row.original.total_runs}</span>,
      },
      {
        // The schedule and its on/off switch; manual scans have neither.
        accessorKey: 'schedule_type',
        meta: { kind: 'text', width: SCANS_WIDTH.schedule, label: t('scans.col.schedule') },
        header: t('scans.col.schedule'),
        enableSorting: false,
        cell: ({ row }) => <ScheduleCell config={row.original} onToggle={handleToggle} inline />,
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        enableHiding: false,
        cell: ({ row }) => (
          <ConfigActionsCell
            config={row.original}
            onAction={handleAction}
            triggering={isTriggering(row.original.id)}
          />
        ),
      },
    ],
    [handleAction, handleToggle, isTriggering, t]
  )

  const activeFiltersCount = [
    statusFilter !== 'all',
    typeFilter !== 'all',
    scheduleFilter !== 'all',
    originFilter !== 'all',
    tagFilter !== '',
    fqFilter !== '',
    showOneOff,
  ].filter(Boolean).length

  // One URL write for several params (two `setFilter` calls in a row would
  // each start from the same URL, and the second would undo the first).
  const patchUrl = (remove: string[]) => {
    const next = new URLSearchParams(window.location.search)
    for (const name of [...remove, 'page']) next.delete(name)
    replaceUrlSearch(next)
  }
  /** The filters that show as chips (Add filter and the query text). */
  const CHIP_PARAMS = ['type', 'schedule', 'tag', 'one_off', 'fq']
  const clearChipFilters = () => patchUrl(CHIP_PARAMS)
  /** Everything that narrows the list: chips, the two selects and the search. */
  const clearFilters = () => patchUrl([...CHIP_PARAMS, 'status', 'origin', 'q'])

  const typeLabel = (v: ApiScanType) =>
    t(CONFIG_TYPES.find((s) => s.value === v)?.labelKey ?? '', v)

  // The active filters as chips ("Field: value"), each removable on its own.
  // State and Origin are the toolbar's own selects, so they are not chips.
  const chipList: { key: string; text: string; clear: () => void }[] = [
    ...(typeFilter !== 'all'
      ? [
          {
            key: 'type',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.filter.type', 'Scan type'),
              value: typeLabel(typeFilter),
            }),
            clear: () => setTypeFilter('all'),
          },
        ]
      : []),
    ...(scheduleFilter !== 'all'
      ? [
          {
            key: 'schedule',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.col.schedule'),
              value: scheduleTypeName(t, scheduleFilter),
            }),
            clear: () => setScheduleFilter('all'),
          },
        ]
      : []),
    ...(tagFilter
      ? [
          {
            key: 'tag',
            text: t('scans.filter.chip', '{field}: {value}', {
              field: t('scans.filter.tag', 'Tag'),
              value: tagFilter,
            }),
            clear: () => setTagFilter(''),
          },
        ]
      : []),
    ...(showOneOff
      ? [
          {
            key: 'one_off',
            text: t('scans.filter.oneOffShown', 'One-off scans shown'),
            clear: () => setOneOffParam(''),
          },
        ]
      : []),
  ]
  const removableCount = chipList.length + (fqFilter ? 1 : 0)
  // In Query mode the text owns the filter: the chips step aside.
  const chipsRow =
    !queryMode.active && removableCount > 0 ? (
      <FilterChipsRow
        data-testid="scans-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={[
          ...chipList.map((c) => (
            <RemovableFilterChip
              key={c.key}
              text={c.text}
              onRemove={c.clear}
              removeLabel={t('scans.filter.remove', 'Remove filter {filter}', { filter: c.text })}
            />
          )),
          ...(fqFilter
            ? [
                <ScanQueryChip
                  key="fq"
                  search={urlParams}
                  onOpen={() => queryMode.setActive(true)}
                  onSearchChange={replaceUrlSearch}
                />,
              ]
            : []),
        ]}
        onClearAll={removableCount > 1 ? clearChipFilters : undefined}
      />
    ) : undefined

  // A status metric toggles its filter; "All" clears it.
  const toggleStatus = (value: ConfigStatusFilter) =>
    setStatusFilter(statusFilter === value ? 'all' : value)

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: t('scans.configs.metricAll', 'Configurations'),
      value: stats?.total ?? 0,
      onClick: () => setStatusFilter('all'),
      active: statusFilter === 'all',
    },
    {
      key: 'active',
      label: t('scans.configs.metricEnabled', 'Enabled'),
      value: stats?.active ?? 0,
      onClick: () => toggleStatus('active'),
      active: statusFilter === 'active',
    },
    {
      key: 'paused',
      label: t('scans.configs.metricPaused', 'Schedule paused'),
      value: stats?.paused ?? 0,
      onClick: () => toggleStatus('paused'),
      active: statusFilter === 'paused',
    },
    {
      key: 'disabled',
      label: t('scans.configs.metricDisabled', 'Disabled'),
      value: stats?.disabled ?? 0,
      onClick: () => toggleStatus('disabled'),
      active: statusFilter === 'disabled',
    },
  ]

  // Filters are single-valued in the API, so each section behaves like a radio
  // group: ticking an option replaces the previous one, unticking clears it.
  // `withSelects`: the phone sheet also holds State and Origin (the toolbar's
  // two selects), so every filter is in one place there; the Add filter
  // popover holds only what the toolbar does not already show.
  const facetPanel = (withSelects: boolean) => (
    <FacetPanel
      activeCount={withSelects ? activeFiltersCount : removableCount}
      onClearAll={withSelects ? clearFilters : clearChipFilters}
    >
      {withSelects && (
        <FacetSection
          title={t('scans.filter.state', 'State')}
          selectedCount={statusFilter !== 'all' ? 1 : 0}
        >
          {CONFIG_STATES.map((f) => (
            <FacetOption
              key={f.value}
              label={t(f.labelKey)}
              checked={statusFilter === f.value}
              onCheckedChange={(on) => setStatusFilter(on ? f.value : 'all')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('scans.filter.type', 'Scan type')}
        selectedCount={typeFilter !== 'all' ? 1 : 0}
      >
        {CONFIG_TYPES.map((f) => (
          <FacetOption
            key={f.value}
            label={t(f.labelKey)}
            checked={typeFilter === f.value}
            onCheckedChange={(on) => setTypeFilter(on ? f.value : 'all')}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('scans.col.schedule')}
        selectedCount={scheduleFilter !== 'all' ? 1 : 0}
      >
        {SCHEDULE_TYPES.map((type) => (
          <FacetOption
            key={type}
            label={scheduleTypeName(t, type)}
            checked={scheduleFilter === type}
            onCheckedChange={(on) => setScheduleFilter(on ? type : 'all')}
          />
        ))}
      </FacetSection>
      {withSelects && (
        <FacetSection
          title={t('scans.origin.title')}
          selectedCount={originFilter !== 'all' ? 1 : 0}
        >
          {CONFIG_ORIGINS.map((f) => (
            <FacetOption
              key={f.value}
              label={t(f.labelKey)}
              checked={originFilter === f.value}
              onCheckedChange={(on) => setOriginFilter(on ? f.value : 'all')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('scans.filter.oneOff', 'One-off scans')}
        selectedCount={showOneOff ? 1 : 0}
      >
        <FacetOption
          label={t('scans.filter.oneOffShow', 'Show one-off scans')}
          checked={showOneOff}
          onCheckedChange={(on) => setOneOffParam(on ? '1' : '')}
        />
      </FacetSection>
      <FacetSection title={t('scans.filter.tag', 'Tag')} selectedCount={tagFilter ? 1 : 0}>
        <div className="relative pe-1 pt-1">
          <Tag
            className="pointer-events-none absolute start-2.5 top-1/2 mt-0.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            placeholder={t('scans.filter.tagPlaceholder', 'Filter by tag…')}
            aria-label={t('scans.filter.tagLabel', 'Filter by tag')}
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            className="ps-8 text-sm"
          />
        </div>
      </FacetSection>
    </FacetPanel>
  )

  // The toolbar row after the search: Add filter (it never changes size),
  // then the list's two fixed selects, each in a box as wide as its longest
  // value, so choosing a value moves nothing.
  const toolbarStart = (
    <>
      <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
      <FilterSelect<ConfigStatusFilter>
        label={t('scans.filter.state', 'State')}
        value={statusFilter}
        clearable={false}
        // The key folds away on a narrow toolbar: "All states" still says what it is.
        foldLabel
        options={[
          { value: 'all', label: t('scans.filter.allStates', 'All states'), count: stats?.total },
          ...CONFIG_STATES.map((s) => ({
            value: s.value,
            label: t(s.labelKey),
            count: stats?.[s.value],
          })),
        ]}
        onChange={(v) => setStatusFilter(v || 'all')}
      />
      <FilterSelect<ConfigOriginFilter>
        label={t('scans.origin.title')}
        value={originFilter}
        clearable={false}
        foldLabel
        options={[
          { value: 'all', label: t('scans.filter.allOrigins', 'All origins') },
          ...CONFIG_ORIGINS.map((o) => ({ value: o.value, label: t(o.labelKey) })),
        ]}
        onChange={(v) => setOriginFilter(v || 'all')}
      />
    </>
  )

  const refreshing = isValidatingConfigs || isLoadingStats
  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          onClick={() => {
            void retryConfigs()
            void retryStats()
          }}
          disabled={refreshing}
          aria-label={t('scans.configs.refresh', 'Refresh')}
        >
          <RefreshCw
            className={cn('h-4 w-4', refreshing && 'animate-spin motion-reduce:animate-none')}
            aria-hidden
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{t('scans.configs.refresh', 'Refresh')}</TooltipContent>
    </Tooltip>
  )

  // The bulk bar: two direct actions (Activate, Pause), the rest under More.
  // Each shows only with its permission (the API checks again); with neither
  // permission there is no checkbox column.
  const scansBulk: DataTableBulk<ScanConfig> | undefined =
    canWrite || canDelete
      ? {
          rowLabel: (c) => c.name,
          checkboxLabel: (c) => t('scans.card.select', undefined, { name: c.name }),
          actions: canWrite ? (
            <>
              <Button
                variant="ghost"
                size="sm"
                disabled={isBulkOperating}
                onClick={() => setBulkConfirm('activate')}
              >
                <Play aria-hidden />
                {t('scans.bulk.activate')}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={isBulkOperating}
                onClick={() => setBulkConfirm('pause')}
              >
                <Pause aria-hidden />
                {t('scans.bulk.pause')}
              </Button>
            </>
          ) : null,
          more: [
            ...(canWrite
              ? [
                  {
                    id: 'disable',
                    label: t('scans.bulk.disable'),
                    icon: XCircle,
                    disabledReason: isBulkOperating
                      ? t('scans.bulk.busy', 'Wait for the current change to finish.')
                      : undefined,
                    onSelect: () => setBulkDisableConfirmOpen(true),
                  },
                ]
              : []),
            ...(canDelete
              ? [
                  {
                    id: 'delete',
                    label: t('scans.bulk.delete'),
                    icon: Trash2,
                    destructive: true,
                    disabledReason: isBulkOperating
                      ? t('scans.bulk.busy', 'Wait for the current change to finish.')
                      : undefined,
                    onSelect: () => setBulkDeleteConfirmOpen(true),
                  },
                ]
              : []),
          ],
          onSelectionChange: (selection) =>
            setSelectedIds(selection?.kind === 'ids' ? selection.rows.map((c) => c.id) : []),
        }
      : undefined

  const narrowed = activeFiltersCount > 0 || searchQuery.trim() !== ''
  const noAccess = accessStateOf(configsError) === 'no_access'

  return (
    <>
      {statsError && !stats ? (
        // On a phone the counts follow the list, like the strip they replace.
        <div className="max-md:order-last">
          <ErrorState
            title={t('scans.configs.statsErrorTitle', 'scan counts')}
            error={statsError}
            onRetry={() => void retryStats()}
          />
        </div>
      ) : (
        <MetricStrip loading={isLoadingStats} items={metrics} listFirst />
      )}

      <ListTitleRow
        title={t('scans.configs.viewAll', 'All scan configurations')}
        count={
          <ListCount
            total={configsResponse?.total ?? 0}
            loading={!configsResponse}
            label={t(
              'scans.configs.total',
              '{count, plural, one {# scan configuration} other {# scan configurations}}',
              { count: configsResponse?.total ?? 0 }
            )}
          />
        }
      >
        {refreshButton}
      </ListTitleRow>

      {noAccess ? (
        <NoAccessState title={t('scans.configs.subject', 'the scans list')} />
      ) : (
        <DataTable
          columns={columns}
          data={configs}
          error={configsError}
          onRetry={() => void retryConfigs()}
          errorTitle={t('scans.errorTitle', 'scans')}
          // The first read: skeleton rows under a toolbar that stays mounted.
          isLoading={isLoadingConfigs && !configsResponse}
          isRefreshing={isValidatingConfigs && !!configsResponse}
          refreshingLabel={t('scans.configs.refreshing', 'Refreshing scans')}
          showSearch={false}
          search={{
            value: searchQuery,
            onChange: setSearchQuery,
            placeholder: t('scans.configs.searchPlaceholder', 'Search configurations…'),
            label: t('scans.configs.searchLabel', 'Search scan configurations'),
            query: queryMode.query,
          }}
          // One filter entry per width: Add filter from 768, this button
          // (joined to the search field) on a phone, where it opens the sheet.
          filterToggle={{
            open: false,
            onToggle: () => setFilterSheetOpen(true),
            onOpenSheet: () => setFilterSheetOpen(true),
            activeCount: activeFiltersCount,
            controlsId: 'scan-config-filters',
            label: t('scans.configs.filtersLabel', 'Scan configuration filters'),
            sheetOnly: true,
          }}
          toolbarStart={toolbarStart}
          toolbarBelow={chipsRow}
          manualPagination
          rowCount={configsResponse?.total ?? 0}
          pagination={{ pageIndex: pageParam - 1, pageSize: perPage }}
          onPaginationChange={list.setPagination}
          pageSize={perPage}
          paginationNoun={t('scans.configs.noun', 'scans')}
          sorting={sorting}
          onSortingChange={list.setSorting}
          getRowId={(c) => c.id}
          onRowClick={setSelectedConfig}
          mobileRow={(config, selection) => (
            <ScanMobileCard
              config={config}
              selection={selection}
              onOpen={setSelectedConfig}
              onOpenRun={setOpenRunId}
              actions={
                <ConfigActionsCell
                  config={config}
                  onAction={handleAction}
                  triggering={isTriggering(config.id)}
                />
              }
            />
          )}
          // No bulk action for this user: no checkbox column either.
          bulk={scansBulk}
          resetSelectionKey={selectionEpoch}
          showSelectionCount={false}
          isFiltered={narrowed}
          onClearFilters={clearFilters}
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={Radar}
                title={t('scans.list.empty')}
                description={t('scans.list.emptyHint')}
              />
            ),
            noMatch: (
              <EmptyState
                icon={SearchX}
                title={t('scans.list.emptyFiltered')}
                description={t('scans.list.emptyFilteredHint')}
                action={
                  <Button variant="outline" size="sm" onClick={clearFilters}>
                    {t('common.table.clearFilters', 'Clear filters')}
                  </Button>
                }
              />
            ),
          }}
        />
      )}

      {/* The scans the platform runs itself stay visible, read-only. With the
          origin filter on System the table already lists them. */}
      {originFilter === 'all' && <ManagedScansSection onOpenRun={setOpenRunId} />}

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title={t('scans.configs.filtersLabel', 'Scan configuration filters')}
      >
        {facetPanel(true)}
      </FilterSheet>

      {/* Config Details Sheet */}
      <ScanConfigDetailSheet
        config={selectedConfig}
        onOpenChange={(open) => !open && setSelectedConfig(null)}
        onDelete={(config) => {
          setConfigToDelete(config)
          setDeleteConfirmOpen(true)
        }}
        onEdit={(config) => {
          setSelectedConfig(null)
          setConfigToEdit(config)
          setEditDialogOpen(true)
        }}
        onClone={(config) => {
          setSelectedConfig(null)
          setConfigToClone(config)
          setCloneDialogOpen(true)
        }}
      />

      {/* Bulk delete confirmation: deleting configurations cannot be undone. */}
      <ConfirmDialog
        open={bulkDeleteConfirmOpen}
        onOpenChange={setBulkDeleteConfirmOpen}
        title={bulkCountText('confirm.scan.bulkDeleteTitle')}
        desc={t(
          'confirm.scan.bulkDeleteDesc',
          'The selected scans and their schedules are deleted. Past runs and findings stay. This cannot be undone.'
        )}
        confirmText={
          isBulkDeleting
            ? t('confirm.deleting', 'Deleting…')
            : bulkCountText('confirm.scan.bulkDeleteBtn')
        }
        destructive
        isLoading={isBulkDeleting}
        typeToConfirm={irreversibleTypeToConfirm(selectedNames)}
        handleConfirm={async () => {
          await runBulk(bulkDelete, t('scans.bulk.deleteFailed'))
          setBulkDeleteConfirmOpen(false)
        }}
      >
        <ConfirmSample names={selectedNames} total={selectedIds.length} />
      </ConfirmDialog>

      {/* Bulk activate (starts scans) and bulk pause: the count and the names. */}
      <ConfirmDialog
        open={bulkConfirm !== null}
        onOpenChange={(open) => !open && setBulkConfirm(null)}
        title={bulkCountText(
          bulkConfirm === 'pause' ? 'confirm.scan.bulkPauseTitle' : 'confirm.scan.bulkActivateTitle'
        )}
        desc={t(
          bulkConfirm === 'pause' ? 'confirm.scan.bulkPauseDesc' : 'confirm.scan.bulkActivateDesc'
        )}
        confirmText={bulkCountText(
          bulkConfirm === 'pause' ? 'confirm.scan.bulkPauseBtn' : 'confirm.scan.bulkActivateBtn'
        )}
        isLoading={isActivating || isPausing}
        handleConfirm={async () => {
          if (bulkConfirm === 'pause') {
            await runBulk(bulkPause, t('scans.bulk.pauseFailed'))
          } else {
            await runBulk(bulkActivate, t('scans.bulk.activateFailed'))
          }
          setBulkConfirm(null)
        }}
      >
        <ConfirmSample names={selectedNames} total={selectedIds.length} />
      </ConfirmDialog>

      <ScheduleOnConfirm
        name={configToResume?.name ?? ''}
        open={configToResume !== null}
        onOpenChange={(open) => !open && setConfigToResume(null)}
        onConfirm={confirmResume}
      />

      {/* Bulk disable: the selected scans stop running until activated again. */}
      <ConfirmDialog
        open={bulkDisableConfirmOpen}
        onOpenChange={setBulkDisableConfirmOpen}
        title={bulkCountText('confirm.scan.bulkDisableTitle')}
        desc={t(
          'confirm.scan.bulkDisableDesc',
          'The selected scans stop running on their schedules and cannot be started until you activate them again. Their history stays.'
        )}
        confirmText={bulkCountText('confirm.scan.bulkDisableBtn')}
        destructive
        isLoading={isDisabling}
        handleConfirm={async () => {
          await runBulk(bulkDisable, t('scans.bulk.disableFailed'))
          setBulkDisableConfirmOpen(false)
        }}
      >
        <ConfirmSample names={selectedNames} total={selectedIds.length} />
      </ConfirmDialog>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title={t('confirm.scan.deleteTitle', 'Delete scan "{name}"?', {
          name: configToDelete?.name ?? '',
        })}
        desc={t(
          'confirm.scan.deleteDesc',
          'The scan and its schedule are deleted. Past runs and findings stay. This cannot be undone.'
        )}
        confirmText={isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.scan.deleteBtn')}
        destructive
        isLoading={isDeleting}
        typeToConfirm={
          configToDelete ? confirmName(configToDelete.name, configToDelete.id) : undefined
        }
        handleConfirm={handleConfirmDelete}
      />

      {triggerDialog}
      <LazyRunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />

      {/* Clone Scan Dialog */}
      <LazyCloneScanDialog
        scan={configToClone}
        open={cloneDialogOpen}
        onOpenChange={setCloneDialogOpen}
      />

      {/* Edit Scan Dialog */}
      <LazyEditScanDialog
        scanConfig={configToEdit}
        open={editDialogOpen}
        onOpenChange={setEditDialogOpen}
        onSuccess={() => {
          setConfigToEdit(null)
        }}
      />
    </>
  )
}
