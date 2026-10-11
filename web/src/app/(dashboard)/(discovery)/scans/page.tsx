'use client'

import { IntensityBadge } from '@/features/scans/components/intensity-badge'
import * as React from 'react'
import { useState, useMemo, useCallback, useEffect } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import { SensorOptInBanner } from '@/features/sensors/components/sensor-opt-in-banner'
import { ScanWindowsBanner } from '@/features/scan-windows'
import { ScanApprovalBadge } from '@/features/scans/components/approval/scan-approval-badge'
import {
  MetricStrip,
  type MetricStripItem,
  DataTable,
  DataTableColumnHeader,
  BulkActionBar,
  FacetPanel,
  FacetSection,
  FacetOption,
  FilterPanelToggle,
  FilterSheet,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { bulkTypeToConfirm, ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { toast } from 'sonner'
import {
  Search,
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
} from 'lucide-react'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { Can, Permission } from '@/lib/permissions'
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
import { SCAN_TYPE_LABELS, SCHEDULE_TYPE_LABELS, SCHEDULE_TYPES } from '@/lib/api/scan-types'
import type {
  ScanConfig,
  ScanConfigStatus,
  ScanType as ApiScanType,
  ScheduleType,
} from '@/lib/api/scan-types'
import { CloneScanDialog, EditScanDialog } from '@/features/scans/components'
import {
  ScanCreateActions,
  ScansPageHeader,
  ScansSectionTabs,
} from '@/features/scans/components/scans-section-tabs'
import { ScanConfigDetailSheet } from '@/features/scans/components/scan-config-detail-sheet'
import { LastRunCell } from '@/features/scans/components/last-run-cell'
import { ScheduleCell } from '@/features/scans/components/schedule-cell'
import { lastRunOf, scanTypeLabel } from '@/features/scans/lib/scan-status'
import { RunDetailSheet } from '@/features/scans/components/run-detail-sheet'
import { useScanTrigger } from '@/features/scans/hooks/use-scan-trigger'
import { scanSuccessRate } from '@/features/scans/lib/format'
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
type ConfigTypeFilter = ApiScanType | 'all'

// The configuration's state, not a run state: an enabled scan runs on its
// schedule (if it has one), a paused one only when someone runs it.
const configStatusFilters: { value: ConfigStatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Enabled' },
  { value: 'paused', label: 'Schedule paused' },
  { value: 'disabled', label: 'Disabled' },
]

const configTypeFilters: { value: ConfigTypeFilter; label: string }[] = [
  { value: 'all', label: 'All types' },
  { value: 'workflow', label: 'Workflow' },
  { value: 'single', label: 'Single scanner' },
]

type ConfigScheduleFilter = ScheduleType | 'all'

const configScheduleFilters: { value: ConfigScheduleFilter; label: string }[] = [
  { value: 'all', label: 'All schedules' },
  ...SCHEDULE_TYPES.map((type) => ({
    value: type as ScheduleType,
    label: SCHEDULE_TYPE_LABELS[type],
  })),
]

// Map API status to UI-friendly status for StatusBadge
// ============================================
// UTILS
// ============================================

// ============================================
// SHARED LIST PIECES
// ============================================

const CONFIG_FILTERS_OPEN_KEY = 'openctem:scan-config-filters-open'

/**
 * Whether the filter panel is open. Closed by default so the table gets the
 * width; the viewer's choice is remembered per browser (safe to lose).
 */
function usePersistentFiltersOpen(key: string): [boolean, (open: boolean) => void] {
  const [open, setOpenState] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(key) === '1') setOpenState(true)
    } catch {
      // storage unavailable — stay closed
    }
  }, [key])
  const setOpen = useCallback(
    (next: boolean) => {
      setOpenState(next)
      try {
        window.localStorage.setItem(key, next ? '1' : '0')
      } catch {
        // best-effort
      }
    },
    [key]
  )
  return [open, setOpen]
}

function SearchBox({
  value,
  onChange,
  placeholder,
  label,
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  label: string
}) {
  return (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label}
        className="h-9 ps-9"
      />
    </div>
  )
}

/** Shaped like the DataTable it stands in for: toolbar, then rows. */
function TableSkeleton() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Skeleton className="h-9 w-24" />
        <Skeleton className="h-9 w-72" />
        <Skeleton className="ms-auto h-9 w-24" />
      </div>
      <div className="space-y-2 rounded-md border p-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    </div>
  )
}

// ============================================
// MAIN PAGE COMPONENT
// ============================================

export default function ScansPage() {
  return (
    <Main>
      <ScansPageHeader>
        <ScanCreateActions />
      </ScansPageHeader>
      <ScansSectionTabs />

      <ScanWindowsBanner className="mt-5" />
      <div className="mt-4">
        <SensorOptInBanner />
      </div>

      <div className="mt-5">
        <ConfigurationsTab />
      </div>
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
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0" aria-label="Row actions">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <Link href={`/scans/${config.id}`} className="flex items-center">
            <Eye className="me-2 h-4 w-4" />
            View details
          </Link>
        </DropdownMenuItem>
        <Can permission={Permission.ScansWrite}>
          <DropdownMenuItem onClick={() => onAction('edit', config)}>
            <Pencil className="me-2 h-4 w-4" />
            Edit
          </DropdownMenuItem>
        </Can>
        {/* Trigger, clone, pause and resume all need scans:write. */}
        <Can permission={Permission.ScansWrite}>
          <DropdownMenuItem disabled={triggering} onClick={() => onAction('trigger', config)}>
            {triggering ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Play className="me-2 h-4 w-4" />
            )}
            {triggering ? 'Starting…' : 'Trigger scan'}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => onAction('clone', config)}>
            <Copy className="me-2 h-4 w-4" />
            Clone
          </DropdownMenuItem>
          {(config.status === 'active' || config.status === 'paused') && <DropdownMenuSeparator />}
          {config.status === 'active' && (
            <DropdownMenuItem onClick={() => onAction('pause', config)}>
              <Pause className="me-2 h-4 w-4" />
              Pause
            </DropdownMenuItem>
          )}
          {config.status === 'paused' && (
            <DropdownMenuItem onClick={() => onAction('activate', config)}>
              <Play className="me-2 h-4 w-4" />
              Resume
            </DropdownMenuItem>
          )}
        </Can>
        <Can permission={Permission.ScansDelete}>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="text-destructive focus:text-destructive"
            onClick={() => onAction('delete', config)}
          >
            <Trash2 className="me-2 h-4 w-4" />
            Delete
          </DropdownMenuItem>
        </Can>
      </DropdownMenuContent>
    </DropdownMenu>
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
    filters: { status: 'all', type: 'all', schedule: 'all', tag: '', one_off: '' },
  })
  const searchQuery = list.q
  const setSearchQuery = list.setSearch
  const debouncedSearch = useDebounce(searchQuery, 300)
  const statusFilter = list.filters.status as ConfigStatusFilter
  const setStatusFilter = (v: ConfigStatusFilter) => list.setFilter('status', v)
  const typeFilter = list.filters.type as ConfigTypeFilter
  const setTypeFilter = (v: ConfigTypeFilter) => list.setFilter('type', v)
  const scheduleFilter = list.filters.schedule as ConfigScheduleFilter
  const setScheduleFilter = (v: ConfigScheduleFilter) => list.setFilter('schedule', v)
  const tagFilter = list.filters.tag
  const setTagFilter = (v: string) => list.setFilter('tag', v)
  const debouncedTag = useDebounce(tagFilter, 300)
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
  const [filtersOpen, setFiltersOpen] = usePersistentFiltersOpen(CONFIG_FILTERS_OPEN_KEY)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [bulkDeleteConfirmOpen, setBulkDeleteConfirmOpen] = useState(false)
  const [bulkDisableConfirmOpen, setBulkDisableConfirmOpen] = useState(false)
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
      tags: debouncedTag || undefined,
      search: debouncedSearch || undefined,
      include_ad_hoc: showOneOff || undefined,
      sort: list.sort,
      page: pageParam,
      per_page: perPage,
    }),
    [
      statusFilter,
      typeFilter,
      scheduleFilter,
      debouncedTag,
      debouncedSearch,
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

  const { data: configsResponse, isLoading: isLoadingConfigs } = useScanConfigs(filters, swrConfig)
  const { data: stats, isLoading: isLoadingStats } = useScanConfigStats(swrConfig)

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

  // Narrowing the list starts again at page 1 (page 3 of the old result may
  // not exist in the new one). Skipped on mount so a shared link keeps its page.
  const filterKey = [
    statusFilter,
    typeFilter,
    scheduleFilter,
    debouncedTag,
    debouncedSearch,
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

  // Calculate progress for a config - memoized
  // Success rate over FINISHED runs (succeeded + failed). total_runs also
  // counts runs that are still going, so dividing by it understated the rate,
  // and a scan with no finished run has no rate at all (not 0%).
  const getProgress = useCallback((config: ScanConfig) => scanSuccessRate(config) ?? -1, [])

  // The Schedule column's switch: pause turns the schedule off, resume on.
  const handleToggle = useCallback(async (action: 'pause' | 'activate', config: ScanConfig) => {
    const endpoint =
      action === 'pause' ? scanEndpoints.pause(config.id) : scanEndpoints.activate(config.id)
    try {
      await post(endpoint, {})
    } catch (error) {
      toast.error(getErrorMessage(error, `Failed to change the schedule of "${config.name}"`))
      throw error
    }
    toast.success(`Schedule of "${config.name}" turned ${action === 'pause' ? 'off' : 'on'}`)
    await invalidateScanConfigsCache()
  }, [])

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

      // Trigger asks first when a run is already in progress, and ignores a
      // second click while the first is in flight (useScanTrigger).
      if (action === 'trigger') {
        await triggerScan(config)
        return
      }

      try {
        switch (action) {
          case 'pause':
            await post(scanEndpoints.pause(config.id), {})
            toast.success(`Scan "${config.name}" paused`)
            break
          case 'activate':
            await post(scanEndpoints.activate(config.id), {})
            toast.success(`Scan "${config.name}" activated`)
            break
        }
        // Invalidate caches to refresh the list
        await invalidateScanConfigsCache()
      } catch (error) {
        console.error(`Failed to ${action} scan:`, error)
        toast.error(getErrorMessage(error, `Failed to ${action} scan "${config.name}"`), {})
      }
    },
    [triggerScan]
  )

  const handleConfirmDelete = useCallback(async () => {
    if (!configToDelete) return

    setIsDeleting(true)
    try {
      await del(scanEndpoints.delete(configToDelete.id))
      toast.success(`Scan "${configToDelete.name}" deleted`)
      setSelectedConfig(null)
      await invalidateScanConfigsCache()
    } catch (error) {
      console.error('Failed to delete scan:', error)
      toast.error(getErrorMessage(error, `Failed to delete scan "${configToDelete.name}"`))
    } finally {
      setIsDeleting(false)
      setDeleteConfirmOpen(false)
      setConfigToDelete(null)
    }
  }, [configToDelete])

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
      {
        id: 'select',
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label="Select row"
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => (
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <p className="font-medium">{row.original.name}</p>
              <ScanApprovalBadge
                status={(row.original as { approval_status?: string }).approval_status}
              />
            </div>
            {row.original.description && (
              <p className="max-w-[300px] truncate text-xs text-muted-foreground">
                {row.original.description}
              </p>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'scan_type',
        header: 'Type',
        enableSorting: false,
        cell: ({ row }) => {
          // What the scan runs: the workflow's name, or a single check's tool.
          const { label, kind } = scanTypeLabel(row.original)
          return (
            <div className="flex min-w-0 flex-col">
              <span className="max-w-[14rem] truncate text-sm" title={label}>
                {label}
              </span>
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                {SCAN_TYPE_LABELS[kind]}
                <IntensityBadge intensity={row.original.intensity} />
              </span>
            </div>
          )
        },
      },
      {
        // The real latest run, never the configuration's enabled flag.
        id: 'last_run_at',
        accessorKey: 'last_run_at',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Last run" />,
        cell: ({ row }) => <LastRunCell run={lastRunOf(row.original)} onOpen={setOpenRunId} />,
      },
      {
        id: 'success_rate',
        accessorFn: (c) => getProgress(c),
        header: 'Success rate',
        enableSorting: false,
        cell: ({ row }) => {
          const rate = scanSuccessRate(row.original)
          if (rate === null) return <span className="text-muted-foreground">-</span>
          const settled =
            row.original.successful_runs +
            (row.original.partial_runs ?? 0) +
            row.original.failed_runs
          return (
            <div
              className="flex items-center gap-2"
              title={`${row.original.successful_runs} of ${settled} finished runs succeeded`}
            >
              <Progress value={rate} className="h-2 w-20 shrink-0" />
              <span className="w-10 shrink-0 text-xs tabular-nums text-muted-foreground">
                {rate}%
              </span>
            </div>
          )
        },
      },
      {
        accessorKey: 'total_runs',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Runs" />,
        cell: ({ row }) => <span className="text-sm tabular-nums">{row.original.total_runs}</span>,
      },
      {
        id: 'results',
        accessorFn: (c) => c.successful_runs,
        header: 'Results',
        enableSorting: false,
        cell: ({ row }) => {
          const config = row.original
          if (config.total_runs === 0) return <span className="text-muted-foreground">-</span>
          const blocked = config.blocked_runs ?? 0
          return (
            <span className="text-sm tabular-nums">
              {config.successful_runs} passed
              {(config.partial_runs ?? 0) > 0 && (
                <span className="text-warning"> · {config.partial_runs} partial</span>
              )}
              {config.failed_runs > 0 && (
                <span className="text-destructive"> · {config.failed_runs} failed</span>
              )}
              {blocked > 0 && <span className="text-destructive"> · {blocked} blocked</span>}
            </span>
          )
        },
      },
      {
        // The schedule and its on/off switch; manual scans have neither.
        accessorKey: 'schedule_type',
        header: 'Schedule',
        enableSorting: false,
        cell: ({ row }) => <ScheduleCell config={row.original} onToggle={handleToggle} />,
      },
      {
        id: 'actions',
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
    [getProgress, handleAction, handleToggle, isTriggering]
  )

  const activeFiltersCount = [
    statusFilter !== 'all',
    typeFilter !== 'all',
    scheduleFilter !== 'all',
    tagFilter !== '',
    showOneOff,
  ].filter(Boolean).length

  const clearFilters = () => {
    setStatusFilter('all')
    setTypeFilter('all')
    setScheduleFilter('all')
    setTagFilter('')
    setOneOffParam('')
    setPageParam(1)
  }

  // A status metric toggles its filter; "All" clears it.
  const toggleStatus = (value: ConfigStatusFilter) =>
    setStatusFilter(statusFilter === value ? 'all' : value)

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: 'Configurations',
      value: stats?.total ?? 0,
      onClick: () => setStatusFilter('all'),
      active: statusFilter === 'all',
    },
    {
      key: 'active',
      label: 'Enabled',
      value: stats?.active ?? 0,
      onClick: () => toggleStatus('active'),
      active: statusFilter === 'active',
    },
    {
      key: 'paused',
      label: 'Schedule paused',
      value: stats?.paused ?? 0,
      onClick: () => toggleStatus('paused'),
      active: statusFilter === 'paused',
    },
    {
      key: 'disabled',
      label: 'Disabled',
      value: stats?.disabled ?? 0,
      onClick: () => toggleStatus('disabled'),
      active: statusFilter === 'disabled',
    },
  ]

  // Filters are single-valued in the API, so each section behaves like a radio
  // group: ticking an option replaces the previous one, unticking clears it.
  const facetPanel = (
    <FacetPanel activeCount={activeFiltersCount} onClearAll={clearFilters}>
      <FacetSection title="State" selectedCount={statusFilter !== 'all' ? 1 : 0}>
        {configStatusFilters
          .filter((f) => f.value !== 'all')
          .map((f) => (
            <FacetOption
              key={f.value}
              label={f.label}
              checked={statusFilter === f.value}
              onCheckedChange={(on) => setStatusFilter(on ? f.value : 'all')}
            />
          ))}
      </FacetSection>
      <FacetSection title="Scan type" selectedCount={typeFilter !== 'all' ? 1 : 0}>
        {configTypeFilters
          .filter((f) => f.value !== 'all')
          .map((f) => (
            <FacetOption
              key={f.value}
              label={f.label}
              checked={typeFilter === f.value}
              onCheckedChange={(on) => setTypeFilter(on ? f.value : 'all')}
            />
          ))}
      </FacetSection>
      <FacetSection title="Schedule" selectedCount={scheduleFilter !== 'all' ? 1 : 0}>
        {configScheduleFilters
          .filter((f) => f.value !== 'all')
          .map((f) => (
            <FacetOption
              key={f.value}
              label={f.label}
              checked={scheduleFilter === f.value}
              onCheckedChange={(on) => setScheduleFilter(on ? f.value : 'all')}
            />
          ))}
      </FacetSection>
      <FacetSection title="One-off scans" selectedCount={showOneOff ? 1 : 0}>
        <FacetOption
          label="Show one-off scans"
          checked={showOneOff}
          onCheckedChange={(on) => setOneOffParam(on ? '1' : '')}
        />
      </FacetSection>
      <FacetSection title="Tag" selectedCount={tagFilter ? 1 : 0}>
        <div className="relative pe-1 pt-1">
          <Tag className="pointer-events-none absolute start-2.5 top-1/2 mt-0.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Filter by tag…"
            aria-label="Filter by tag"
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            className="h-8 ps-8 text-sm"
          />
        </div>
      </FacetSection>
    </FacetPanel>
  )

  const toolbarStart = (
    <>
      <FilterPanelToggle
        open={filtersOpen}
        onToggle={() => setFiltersOpen(!filtersOpen)}
        onOpenSheet={() => setFilterSheetOpen(true)}
        activeCount={activeFiltersCount}
        controlsId="scan-config-filters"
      />
      <SearchBox
        value={searchQuery}
        onChange={setSearchQuery}
        placeholder="Search configurations…"
        label="Search scan configurations"
      />
    </>
  )

  return (
    <>
      <MetricStrip loading={isLoadingStats} items={metrics} />

      <div className="mt-5 flex items-start gap-5">
        {filtersOpen && (
          <aside
            id="scan-config-filters"
            aria-label="Scan configuration filters"
            className="sticky top-4 hidden h-[calc(100svh-7.5rem)] w-64 shrink-0 flex-col rounded-xl border bg-card p-4 shadow-sm lg:flex"
          >
            <div className="flex min-h-0 flex-1 flex-col">{facetPanel}</div>
          </aside>
        )}

        <div className="min-w-0 flex-1">
          {isLoadingConfigs && !configsResponse ? (
            <TableSkeleton />
          ) : (
            <DataTable
              columns={columns}
              data={configs}
              showSearch={false}
              toolbarStart={toolbarStart}
              manualPagination
              rowCount={configsResponse?.total ?? 0}
              pagination={{ pageIndex: pageParam - 1, pageSize: perPage }}
              onPaginationChange={list.setPagination}
              pageSize={perPage}
              pageSizeOptions={[...SCAN_PAGE_SIZES]}
              paginationNoun="scans"
              sorting={sorting}
              onSortingChange={list.setSorting}
              getRowId={(c) => c.id}
              onRowClick={setSelectedConfig}
              onSelectionChange={(rows) => setSelectedIds(rows.map((c) => c.id))}
              resetSelectionKey={selectionEpoch}
              showSelectionCount={false}
              emptyMessage={
                activeFiltersCount > 0 || searchQuery
                  ? 'No configurations match these filters'
                  : 'No scan configurations yet'
              }
              emptyDescription={
                activeFiltersCount > 0 || searchQuery
                  ? 'Try removing a filter or clearing the search.'
                  : 'Create one with New scan to schedule recurring scans.'
              }
            />
          )}
        </div>
      </div>

      <BulkActionBar count={selectedIds.length} onClear={clearSelection}>
        <Can permission={Permission.ScansWrite}>
          <Button
            variant="ghost"
            size="sm"
            disabled={isBulkOperating}
            onClick={() => runBulk(bulkActivate, 'Failed to activate selected scans')}
          >
            <Play className="me-2 h-4 w-4" />
            Activate
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={isBulkOperating}
            onClick={() => runBulk(bulkPause, 'Failed to pause selected scans')}
          >
            <Pause className="me-2 h-4 w-4" />
            Pause
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={isBulkOperating}
            onClick={() => setBulkDisableConfirmOpen(true)}
          >
            <XCircle className="me-2 h-4 w-4" />
            Disable
          </Button>
        </Can>
        <Can permission={Permission.ScansDelete}>
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            disabled={isBulkOperating}
            onClick={() => setBulkDeleteConfirmOpen(true)}
          >
            {isBulkDeleting ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Trash2 className="me-2 h-4 w-4" />
            )}
            Delete
          </Button>
        </Can>
      </BulkActionBar>

      <FilterSheet
        open={filterSheetOpen}
        onOpenChange={setFilterSheetOpen}
        title="Scan configuration filters"
      >
        {facetPanel}
      </FilterSheet>

      {/* Config Details Sheet */}
      <ScanConfigDetailSheet
        config={selectedConfig}
        onOpenChange={(open) => !open && setSelectedConfig(null)}
        onDelete={(config) => {
          setConfigToDelete(config)
          setDeleteConfirmOpen(true)
        }}
      />

      {/* Bulk delete confirmation: deleting configurations cannot be undone. */}
      <ConfirmDialog
        open={bulkDeleteConfirmOpen}
        onOpenChange={setBulkDeleteConfirmOpen}
        title={
          selectedIds.length === 1
            ? t('confirm.scan.bulkDeleteTitleOne', 'Delete 1 scan?')
            : t('confirm.scan.bulkDeleteTitle', 'Delete {count} scans?', {
                count: selectedIds.length,
              })
        }
        desc={t(
          'confirm.scan.bulkDeleteDesc',
          'The selected scans and their schedules are deleted. Past runs and findings stay. This cannot be undone.'
        )}
        confirmText={
          isBulkDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        destructive
        isLoading={isBulkDeleting}
        typeToConfirm={bulkTypeToConfirm(selectedIds.length)}
        handleConfirm={async () => {
          await runBulk(bulkDelete, 'Failed to delete selected scans')
          setBulkDeleteConfirmOpen(false)
        }}
      />

      {/* Bulk disable: the selected scans stop running until activated again. */}
      <ConfirmDialog
        open={bulkDisableConfirmOpen}
        onOpenChange={setBulkDisableConfirmOpen}
        title={
          selectedIds.length === 1
            ? t('confirm.scan.bulkDisableTitleOne', 'Disable 1 scan?')
            : t('confirm.scan.bulkDisableTitle', 'Disable {count} scans?', {
                count: selectedIds.length,
              })
        }
        desc={t(
          'confirm.scan.bulkDisableDesc',
          'The selected scans stop running on their schedules and cannot be started until you activate them again. Their history stays.'
        )}
        confirmText={t('confirm.disable', 'Disable')}
        destructive
        isLoading={isDisabling}
        handleConfirm={async () => {
          await runBulk(bulkDisable, 'Failed to disable selected scans')
          setBulkDisableConfirmOpen(false)
        }}
      />

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
        confirmText={
          isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        destructive
        isLoading={isDeleting}
        handleConfirm={handleConfirmDelete}
      />

      {triggerDialog}
      <RunDetailSheet runId={openRunId} onOpenChange={(o) => !o && setOpenRunId(null)} />

      {/* Clone Scan Dialog */}
      <CloneScanDialog
        scan={configToClone}
        open={cloneDialogOpen}
        onOpenChange={setCloneDialogOpen}
      />

      {/* Edit Scan Dialog */}
      <EditScanDialog
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
