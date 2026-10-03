'use client'

import * as React from 'react'
import { useState, useMemo, useCallback, useEffect } from 'react'
import Link from 'next/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import { triggerErrorHint } from '@/features/scan-zones'
import {
  PageHeader,
  RunStatusBadge,
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
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { toast } from 'sonner'
import {
  Plus,
  Search,
  MoreHorizontal,
  Eye,
  Pause,
  Play,
  Trash2,
  XCircle,
  Clock,
  Shield,
  Copy,
  Pencil,
  Tag,
  Settings,
  Zap,
  Loader2,
  Download,
  FileJson,
  FileSpreadsheet,
} from 'lucide-react'
import { useDebounce } from '@/hooks/use-debounce'
import { SEVERITY_BADGE_SOFT } from '@/lib/severity-colors'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Can, Permission } from '@/lib/permissions'
import { cn, exportToCSV, exportToJSON } from '@/lib/utils'
import {
  useScanConfigs,
  useScanConfigStats,
  useScanSessions,
  useScanSessionStats,
  useBulkActivateScanConfigs,
  useBulkPauseScanConfigs,
  useBulkDisableScanConfigs,
  useBulkDeleteScanConfigs,
  invalidateScanConfigsCache,
} from '@/lib/api/scan-hooks'
import type { ScanSession, ScanRunStatus } from '@/lib/api/scan-types'
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
import {
  NewScanDialog,
  CloneScanDialog,
  EditScanDialog,
  QuickScanDialog,
} from '@/features/scans/components'
import { ScanConfigDetailSheet } from '@/features/scans/components/scan-config-detail-sheet'
import { ScanSessionDetailSheet } from '@/features/scans/components/scan-session-detail-sheet'
import { formatScanDate, formatScanDuration } from '@/features/scans/lib/format'

// ============================================
// CONFIGURATIONS TAB TYPES
// ============================================

type ConfigStatusFilter = ScanConfigStatus | 'all'
type ConfigTypeFilter = ApiScanType | 'all'

const configStatusFilters: { value: ConfigStatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'paused', label: 'Paused' },
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

// ============================================
// RUNS TAB TYPES
// ============================================

type RunStatusFilter = 'all' | ScanRunStatus

const runStatusFilters: { value: RunStatusFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'running', label: 'Running' },
  { value: 'queued', label: 'Queued' },
  { value: 'pending', label: 'Pending' },
  { value: 'completed', label: 'Completed' },
  { value: 'failed', label: 'Failed' },
  { value: 'timeout', label: 'Timed out' },
]

// Map API status to UI-friendly status for StatusBadge
// ============================================
// UTILS
// ============================================

const formatDate = formatScanDate
const formatDuration = formatScanDuration

/**
 * Format next run time as relative time (e.g., "in 2 days", "in 3 hours")
 */
function formatNextRun(nextRunAt?: string): string | null {
  if (!nextRunAt) return null

  const now = new Date()
  const nextRun = new Date(nextRunAt)
  const diffMs = nextRun.getTime() - now.getTime()

  if (diffMs < 0) return 'Overdue'

  const diffMinutes = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))

  if (diffDays > 0) return `in ${diffDays} day${diffDays > 1 ? 's' : ''}`
  if (diffHours > 0) return `in ${diffHours} hour${diffHours > 1 ? 's' : ''}`
  if (diffMinutes > 0) return `in ${diffMinutes} min${diffMinutes > 1 ? 's' : ''}`
  return 'Soon'
}

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
  // The active tab lives in the URL (`?tab=runs`) so either view can be linked to.
  const [tabParam, setTabParam] = useUrlFilter('tab', 'configurations')
  const mainTab: 'configurations' | 'runs' = tabParam === 'runs' ? 'runs' : 'configurations'
  const [dialogOpen, setDialogOpen] = useState(false)
  const [quickScanOpen, setQuickScanOpen] = useState(false)

  return (
    <>
      <NewScanDialog open={dialogOpen} onOpenChange={setDialogOpen} />
      <QuickScanDialog open={quickScanOpen} onOpenChange={setQuickScanOpen} />
      <Main>
        <PageHeader
          title="Scans"
          description="Schedule scan configurations and follow every run they produce."
        >
          <Can permission={Permission.ScansWrite} mode="disable">
            <Button variant="outline" size="sm" onClick={() => setQuickScanOpen(true)}>
              <Zap className="me-2 h-4 w-4" />
              Quick scan
            </Button>
          </Can>
          <Can permission={Permission.ScansWrite} mode="disable">
            <Button size="sm" onClick={() => setDialogOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              New scan
            </Button>
          </Can>
        </PageHeader>

        <Tabs value={mainTab} onValueChange={setTabParam} className="mt-4">
          <TabsList>
            <TabsTrigger value="configurations" className="gap-2">
              <Settings className="h-4 w-4" />
              Configurations
            </TabsTrigger>
            <TabsTrigger value="runs" className="gap-2">
              <Play className="h-4 w-4" />
              Runs
            </TabsTrigger>
          </TabsList>

          <TabsContent value="configurations" className="mt-5">
            <ConfigurationsTab />
          </TabsContent>

          <TabsContent value="runs" className="mt-5">
            <RunsTab />
          </TabsContent>
        </Tabs>
      </Main>
    </>
  )
}

// ============================================
// STATUS TOGGLE CELL (with loading state and debounce)
// ============================================

interface StatusToggleCellProps {
  config: ScanConfig
  onToggle: (action: 'pause' | 'activate', config: ScanConfig) => Promise<void>
}

function StatusToggleCell({ config, onToggle }: StatusToggleCellProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [localStatus, setLocalStatus] = useState(config.status)
  const debounceRef = React.useRef<NodeJS.Timeout | null>(null)

  // Sync local status with prop when config changes
  React.useEffect(() => {
    setLocalStatus(config.status)
  }, [config.status])

  const handleToggle = async (checked: boolean) => {
    // Debounce to prevent rapid clicking
    if (debounceRef.current) {
      clearTimeout(debounceRef.current)
    }

    const action = checked ? 'activate' : 'pause'
    const canToggle =
      (checked && localStatus === 'paused') || (!checked && localStatus === 'active')

    if (!canToggle) return

    // Optimistic update
    setLocalStatus(checked ? 'active' : 'paused')
    setIsLoading(true)

    debounceRef.current = setTimeout(async () => {
      try {
        await onToggle(action, config)
      } catch {
        // Revert on error
        setLocalStatus(config.status)
      } finally {
        setIsLoading(false)
      }
    }, 300) // 300ms debounce
  }

  const isActive = localStatus === 'active'
  const isDisabled = config.status === 'disabled'

  return (
    <div className="flex items-center gap-2">
      <div className="relative">
        <Switch
          checked={isActive}
          onCheckedChange={handleToggle}
          disabled={isDisabled || isLoading}
          aria-label={isActive ? 'Pause scan' : 'Activate scan'}
        />
        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
          </div>
        )}
      </div>
      <span className="text-xs text-muted-foreground min-w-[50px]">
        {isLoading
          ? 'Saving…'
          : localStatus === 'active'
            ? 'Active'
            : localStatus === 'paused'
              ? 'Paused'
              : 'Disabled'}
      </span>
    </div>
  )
}

// ============================================
// CONFIG ACTIONS CELL (simplified - no hooks to prevent re-renders)
// ============================================

type ConfigAction = 'trigger' | 'pause' | 'activate' | 'delete' | 'clone' | 'edit'

interface ConfigActionsCellProps {
  config: ScanConfig
  onAction: (action: ConfigAction, config: ScanConfig) => void
}

function ConfigActionsCell({ config, onAction }: ConfigActionsCellProps) {
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
        <DropdownMenuItem onClick={() => onAction('trigger', config)}>
          <Play className="me-2 h-4 w-4" />
          Trigger scan
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onAction('clone', config)}>
          <Copy className="me-2 h-4 w-4" />
          Clone
        </DropdownMenuItem>
        <DropdownMenuSeparator />
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
  // bookmarked. The hook returns plain strings; the casts keep the narrower
  // filter types downstream.
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const debouncedSearch = useDebounce(searchQuery, 300)
  const [statusFilter, setStatusFilter] = useUrlFilter('status', 'all') as [
    ConfigStatusFilter,
    (v: ConfigStatusFilter) => void,
  ]
  const [typeFilter, setTypeFilter] = useUrlFilter('type', 'all') as [
    ConfigTypeFilter,
    (v: ConfigTypeFilter) => void,
  ]
  const [scheduleFilter, setScheduleFilter] = useUrlFilter('schedule', 'all') as [
    ConfigScheduleFilter,
    (v: ConfigScheduleFilter) => void,
  ]
  const [tagFilter, setTagFilter] = useUrlFilter('tag', '')
  const debouncedTag = useDebounce(tagFilter, 300)
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
  const [configToDelete, setConfigToDelete] = useState<ScanConfig | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)
  const [cloneDialogOpen, setCloneDialogOpen] = useState(false)
  const [configToClone, setConfigToClone] = useState<ScanConfig | null>(null)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [configToEdit, setConfigToEdit] = useState<ScanConfig | null>(null)

  // Memoize filter object to prevent unnecessary re-renders
  const filters = useMemo(
    () => ({
      status: statusFilter !== 'all' ? statusFilter : undefined,
      scan_type: typeFilter !== 'all' ? typeFilter : undefined,
      schedule_type: scheduleFilter !== 'all' ? scheduleFilter : undefined,
      tags: debouncedTag || undefined,
      search: debouncedSearch || undefined,
    }),
    [statusFilter, typeFilter, scheduleFilter, debouncedTag, debouncedSearch]
  )

  // API hooks with stable configuration
  const swrConfig = useMemo(
    () => ({
      revalidateOnFocus: false,
      revalidateOnReconnect: false,
      refreshInterval: 0,
      dedupingInterval: 5000,
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
    return configsResponse?.items ?? []
  }, [configsResponse?.items])

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

  // Total runs across the listed configurations
  const totalRunsCount = useMemo(() => {
    return configs.reduce((sum, c) => sum + c.total_runs, 0)
  }, [configs])

  // Calculate progress for a config - memoized
  const getProgress = useCallback((config: ScanConfig) => {
    if (config.total_runs === 0) return 0
    return Math.round((config.successful_runs / config.total_runs) * 100)
  }, [])

  // Toggle handler for StatusToggleCell (returns Promise for loading state)
  const handleToggle = useCallback(async (action: 'pause' | 'activate', config: ScanConfig) => {
    const endpoint =
      action === 'pause' ? scanEndpoints.pause(config.id) : scanEndpoints.activate(config.id)
    await post(endpoint, {})
    toast.success(`Scan "${config.name}" ${action === 'pause' ? 'paused' : 'activated'}`)
    await invalidateScanConfigsCache()
  }, [])

  const handleAction = useCallback(async (action: ConfigAction, config: ScanConfig) => {
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

    try {
      switch (action) {
        case 'trigger':
          await post(scanEndpoints.trigger(config.id), {})
          toast.success(`Scan "${config.name}" triggered successfully`)
          break
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
      toast.error(getErrorMessage(error, `Failed to ${action} scan "${config.name}"`), {
        description: action === 'trigger' ? triggerErrorHint(error) : undefined,
      })
    }
  }, [])

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
            <p className="font-medium">{row.original.name}</p>
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
        cell: ({ row }) => (
          <Badge variant="outline">{SCAN_TYPE_LABELS[row.original.scan_type]}</Badge>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Status',
        enableSorting: false,
        cell: ({ row }) => <StatusToggleCell config={row.original} onToggle={handleToggle} />,
      },
      {
        id: 'success_rate',
        accessorFn: (c) => getProgress(c),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Success rate" />,
        cell: ({ row }) => {
          const progress = getProgress(row.original)
          return (
            <div className="flex items-center gap-2">
              <Progress value={progress} className="h-2 w-20 shrink-0" />
              <span className="w-10 shrink-0 text-xs tabular-nums text-muted-foreground">
                {progress}%
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Results" />,
        cell: ({ row }) => {
          const config = row.original
          if (config.total_runs === 0) return <span className="text-muted-foreground">-</span>
          return (
            <span className="text-sm tabular-nums">
              {config.successful_runs} passed
              {config.failed_runs > 0 && (
                <span className="text-destructive"> · {config.failed_runs} failed</span>
              )}
            </span>
          )
        },
      },
      {
        accessorKey: 'schedule_type',
        header: 'Schedule',
        enableSorting: false,
        cell: ({ row }) => {
          const config = row.original
          const nextRun = formatNextRun(config.next_run_at)
          const isPaused = config.status === 'paused'
          const isActive = config.status === 'active'
          return (
            <div className="flex flex-col">
              <span className="text-sm">{SCHEDULE_TYPE_LABELS[config.schedule_type]}</span>
              {nextRun && (isActive || isPaused) && (
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  Next: {nextRun}
                  {isPaused && <span className="opacity-70">(if resumed)</span>}
                </span>
              )}
            </div>
          )
        },
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => <ConfigActionsCell config={row.original} onAction={handleAction} />,
      },
    ],
    [getProgress, handleAction, handleToggle]
  )

  const activeFiltersCount = [
    statusFilter !== 'all',
    typeFilter !== 'all',
    scheduleFilter !== 'all',
    tagFilter !== '',
  ].filter(Boolean).length

  const clearFilters = () => {
    setStatusFilter('all')
    setTypeFilter('all')
    setScheduleFilter('all')
    setTagFilter('')
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
      label: 'Active',
      value: stats?.active ?? 0,
      onClick: () => toggleStatus('active'),
      active: statusFilter === 'active',
    },
    {
      key: 'paused',
      label: 'Paused',
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
    { key: 'runs', label: 'Runs (listed)', value: totalRunsCount },
  ]

  // Filters are single-valued in the API, so each section behaves like a radio
  // group: ticking an option replaces the previous one, unticking clears it.
  const facetPanel = (
    <FacetPanel activeCount={activeFiltersCount} onClearAll={clearFilters}>
      <FacetSection title="Status" selectedCount={statusFilter !== 'all' ? 1 : 0}>
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
          onClick={() => runBulk(bulkDisable, 'Failed to disable selected scans')}
        >
          <XCircle className="me-2 h-4 w-4" />
          Disable
        </Button>
        <Can permission={Permission.ScansDelete}>
          <Button
            variant="ghost"
            size="sm"
            className="text-destructive hover:text-destructive"
            disabled={isBulkOperating}
            onClick={() => runBulk(bulkDelete, 'Failed to delete selected scans')}
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

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title="Delete scan configuration"
        desc={
          <>
            Are you sure you want to delete &quot;{configToDelete?.name}&quot;? This action cannot
            be undone and will remove all associated run history.
          </>
        }
        confirmText={isDeleting ? 'Deleting...' : 'Delete'}
        destructive
        isLoading={isDeleting}
        handleConfirm={handleConfirmDelete}
      />

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

// ============================================
// RUN ACTIONS CELL (extracted to prevent re-renders)
// ============================================

interface RunActionsCellProps {
  session: ScanSession
  onViewDetails: (session: ScanSession) => void
}

function RunActionsCell({ session, onViewDetails }: RunActionsCellProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="h-8 w-8 p-0" aria-label="Row actions">
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => onViewDetails(session)}>
          <Eye className="me-2 h-4 w-4" />
          View details
        </DropdownMenuItem>
        {session.status === 'completed' && session.findings_total > 0 && (
          <DropdownMenuItem asChild>
            <Link href={`/findings?scan_id=${session.id}`}>
              <Shield className="me-2 h-4 w-4" />
              View {session.findings_total} findings
            </Link>
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

// ============================================
// RUNS TAB
// ============================================

function RunsTab() {
  const [selectedSession, setSelectedSession] = useState<ScanSession | null>(null)
  // Own URL keys: the Configurations tab already uses `status` and `q`.
  const [statusFilter, setStatusFilter] = useUrlFilter('run_status', 'all') as [
    RunStatusFilter,
    (v: RunStatusFilter) => void,
  ]
  const [searchQuery, setSearchQuery] = useUrlFilter('run_q', '')

  // API filters
  const apiFilters = useMemo(
    () => ({
      status: statusFilter !== 'all' ? statusFilter : undefined,
      per_page: 50,
    }),
    [statusFilter]
  )

  // Stable SWR config
  const swrConfig = useMemo(
    () => ({
      revalidateOnFocus: false,
      revalidateOnReconnect: false,
      refreshInterval: 30000, // Refresh every 30s for running scans
      dedupingInterval: 5000,
    }),
    []
  )

  // Real API hooks
  const { data: sessionsResponse, isLoading: isLoadingSessions } = useScanSessions(
    apiFilters,
    swrConfig
  )
  const { data: stats, isLoading: isLoadingStats } = useScanSessionStats(undefined, swrConfig)

  // Extract sessions from response
  const sessions = useMemo((): ScanSession[] => {
    return sessionsResponse?.data ?? []
  }, [sessionsResponse?.data])

  // Filter sessions by search (client-side over the loaded page)
  const filteredSessions = useMemo(() => {
    if (!searchQuery) return sessions
    const search = searchQuery.toLowerCase()
    return sessions.filter(
      (s) =>
        s.scanner_name.toLowerCase().includes(search) ||
        s.asset_value.toLowerCase().includes(search) ||
        s.asset_type.toLowerCase().includes(search)
    )
  }, [sessions, searchQuery])

  // Handlers
  const handleViewDetails = useCallback((session: ScanSession) => {
    setSelectedSession(session)
  }, [])

  // NOTE: the /api/v1/scan-sessions route group exposes only GET (list/stats/
  // {id}) and DELETE — there is no /stop and no /retry endpoint. The former Stop
  // and Retry controls POSTed to non-existent routes and always 404'd, so both
  // have been removed rather than left as dead actions. (The /{id}/retry route
  // that does exist belongs to the notification-outbox group, not scan sessions.)
  // Row selection went with them: no bulk action exists for runs, so a
  // checkbox column (and its "N selected" button) did nothing.

  // Export handlers
  const handleExportCSV = useCallback(() => {
    const dataToExport = filteredSessions.length > 0 ? filteredSessions : sessions
    if (dataToExport.length === 0) {
      toast.error('No data to export')
      return
    }

    const columns = {
      scanner_name: 'Scanner',
      scanner_version: 'Version',
      asset_type: 'Asset Type',
      asset_value: 'Target',
      status: 'Status',
      findings_total: 'Total Findings',
      findings_new: 'New Findings',
      findings_fixed: 'Fixed Findings',
      duration_ms: 'Duration (ms)',
      started_at: 'Started At',
      completed_at: 'Completed At',
      error_message: 'Error',
    }

    const timestamp = new Date().toISOString().split('T')[0]
    exportToCSV(dataToExport, `scan-sessions-${timestamp}`, columns)
    toast.success(`Exported ${dataToExport.length} scan sessions to CSV`)
  }, [filteredSessions, sessions])

  const handleExportJSON = useCallback(() => {
    const dataToExport = filteredSessions.length > 0 ? filteredSessions : sessions
    if (dataToExport.length === 0) {
      toast.error('No data to export')
      return
    }

    const timestamp = new Date().toISOString().split('T')[0]
    exportToJSON(
      { sessions: dataToExport, exported_at: new Date().toISOString() },
      `scan-sessions-${timestamp}`
    )
    toast.success(`Exported ${dataToExport.length} scan sessions to JSON`)
  }, [filteredSessions, sessions])

  // Table columns for ScanSession
  const columns: ColumnDef<ScanSession>[] = useMemo(
    () => [
      {
        accessorKey: 'scanner_name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Scanner" />,
        cell: ({ row }) => (
          <div>
            <p className="font-medium">{row.original.scanner_name}</p>
            {row.original.scanner_version && (
              <p className="text-xs text-muted-foreground">v{row.original.scanner_version}</p>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'asset_value',
        header: 'Target',
        enableSorting: false,
        cell: ({ row }) => (
          <div>
            <p className="max-w-[200px] truncate font-medium">{row.original.asset_value}</p>
            <p className="text-xs text-muted-foreground">{row.original.asset_type}</p>
          </div>
        ),
      },
      {
        accessorKey: 'status',
        header: 'Status',
        enableSorting: false,
        cell: ({ row }) => <RunStatusBadge status={row.original.status} />,
      },
      {
        accessorKey: 'findings_total',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Findings" />,
        cell: ({ row }) => {
          const session = row.original
          if (session.findings_total === 0) {
            return <span className="text-muted-foreground">-</span>
          }
          const severities = session.findings_by_severity ?? {}
          const rest = (severities.medium ?? 0) + (severities.low ?? 0)
          return (
            <div className="flex items-center gap-1">
              {(severities.critical ?? 0) > 0 && (
                <Badge
                  variant="outline"
                  className={cn('px-1.5 text-xs tabular-nums', SEVERITY_BADGE_SOFT.critical)}
                >
                  C {severities.critical}
                </Badge>
              )}
              {(severities.high ?? 0) > 0 && (
                <Badge
                  variant="outline"
                  className={cn('px-1.5 text-xs tabular-nums', SEVERITY_BADGE_SOFT.high)}
                >
                  H {severities.high}
                </Badge>
              )}
              {rest > 0 && (
                <Badge variant="secondary" className="px-1.5 text-xs tabular-nums">
                  +{rest}
                </Badge>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'findings_new',
        header: ({ column }) => <DataTableColumnHeader column={column} title="New" />,
        cell: ({ row }) => {
          const newFindings = row.original.findings_new
          if (newFindings === 0) return <span className="text-muted-foreground">-</span>
          return <span className="text-sm tabular-nums">{newFindings}</span>
        },
      },
      {
        accessorKey: 'duration_ms',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Duration" />,
        cell: ({ row }) => {
          const durationMs = row.original.duration_ms
          if (!durationMs) {
            return (
              <span className="text-xs text-muted-foreground">
                {row.original.status === 'running' ? 'Running…' : '-'}
              </span>
            )
          }
          return <span className="text-sm tabular-nums">{formatDuration(durationMs)}</span>
        },
      },
      {
        id: 'started',
        accessorFn: (s) => s.started_at || s.created_at,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Started" />,
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {formatDate(row.original.started_at || row.original.created_at)}
          </span>
        ),
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => (
          <RunActionsCell session={row.original} onViewDetails={handleViewDetails} />
        ),
      },
    ],
    [handleViewDetails]
  )

  const toggleStatus = (value: RunStatusFilter) =>
    setStatusFilter(statusFilter === value ? 'all' : value)

  const metrics: MetricStripItem[] = [
    {
      key: 'all',
      label: 'Runs',
      value: stats?.total ?? 0,
      onClick: () => setStatusFilter('all'),
      active: statusFilter === 'all',
    },
    {
      key: 'running',
      label: 'Running',
      value: stats?.by_status?.running ?? 0,
      onClick: () => toggleStatus('running'),
      active: statusFilter === 'running',
    },
    {
      key: 'completed',
      label: 'Completed',
      value: stats?.by_status?.completed ?? 0,
      onClick: () => toggleStatus('completed'),
      active: statusFilter === 'completed',
    },
    {
      key: 'failed',
      label: 'Failed',
      value: stats?.by_status?.failed ?? 0,
      tone: 'danger',
      onClick: () => toggleStatus('failed'),
      active: statusFilter === 'failed',
    },
    {
      key: 'timeout',
      label: 'Timed out',
      value: stats?.by_status?.timeout ?? 0,
      tone: 'danger',
      onClick: () => toggleStatus('timeout'),
      active: statusFilter === 'timeout',
    },
    { key: 'findings', label: 'Findings', value: stats?.findings_total ?? 0 },
  ]

  const toolbarStart = (
    <>
      <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as RunStatusFilter)}>
        <SelectTrigger className="h-9 w-auto min-w-36" aria-label="Filter runs by status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {runStatusFilters.map((f) => (
            <SelectItem key={f.value} value={f.value}>
              {f.value === 'all' ? 'All statuses' : f.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <SearchBox
        value={searchQuery}
        onChange={setSearchQuery}
        placeholder="Search scanner, target…"
        label="Search scan runs"
      />
    </>
  )

  const toolbarEnd = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9">
          <Download className="h-4 w-4 sm:me-2" />
          <span className="hidden sm:inline">Export</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={handleExportCSV}>
          <FileSpreadsheet className="me-2 h-4 w-4" />
          Export as CSV
        </DropdownMenuItem>
        <DropdownMenuItem onClick={handleExportJSON}>
          <FileJson className="me-2 h-4 w-4" />
          Export as JSON
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  const filtered = statusFilter !== 'all' || !!searchQuery

  return (
    <>
      <MetricStrip loading={isLoadingStats} items={metrics} />

      <div className="mt-5">
        {isLoadingSessions && !sessionsResponse ? (
          <TableSkeleton />
        ) : (
          <DataTable
            columns={columns}
            data={filteredSessions}
            showSearch={false}
            toolbarStart={toolbarStart}
            toolbarEnd={toolbarEnd}
            getRowId={(s) => s.id}
            onRowClick={handleViewDetails}
            emptyMessage={filtered ? 'No runs match these filters' : 'No scan runs yet'}
            emptyDescription={
              filtered
                ? 'Try another status or clear the search.'
                : 'Runs appear here once a scan configuration or quick scan starts.'
            }
          />
        )}
      </div>

      {/* Session Details Sheet */}
      <ScanSessionDetailSheet
        session={selectedSession}
        onOpenChange={(open) => !open && setSelectedSession(null)}
      />
    </>
  )
}
