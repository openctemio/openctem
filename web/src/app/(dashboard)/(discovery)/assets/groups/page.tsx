'use client'

import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { useState, useMemo, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  RiskScoreBadge,
  ErrorState,
  MetricStrip,
  type MetricStripItem,
  FacetPanel,
  FacetSection,
  FacetOption,
  BulkActionBar,
  FilterPanelToggle,
  FilterSheet,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Slider } from '@/components/ui/slider'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Plus,
  Download,
  RefreshCw,
  Eye,
  Pencil,
  Trash2,
  FolderKanban,
  Copy,
  Link,
  ExternalLink,
  SlidersHorizontal,
  Tags,
  Search as SearchIcon,
  Package,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { bulkTypeToConfirm, ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import {
  CreateGroupDialog,
  EditGroupDialog,
  GroupQuickView,
  type EditGroupFormData,
  useAllAssetGroups,
  useAssetGroupStats,
  useCreateAssetGroup,
  useUpdateAssetGroup,
  useDeleteAssetGroup,
  useBulkAssetGroupOperations,
} from '@/features/asset-groups'
import { useAssets } from '@/features/assets'
import { useDebounce } from '@/hooks/use-debounce'
import type { AssetGroup, CreateAssetGroupInput } from '@/features/asset-groups/types'
import type { Asset } from '@/features/assets/types'
import { GroupAddAssetsDialog } from '@/features/asset-groups/components/group-add-assets-dialog'
import type { AssetGroupApiFilters } from '@/features/asset-groups/api'
import { copyToClipboard } from '@/lib/clipboard'
import { Can, Permission } from '@/lib/permissions'
import { CriticalityBadge } from '@/features/assets/components/classification-badges'
import {
  CRITICALITY_LABELS,
  RATED_CRITICALITY_LEVELS,
  type RatedCriticality,
} from '@/lib/criticality'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

// ============================================
// CONSTANTS
// ============================================

type Environment = 'production' | 'staging' | 'development' | 'testing'
type Criticality = RatedCriticality

const ENVIRONMENTS: Environment[] = ['production', 'staging', 'development', 'testing']
const CRITICALITIES: readonly Criticality[] = RATED_CRITICALITY_LEVELS

const FILTERS_OPEN_KEY = 'openctem:asset-groups-filters-open'

/** A 0–100 score from a URL value; anything else falls back. */
function clampScore(raw: string, fallback: number): number {
  if (!/^\d+$/.test(raw)) return fallback
  return Math.min(100, Math.max(0, Number(raw)))
}

type Translate = ReturnType<typeof useTranslation>['t']

function assetGroupExportFields(t: Translate): ExportFieldConfig<AssetGroup>[] {
  return [
    { header: t('assetGroups.csv.name', 'Name'), accessor: (g) => g.name },
    {
      header: t('assetGroups.csv.description', 'Description'),
      accessor: (g) => g.description ?? '',
    },
    { header: t('assetGroups.csv.environment', 'Environment'), accessor: (g) => g.environment },
    { header: t('assetGroups.csv.criticality', 'Criticality'), accessor: (g) => g.criticality },
    {
      header: t('assetGroups.csv.businessUnit', 'Business unit'),
      accessor: (g) => g.businessUnit ?? '',
    },
    { header: t('assetGroups.csv.owner', 'Owner'), accessor: (g) => g.owner ?? '' },
    { header: t('assetGroups.csv.assets', 'Assets'), accessor: (g) => g.assetCount },
    { header: t('assetGroups.csv.findings', 'Findings'), accessor: (g) => g.findingCount },
    { header: t('assetGroups.csv.riskScore', 'Risk score'), accessor: (g) => g.riskScore },
    { header: t('assetGroups.csv.tags', 'Tags'), accessor: (g) => (g.tags ?? []).join('; ') },
  ]
}

// ============================================
// PAGE COMPONENT
// ============================================

export default function AssetGroupsPage() {
  const { t } = useTranslation()
  const router = useRouter()

  // Data hooks
  const { data: stats, isLoading: statsLoading } = useAssetGroupStats()
  const createAssetGroup = useCreateAssetGroup()
  const bulkOperations = useBulkAssetGroupOperations()

  // Filters live in the URL so a filtered view can be linked to.
  const [envParam, setEnvParam] = useUrlFilterList('environment')
  const [critParam, setCritParam] = useUrlFilterList('criticality')
  const [findingsParam, setFindingsParam] = useUrlFilter('findings', '')
  const [riskMinParam, setRiskMinParam] = useUrlFilter('risk_min', '0')
  const [riskMaxParam, setRiskMaxParam] = useUrlFilter('risk_max', '100')
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')

  const environments = useMemo(
    () => envParam.filter((v): v is Environment => (ENVIRONMENTS as string[]).includes(v)),
    [envParam]
  )
  const criticalities = useMemo(
    () => critParam.filter((v): v is Criticality => (CRITICALITIES as string[]).includes(v)),
    [critParam]
  )
  const hasFindings = findingsParam === 'yes' ? true : findingsParam === 'no' ? false : null
  const riskMin = clampScore(riskMinParam, 0)
  const riskMax = clampScore(riskMaxParam, 100)
  // The slider moves locally while dragging; the URL is written on release.
  const [riskDraft, setRiskDraft] = useState<[number, number] | null>(null)
  const riskRange: [number, number] = riskDraft ?? [riskMin, riskMax]

  // Filter panel: closed by default; the viewer's choice is remembered.
  const [filtersOpen, setFiltersOpenState] = useState(false)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  useEffect(() => {
    try {
      if (window.localStorage.getItem(FILTERS_OPEN_KEY) === '1') setFiltersOpenState(true)
    } catch {
      // storage unavailable — stay closed
    }
  }, [])
  const toggleFiltersOpen = useCallback(() => {
    setFiltersOpenState((prev) => {
      try {
        window.localStorage.setItem(FILTERS_OPEN_KEY, prev ? '0' : '1')
      } catch {
        // best-effort
      }
      return !prev
    })
  }, [])

  // Dialog state
  const [viewGroup, setViewGroup] = useState<AssetGroup | null>(null)
  const [editGroup, setEditGroup] = useState<AssetGroup | null>(null)
  const [deleteGroup, setDeleteGroup] = useState<AssetGroup | null>(null)
  const [addAssetsGroup, setAddAssetsGroup] = useState<AssetGroup | null>(null)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isEditSubmitting, setIsEditSubmitting] = useState(false)
  const [bulkDeleteConfirm, setBulkDeleteConfirm] = useState(false)

  // Selection state. The table owns the checkboxes; bumping the epoch clears them.
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectedIds([])
    setSelectionEpoch((n) => n + 1)
  }, [])

  const riskActive = riskMin > 0 || riskMax < 100
  const activeFilterCount =
    environments.length +
    criticalities.length +
    (riskActive ? 1 : 0) +
    (hasFindings !== null ? 1 : 0)

  // The search box writes the URL on every key; the request waits for a pause.
  const debouncedSearch = useDebounce(searchQuery.trim(), 300)

  // Build API filters
  const apiFilters = useMemo(() => {
    const result: AssetGroupApiFilters = {}
    if (environments.length > 0) result.environments = environments
    if (criticalities.length > 0) result.criticalities = criticalities
    if (riskMin > 0) result.min_risk_score = riskMin
    if (riskMax < 100) result.max_risk_score = riskMax
    if (hasFindings !== null) result.has_findings = hasFindings
    return result
  }, [environments, criticalities, riskMin, riskMax, hasFindings])
  const searchFilters = useMemo(
    () => (debouncedSearch ? { ...apiFilters, search: debouncedSearch } : apiFilters),
    [apiFilters, debouncedSearch]
  )

  // Fetch data
  // The server searches (name, description, tags) across every group.
  const {
    data: groups,
    total: groupsTotal,
    truncated,
    cap,
    isLoading,
    isError,
    error: listError,
    mutate: refreshData,
  } = useAllAssetGroups({ filters: searchFilters })
  const fetchedGroups = groups

  const exportFields = useMemo(() => assetGroupExportFields(t), [t])
  // CSV export of the current (filtered) groups list.
  const { handleExport: handleExportCsv } = useCsvExport(groups, exportFields, 'asset-groups')
  const handleExportJson = () => {
    if (!groups.length) {
      toast.error(t('assetGroups.noDataToExport', 'Nothing to export'))
      return
    }
    const blob = new Blob([JSON.stringify(groups, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `asset-groups-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Get all assets for create dialog (lazy: only fetch when dialog is open)
  const [createSearch, setCreateSearch] = useState('')
  const debouncedCreateSearch = useDebounce(createSearch.trim(), 300)
  const { assets: foundAssets } = useAssets({
    search: debouncedCreateSearch || undefined,
    pageSize: 20,
    skip: !isCreateOpen,
  })
  // Assets seen in any search, so the picks of an earlier search stay listed
  // (the review step names them) after the search term changes.
  const [seenAssets, setSeenAssets] = useState<Map<string, Asset>>(new Map())
  useEffect(() => {
    if (foundAssets.length === 0) return
    setSeenAssets((prev) => {
      const next = new Map(prev)
      for (const a of foundAssets) next.set(a.id, a)
      return next
    })
  }, [foundAssets])
  const allAssets = useMemo(() => Array.from(seenAssets.values()), [seenAssets])

  // Mutation hooks
  const updateAssetGroup = useUpdateAssetGroup(editGroup?.id || '')
  const deleteAssetGroupMutation = useDeleteAssetGroup(deleteGroup?.id || '')

  // Handlers
  const handleRefresh = () => {
    refreshData()
  }

  const handleCreate = async (input: CreateAssetGroupInput) => {
    await createAssetGroup.trigger(input)
    refreshData()
  }

  const handleEdit = async (formData: EditGroupFormData) => {
    if (!editGroup) return
    setIsEditSubmitting(true)
    try {
      await updateAssetGroup.trigger({
        name: formData.name,
        description: formData.description || undefined,
        environment: formData.environment,
        criticality: formData.criticality,
        businessUnit: formData.businessUnit || undefined,
        owner: formData.owner || undefined,
        ownerEmail: formData.ownerEmail || undefined,
        tags: formData.tags.length > 0 ? formData.tags : undefined,
      })
      refreshData()
      setEditGroup(null)
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t('assetGroups.updateFailed', 'Failed to update the group')
      )
    } finally {
      setIsEditSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteGroup) return
    try {
      await deleteAssetGroupMutation.trigger()
      refreshData()
    } catch {
      // Error handled by hook
    } finally {
      setDeleteGroup(null)
    }
  }

  // A bulk call can fail as a whole. The hook toasts the failure; here the
  // dialog closes and the list refreshes either way, so a failure no longer
  // leaves the confirm dialog open on a stale selection.
  const handleBulkDelete = async () => {
    try {
      await bulkOperations.bulkDelete(selectedIds)
      clearSelection()
    } catch {
      // Reported by the hook.
    } finally {
      setBulkDeleteConfirm(false)
      refreshData()
    }
  }

  const handleBulkAction = async (action: string, value?: string) => {
    const changes =
      action === 'change-criticality' && value
        ? { criticality: value }
        : action === 'change-environment' && value
          ? { environment: value }
          : null
    if (!changes) return
    try {
      await bulkOperations.bulkUpdate(selectedIds, changes)
      clearSelection()
    } catch {
      // Reported by the hook.
    } finally {
      refreshData()
    }
  }

  const handleCopyId = (id: string) => {
    copyToClipboard(id)
    toast.success(t('assetGroups.idCopied', 'Group ID copied'))
  }

  const handleCopyLink = (id: string) => {
    copyToClipboard(`${window.location.origin}/assets/groups/${id}`)
    toast.success(t('assetGroups.linkCopied', 'Link copied'))
  }

  const clearFilters = () => {
    setEnvParam([])
    setCritParam([])
    setFindingsParam('')
    setRiskMinParam('0')
    setRiskMaxParam('100')
    setRiskDraft(null)
  }

  const toggleIn = (setter: typeof setEnvParam, value: string, on: boolean) =>
    setter((prev) => (on ? [...prev, value] : prev.filter((v) => v !== value)))

  // Column definitions
  const columns: ColumnDef<AssetGroup>[] = [
    {
      id: 'select',
      header: ({ table }) => (
        <Checkbox
          checked={table.getIsAllPageRowsSelected()}
          onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
          aria-label={t('assetGroups.selectAll', 'Select all')}
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          onClick={(e) => e.stopPropagation()}
          aria-label={t('assetGroups.selectRow', 'Select row')}
        />
      ),
      enableSorting: false,
      enableHiding: false,
    },
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('assetGroups.col.name', 'Name')} />
      ),
      cell: ({ row }) => {
        const group = row.original
        return (
          <div className="flex min-w-0 items-center gap-2.5">
            <FolderKanban className="h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0">
              <p className="truncate font-medium">{group.name}</p>
              {group.description && (
                <p className="line-clamp-1 text-xs text-muted-foreground">{group.description}</p>
              )}
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'environment',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('assetGroups.col.environment', 'Environment')}
        />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">
          {t(`assetGroups.environment.${row.original.environment}`, row.original.environment)}
        </Badge>
      ),
      filterFn: (row, id, value) => value.includes(row.getValue(id)),
    },
    {
      accessorKey: 'criticality',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('assetGroups.col.criticality', 'Criticality')}
        />
      ),
      cell: ({ row }) => (
        <CriticalityBadge
          criticality={row.original.criticality as Criticality}
          showTooltip={false}
        />
      ),
      filterFn: (row, id, value) => value.includes(row.getValue(id)),
    },
    {
      accessorKey: 'assetCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('assetGroups.col.assets', 'Assets')} />
      ),
      cell: ({ row }) => <span className="tabular-nums">{row.original.assetCount}</span>,
    },
    {
      accessorKey: 'findingCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('assetGroups.col.findings', 'Findings')} />
      ),
      cell: ({ row }) => {
        const count = row.original.findingCount
        return (
          <span
            className={cn(
              'tabular-nums',
              count > 0 ? 'font-medium text-destructive' : 'text-muted-foreground'
            )}
          >
            {count}
          </span>
        )
      },
    },
    {
      accessorKey: 'riskScore',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('assetGroups.col.riskScore', 'Risk score')}
        />
      ),
      cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const group = row.original
        return (
          <DataTableRowActions
            actions={[
              {
                label: t('assetGroups.action.quickView', 'Quick view'),
                icon: Eye,
                onClick: () => setViewGroup(group),
              },
              {
                label: t('assetGroups.action.openFullPage', 'Open full page'),
                icon: ExternalLink,
                onClick: () => router.push(`/assets/groups/${group.id}`),
              },
              {
                label: t('assetGroups.action.edit', 'Edit'),
                icon: Pencil,
                onClick: () => setEditGroup(group),
                permission: Permission.AssetGroupsWrite,
              },
              {
                label: t('assetGroups.action.addAssets', 'Add assets'),
                icon: Plus,
                onClick: () => setAddAssetsGroup(group),
                permission: Permission.AssetGroupsWrite,
              },
              {
                label: t('assetGroups.action.manageAssets', 'Manage assets'),
                icon: Package,
                onClick: () => router.push(`/assets/groups/${group.id}?tab=assets`),
                permission: Permission.AssetGroupsWrite,
              },
              {
                label: t('assetGroups.action.copyId', 'Copy ID'),
                icon: Copy,
                onClick: () => handleCopyId(group.id),
                separatorBefore: true,
              },
              {
                label: t('assetGroups.action.copyLink', 'Copy link'),
                icon: Link,
                onClick: () => handleCopyLink(group.id),
              },
              {
                label: t('assetGroups.action.delete', 'Delete'),
                icon: Trash2,
                onClick: () => setDeleteGroup(group),
                destructive: true,
                separatorBefore: true,
                permission: Permission.AssetGroupsDelete,
              },
            ]}
          />
        )
      },
    },
  ]

  const criticalOnly = criticalities.length === 1 && criticalities[0] === 'critical'
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('assetGroups.metric.groups', 'Groups'),
      value: stats.total,
      onClick: clearFilters,
      active: activeFilterCount === 0,
    },
    {
      key: 'critical',
      label: t('assetGroups.metric.critical', 'Critical groups'),
      value: stats.byCriticality?.critical ?? 0,
      tone: 'danger',
      onClick: () => setCritParam(criticalOnly ? [] : ['critical']),
      active: criticalOnly,
    },
    {
      key: 'assets',
      label: t('assetGroups.metric.assetsInGroups', 'Assets in groups'),
      value: stats.totalAssets,
    },
    {
      key: 'risk',
      label: t('assetGroups.metric.avgRisk', 'Average risk score'),
      // One decimal: the raw average of integer scores can carry a long
      // repeating fractional tail (e.g. 53.16666666666664).
      value: Math.round((stats.averageRiskScore ?? 0) * 10) / 10,
      hint: t('assetGroups.metric.outOf100', 'of 100'),
    },
  ]

  const facetPanel = (
    <FacetPanel activeCount={activeFilterCount} onClearAll={clearFilters}>
      <FacetSection
        title={t('assetGroups.facet.environment', 'Environment')}
        selectedCount={environments.length}
      >
        {ENVIRONMENTS.map((env) => (
          <FacetOption
            key={env}
            label={t(`assetGroups.environment.${env}`, env)}
            checked={environments.includes(env)}
            onCheckedChange={(on) => toggleIn(setEnvParam, env, on)}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('assetGroups.facet.criticality', 'Criticality')}
        selectedCount={criticalities.length}
      >
        {CRITICALITIES.map((crit) => (
          <FacetOption
            key={crit}
            label={t(`criticality.${crit}`, CRITICALITY_LABELS[crit])}
            checked={criticalities.includes(crit)}
            onCheckedChange={(on) => toggleIn(setCritParam, crit, on)}
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('assetGroups.facet.findings', 'Findings')}
        selectedCount={hasFindings !== null ? 1 : 0}
      >
        <FacetOption
          label={t('assetGroups.facet.hasFindings', 'Has findings')}
          checked={hasFindings === true}
          onCheckedChange={(on) => setFindingsParam(on ? 'yes' : '')}
        />
        <FacetOption
          label={t('assetGroups.facet.noFindings', 'No findings')}
          checked={hasFindings === false}
          onCheckedChange={(on) => setFindingsParam(on ? 'no' : '')}
        />
      </FacetSection>
      <FacetSection
        title={t('assetGroups.facet.riskScore', 'Risk score')}
        selectedCount={riskActive ? 1 : 0}
      >
        <div className="space-y-3 pe-1.5 pt-1">
          <p className="text-xs tabular-nums text-muted-foreground">
            {riskRange[0]} – {riskRange[1]}
          </p>
          <Slider
            value={riskRange}
            onValueChange={(value) => setRiskDraft(value as [number, number])}
            onValueCommit={(value) => {
              setRiskMinParam(String(value[0]))
              setRiskMaxParam(String(value[1]))
              setRiskDraft(null)
            }}
            max={100}
            min={0}
            step={5}
            aria-label={t('assetGroups.facet.riskRange', 'Risk score range')}
          />
        </div>
      </FacetSection>
    </FacetPanel>
  )

  const toolbarStart = (
    <>
      <FilterPanelToggle
        open={filtersOpen}
        onToggle={toggleFiltersOpen}
        onOpenSheet={() => setFilterSheetOpen(true)}
        activeCount={activeFilterCount}
        controlsId="asset-group-filters"
      />
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder={t('assetGroups.search.placeholder', 'Search name, description or tag…')}
          aria-label={t('assetGroups.search.label', 'Search asset groups')}
          className="h-9 ps-9"
        />
      </div>
    </>
  )

  const toolbarEnd = (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="h-9 w-9"
            onClick={handleRefresh}
            disabled={isLoading}
            aria-label={t('assetGroups.refresh', 'Refresh')}
          >
            <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('assetGroups.refresh', 'Refresh')}</TooltipContent>
      </Tooltip>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="h-9">
            <Download className="h-4 w-4 md:me-2" />
            <span className="sr-only md:not-sr-only">{t('assetGroups.export', 'Export')}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={handleExportCsv} disabled={groups.length === 0}>
            {t('assetGroups.exportCsv', 'Export as CSV')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleExportJson} disabled={groups.length === 0}>
            {t('assetGroups.exportJson', 'Export as JSON')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  )

  return (
    <>
      <Main>
        <PageHeader
          title={t('assetGroups.title', 'Asset groups')}
          description={t(
            'assetGroups.description',
            'Organize and monitor assets by logical group.'
          )}
        >
          <Can permission={Permission.AssetGroupsWrite} mode="disable">
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="me-2 h-4 w-4" />
              {t('assetGroups.newGroup', 'New group')}
            </Button>
          </Can>
        </PageHeader>
        <AssetsSectionTabs />

        <MetricStrip className="mt-5" loading={statsLoading} items={metrics} />

        <div className="mt-5 flex items-start gap-5">
          {filtersOpen && (
            <aside
              id="asset-group-filters"
              aria-label={t('assetGroups.filtersLabel', 'Asset group filters')}
              className="sticky top-4 hidden max-h-[calc(100svh-7.5rem)] w-64 shrink-0 flex-col rounded-xl border bg-card p-4 shadow-sm lg:flex"
            >
              <div className="flex min-h-0 flex-1 flex-col">{facetPanel}</div>
            </aside>
          )}

          <div className="min-w-0 flex-1">
            {isError && fetchedGroups.length === 0 ? (
              <ErrorState
                title={t('assetGroups.errorTitle', 'asset groups')}
                error={listError}
                onRetry={() => refreshData()}
              />
            ) : isLoading && fetchedGroups.length === 0 ? (
              <div className="space-y-2 rounded-xl border p-3">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : (
              <DataTable
                columns={columns}
                data={groups}
                showSearch={false}
                toolbarStart={toolbarStart}
                toolbarEnd={toolbarEnd}
                emptyMessage={t('assetGroups.empty.title', 'No asset groups found')}
                emptyDescription={
                  activeFilterCount > 0 || searchQuery
                    ? t('assetGroups.empty.filtered', 'Try adjusting your search or filters')
                    : t('assetGroups.empty.none', 'Create a group to organize your assets')
                }
                onRowClick={(group) => setViewGroup(group)}
                getRowId={(group) => group.id}
                onSelectionChange={(rows) => setSelectedIds(rows.map((g) => g.id))}
                resetSelectionKey={selectionEpoch}
                showSelectionCount={false}
              />
            )}
            {truncated && (
              <p className="mt-2 text-xs text-muted-foreground">
                {t(
                  'assetGroups.truncated',
                  'Showing the first {shown} of {total} groups. Search or filter to narrow the list.',
                  {
                    shown: cap,
                    total: groupsTotal,
                  }
                )}
              </p>
            )}
          </div>
        </div>

        <BulkActionBar count={selectedIds.length} onClear={clearSelection} noun="selected">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8">
                <Tags className="me-2 h-4 w-4" />
                {t('assetGroups.bulk.criticality', 'Criticality')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              {CRITICALITIES.map((crit) => (
                <DropdownMenuItem
                  key={crit}
                  onClick={() => handleBulkAction('change-criticality', crit)}
                >
                  {t(`criticality.${crit}`, CRITICALITY_LABELS[crit])}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="h-8">
                <SlidersHorizontal className="me-2 h-4 w-4" />
                {t('assetGroups.bulk.environment', 'Environment')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              {ENVIRONMENTS.map((env) => (
                <DropdownMenuItem
                  key={env}
                  onClick={() => handleBulkAction('change-environment', env)}
                >
                  {t(`assetGroups.environment.${env}`, env)}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
          <Can permission={Permission.AssetGroupsDelete}>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 text-destructive hover:text-destructive"
              onClick={() => setBulkDeleteConfirm(true)}
            >
              <Trash2 className="me-2 h-4 w-4" />
              {t('assetGroups.action.delete', 'Delete')}
            </Button>
          </Can>
        </BulkActionBar>

        <FilterSheet
          open={filterSheetOpen}
          onOpenChange={setFilterSheetOpen}
          title={t('assetGroups.filtersLabel', 'Asset group filters')}
        >
          {facetPanel}
        </FilterSheet>
      </Main>

      {/* Quick View Sheet */}
      <GroupQuickView
        group={viewGroup}
        onClose={() => setViewGroup(null)}
        onEdit={setEditGroup}
        onDelete={setDeleteGroup}
        onRefresh={refreshData}
      />

      {/* Create Group Dialog */}
      <CreateGroupDialog
        open={isCreateOpen}
        onOpenChange={setIsCreateOpen}
        ungroupedAssets={foundAssets}
        reviewAssets={allAssets}
        onAssetSearchChange={setCreateSearch}
        onSubmit={handleCreate}
      />

      {/* Edit Dialog */}
      {editGroup && (
        <EditGroupDialog
          open={!!editGroup}
          onOpenChange={(open) => !open && setEditGroup(null)}
          group={editGroup}
          onSubmit={handleEdit}
          isSubmitting={isEditSubmitting}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteGroup}
        onOpenChange={() => setDeleteGroup(null)}
        title={t('confirm.assetGroup.deleteTitle', 'Delete the asset group "{name}"?', {
          name: deleteGroup?.name ?? '',
        })}
        desc={t(
          'confirm.assetGroup.deleteDesc',
          'The group is deleted and its assets leave it; scans and rules that target the group no longer cover them. The assets themselves are not deleted. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={handleDelete}
      />

      {/* Bulk Delete Confirmation */}
      <ConfirmDialog
        open={bulkDeleteConfirm}
        onOpenChange={setBulkDeleteConfirm}
        title={
          selectedIds.length === 1
            ? t('confirm.assetGroup.bulkDeleteTitleOne', 'Delete 1 asset group?')
            : t('confirm.assetGroup.bulkDeleteTitle', 'Delete {count} asset groups?', {
                count: selectedIds.length,
              })
        }
        desc={t(
          'confirm.assetGroup.bulkDeleteDesc',
          'The groups are deleted and their assets leave them; scans and rules that target these groups no longer cover them. The assets themselves are not deleted. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        typeToConfirm={bulkTypeToConfirm(selectedIds.length)}
        handleConfirm={handleBulkDelete}
      />

      {/* Add Assets Dialog */}
      {addAssetsGroup && (
        <GroupAddAssetsDialog
          group={addAssetsGroup}
          onClose={() => setAddAssetsGroup(null)}
          onSuccess={() => {
            refreshData()
            setAddAssetsGroup(null)
          }}
        />
      )}
    </>
  )
}
