'use client'

import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { useState, useMemo, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  RiskScoreBadge,
  EmptyState,
  MetricStrip,
  type MetricStripItem,
  FacetPanel,
  FacetSection,
  FacetOption,
  FilterSheet,
  PageStack,
  usePhoneSelectMode,
} from '@/features/shared'
import type {
  DataTableBulk,
  DataTableSelection,
} from '@/features/shared/components/data-table/data-table-selection'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { Slider } from '@/components/ui/slider'
import {
  Plus,
  Download,
  RefreshCw,
  Eye,
  Pencil,
  Trash2,
  FolderKanban,
  Link,
  ExternalLink,
  SearchX,
  Package,
  MoreHorizontal,
} from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  ConfirmDialog,
  ConfirmSample,
  irreversibleTypeToConfirm,
} from '@/components/confirm-dialog'
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
import { useSearchQuery } from '@/hooks/use-search-query'
import type { AssetGroup, CreateAssetGroupInput } from '@/features/asset-groups/types'
import type { Asset } from '@/features/assets/types'
import { GroupAddAssetsDialog } from '@/features/asset-groups/components/group-add-assets-dialog'
import { GroupAddFilter } from '@/features/asset-groups/components/group-add-filter'
import { assetGroupHref } from '@/features/asset-groups/lib/group-link'
import type { AssetGroupApiFilters } from '@/features/asset-groups/api'
import { copyToClipboard } from '@/lib/clipboard'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { accessStateOf } from '@/lib/api/access-state'
import { useIsMobile } from '@/hooks/use-mobile'
import { CriticalityBadge } from '@/features/assets/components/classification-badges'
import {
  CRITICALITY_LABELS,
  RATED_CRITICALITY_LEVELS,
  type RatedCriticality,
} from '@/lib/criticality'
import { useCsvExport } from '@/hooks/use-csv-export'
import { assetGroupExportFields } from '@/features/asset-groups/lib/group-export'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { confirmName } from '@/lib/confirm-name'
import { shareableLink } from '@/lib/org-link'

// ============================================
// CONSTANTS
// ============================================

type Environment = 'production' | 'staging' | 'development' | 'testing'
type Criticality = RatedCriticality

const ENVIRONMENTS: Environment[] = ['production', 'staging', 'development', 'testing']
const CRITICALITIES: readonly Criticality[] = RATED_CRITICALITY_LEVELS

/** A 0–100 score from a URL value; anything else falls back. */
function clampScore(raw: string, fallback: number): number {
  if (!/^\d+$/.test(raw)) return fallback
  return Math.min(100, Math.max(0, Number(raw)))
}

// ============================================
// PAGE COMPONENT
// ============================================

export default function AssetGroupsPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const { can } = usePermissions()
  const canWrite = can(Permission.AssetGroupsWrite)
  const canDelete = can(Permission.AssetGroupsDelete)
  const isPhone = useIsMobile()

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

  // One filter entry per width: Add filter from 768, the Filters sheet on a phone.
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)

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
  const [selectedNames, setSelectedNames] = useState<string[]>([])
  const onSelectionChange = useCallback((selection: DataTableSelection<AssetGroup> | null) => {
    const rows = selection?.kind === 'ids' ? selection.rows : []
    setSelectedIds(rows.map((g) => g.id))
    setSelectedNames(rows.map((g) => g.name))
  }, [])
  // A bulk criticality or environment change waits here for the user to confirm.
  const [pendingBulk, setPendingBulk] = useState<{
    action: 'change-criticality' | 'change-environment'
    value: string
    label: string
  } | null>(null)
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectedIds([])
    setSelectedNames([])
    setSelectionEpoch((n) => n + 1)
  }, [])

  const riskActive = riskMin > 0 || riskMax < 100
  const activeFilterCount =
    environments.length +
    criticalities.length +
    (riskActive ? 1 : 0) +
    (hasFindings !== null ? 1 : 0)

  // The search box writes the URL on every key; the request waits for a pause.
  const debouncedSearch = useSearchQuery(searchQuery).term

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
  const debouncedCreateSearch = useSearchQuery(createSearch).term
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
      setPendingBulk(null)
      refreshData()
    }
  }

  const handleCopyLink = (id: string) => {
    copyToClipboard(shareableLink(assetGroupHref(id)))
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

  const clearAll = () => {
    clearFilters()
    setSearchQuery('')
  }

  // Column definitions. One line per row: the description is in the quick
  // view and on the group page.
  const columns: ColumnDef<AssetGroup>[] = [
    {
      accessorKey: 'name',
      meta: {
        kind: 'name',
        pin: 'start',
        // The other columns' floors leave 180 at a 1024 screen (frame 700).
        minWidth: 180,
        label: t('assetGroups.col.name', 'Name'),
      },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('assetGroups.col.name', 'Name')} />
      ),
      cell: ({ row }) => {
        const group = row.original
        return (
          // No width of its own (w-0): the name never widens its column past
          // the frame, and the link ends in an ellipsis inside it.
          <div data-slot="group-name-cell" className="flex w-0 min-w-full items-center">
            <RowNameLink
              href={assetGroupHref(group.id)}
              onOpen={() => setViewGroup(group)}
              title={group.name}
            >
              {group.name}
            </RowNameLink>
          </div>
        )
      },
    },
    {
      accessorKey: 'environment',
      meta: {
        kind: 'status',
        hideBelow: 760,
        label: t('assetGroups.col.environment', 'Environment'),
      },
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
      meta: { kind: 'status', label: t('assetGroups.col.criticality', 'Criticality') },
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
      meta: { kind: 'number', label: t('assetGroups.col.assets', 'Assets') },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('assetGroups.col.assets', 'Assets')} />
      ),
      cell: ({ row }) => <span className="tabular-nums">{row.original.assetCount}</span>,
    },
    {
      accessorKey: 'findingCount',
      meta: { kind: 'number', label: t('assetGroups.col.findings', 'Findings') },
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
      meta: { kind: 'risk', label: t('assetGroups.col.riskScore', 'Risk score') },
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
      meta: { kind: 'actions', label: t('assetGroups.col.actions', 'Actions') },
      enableSorting: false,
      enableHiding: false,
      cell: ({ row }) => {
        const group = row.original
        return (
          <DataTableRowActions
            title={group.name}
            label={t('common.rowActions.actionsFor', 'Actions for {name}', { name: group.name })}
            actions={[
              {
                label: t('assetGroups.action.quickView', 'Quick view'),
                icon: Eye,
                onClick: () => setViewGroup(group),
              },
              {
                label: t('assetGroups.action.openFullPage', 'Open full page'),
                icon: ExternalLink,
                onClick: () => router.push(assetGroupHref(group.id)),
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
                onClick: () => router.push(`${assetGroupHref(group.id)}?tab=assets`),
                permission: Permission.AssetGroupsWrite,
              },
              {
                label: t('assetGroups.action.copyLink', 'Copy link'),
                icon: Link,
                onClick: () => handleCopyLink(group.id),
                separatorBefore: true,
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
      onClick: () => setCritParam(criticalOnly ? [] : ['critical']),
      active: criticalOnly,
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

  // The filters on screen, one chip per field ("Field: values"); removing a
  // chip clears that field.
  const chipList: { key: string; text: string; clear: () => void }[] = [
    ...(environments.length > 0
      ? [
          {
            key: 'environment',
            text: t('assetGroups.chip.field', '{field}: {values}', {
              field: t('assetGroups.facet.environment', 'Environment'),
              values: environments.map((e) => t(`assetGroups.environment.${e}`, e)).join(', '),
            }),
            clear: () => setEnvParam([]),
          },
        ]
      : []),
    ...(criticalities.length > 0
      ? [
          {
            key: 'criticality',
            text: t('assetGroups.chip.field', '{field}: {values}', {
              field: t('assetGroups.facet.criticality', 'Criticality'),
              values: criticalities
                .map((c) => t(`criticality.${c}`, CRITICALITY_LABELS[c]))
                .join(', '),
            }),
            clear: () => setCritParam([]),
          },
        ]
      : []),
    ...(hasFindings !== null
      ? [
          {
            key: 'findings',
            text: t('assetGroups.chip.field', '{field}: {values}', {
              field: t('assetGroups.facet.findings', 'Findings'),
              values: hasFindings
                ? t('assetGroups.facet.hasFindings', 'Has findings')
                : t('assetGroups.facet.noFindings', 'No findings'),
            }),
            clear: () => setFindingsParam(''),
          },
        ]
      : []),
    ...(riskActive
      ? [
          {
            key: 'risk',
            text: t('assetGroups.chip.risk', 'Risk score: {min} to {max}', {
              min: riskMin,
              max: riskMax,
            }),
            clear: () => {
              setRiskMinParam('0')
              setRiskMaxParam('100')
              setRiskDraft(null)
            },
          },
        ]
      : []),
  ]
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="asset-groups-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('assetGroups.chip.remove', 'Remove filter {filter}', {
              filter: c.text,
            })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearFilters : undefined}
      />
    ) : undefined

  // Several groups at once. Without a bulk permission there is no checkbox
  // column; each action shows only to who may use it.
  const criticalityItems: ActionMenuEntry[] = CRITICALITIES.map((crit) => ({
    id: crit,
    label: t(`criticality.${crit}`, CRITICALITY_LABELS[crit]),
    onSelect: () =>
      setPendingBulk({
        action: 'change-criticality',
        value: crit,
        label: t(`criticality.${crit}`, CRITICALITY_LABELS[crit]),
      }),
  }))
  const environmentItems: ActionMenuEntry[] = ENVIRONMENTS.map((env) => ({
    id: env,
    label: t(`assetGroups.environment.${env}`, env),
    onSelect: () =>
      setPendingBulk({
        action: 'change-environment',
        value: env,
        label: t(`assetGroups.environment.${env}`, env),
      }),
  }))
  const groupsBulk: DataTableBulk<AssetGroup> | undefined =
    canWrite || canDelete
      ? {
          rowLabel: (g) => g.name,
          noun: (count) => t('assetGroups.bulk.noun', 'groups selected', { count }),
          onSelectionChange,
          actions: canWrite ? (
            <>
              <ActionMenu
                title={t('assetGroups.bulk.criticality', 'Criticality')}
                label={t('assetGroups.bulk.criticalityFor', 'Set the criticality of the selection')}
                items={criticalityItems}
                trigger={
                  <Button variant="ghost" size="sm">
                    {t('assetGroups.bulk.criticality', 'Criticality')}
                  </Button>
                }
              />
              <ActionMenu
                title={t('assetGroups.bulk.environment', 'Environment')}
                label={t('assetGroups.bulk.environmentFor', 'Set the environment of the selection')}
                items={environmentItems}
                trigger={
                  <Button variant="ghost" size="sm">
                    {t('assetGroups.bulk.environment', 'Environment')}
                  </Button>
                }
              />
            </>
          ) : null,
          more: canDelete
            ? [
                {
                  id: 'delete',
                  label: t('assetGroups.action.delete', 'Delete'),
                  destructive: true,
                  onSelect: () => setBulkDeleteConfirm(true),
                },
              ]
            : undefined,
        }
      : undefined
  // Phone cards have no header checkbox: "Select" starts the list's More.
  const phoneSelect = usePhoneSelectMode(isPhone && !!groupsBulk)

  const nothingToExport =
    groups.length === 0 ? t('assetGroups.noDataToExport', 'Nothing to export') : undefined
  const exportItems: ActionMenuEntry[] = [
    {
      id: 'export-csv',
      label: t('assetGroups.exportCsv', 'Export as CSV'),
      disabledReason: nothingToExport,
      onSelect: handleExportCsv,
    },
    {
      id: 'export-json',
      label: t('assetGroups.exportJson', 'Export as JSON'),
      disabledReason: nothingToExport,
      onSelect: handleExportJson,
    },
  ]
  const viewTitle = t('assetGroups.viewAll', 'All groups')
  // On a phone the list's actions are one More, so the row keeps its name and count.
  const phoneMoreItems: ActionMenuEntry[] = [
    ...(phoneSelect.item ? [phoneSelect.item] : []),
    { id: 'refresh', label: t('assetGroups.refresh', 'Refresh'), onSelect: handleRefresh },
    ...exportItems,
  ]
  const listActions = isPhone ? (
    <ActionMenu
      title={viewTitle}
      label={t('common.actionMenu.label', 'Actions for {name}', { name: viewTitle })}
      items={phoneMoreItems}
      trigger={
        <Button
          variant="outline"
          size="icon"
          aria-label={t('assetGroups.moreActions', 'More actions')}
        >
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </Button>
      }
    />
  ) : (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            onClick={handleRefresh}
            disabled={isLoading}
            aria-label={t('assetGroups.refresh', 'Refresh')}
          >
            <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} aria-hidden />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('assetGroups.refresh', 'Refresh')}</TooltipContent>
      </Tooltip>
      <ActionMenu
        title={t('assetGroups.export', 'Export')}
        label={t('assetGroups.exportLabel', 'Export the groups in the list')}
        items={exportItems}
        trigger={
          <Button variant="outline" size="sm">
            <Download className="me-2 h-4 w-4" aria-hidden />
            {t('assetGroups.export', 'Export')}
          </Button>
        }
      />
    </>
  )

  const narrowed = activeFilterCount > 0 || !!searchQuery
  const firstLoad = isLoading && fetchedGroups.length === 0
  const noAccess = isError && accessStateOf(listError) === 'no_access'

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('assetGroups.title', 'Asset groups')}
            description={t('assetGroups.description', 'Organize and monitor assets by group.')}
          >
            <Can permission={Permission.AssetGroupsWrite} mode="disable">
              <Button
                size="sm"
                iconOnlyBelow="md"
                aria-label={t('assetGroups.newGroup', 'New group')}
                onClick={() => setIsCreateOpen(true)}
              >
                <Plus className="h-4 w-4 md:me-2" aria-hidden />
                <span className="sr-only md:not-sr-only">
                  {t('assetGroups.newGroup', 'New group')}
                </span>
              </Button>
            </Can>
          </PageHeader>
          <AssetsSectionTabs />

          {/* On a phone the list starts sooner: both numbers are reachable there
              (the count in the title row, Criticality in the Filters sheet). */}
          <MetricStrip loading={statsLoading} items={metrics} className="max-md:hidden" />

          {/* The list's title row: its name and its one count (the groups the
              list shows, filters and search applied), then the list's actions. */}
          <ListTitleRow
            title={viewTitle}
            count={
              <ListCount
                total={groupsTotal}
                loading={firstLoad || isError}
                label={t('assetGroups.count', '{count, plural, one {# group} other {# groups}}', {
                  count: groupsTotal,
                })}
              />
            }
          >
            {!isPhone && listActions}
          </ListTitleRow>

          {noAccess ? (
            <NoAccessState title={t('assetGroups.subject', 'the asset groups list')} />
          ) : (
            <DataTable
              columns={columns}
              data={groups}
              caption={t('assetGroups.title', 'Asset groups')}
              // The row actions stay in view on a narrow frame (as on /scans).
              pinActions
              // A failed read keeps the toolbar, so a search or filter from a
              // shared link can still be changed.
              error={isError && fetchedGroups.length === 0 ? listError : undefined}
              onRetry={() => refreshData()}
              errorTitle={t('assetGroups.errorTitle', 'asset groups')}
              // The first read: skeleton rows under a toolbar that stays mounted.
              isLoading={firstLoad}
              showSearch={false}
              search={{
                value: searchQuery,
                onChange: setSearchQuery,
                placeholder: isPhone
                  ? t('assetGroups.search.placeholderShort', 'Search groups…')
                  : t('assetGroups.search.placeholder', 'Search name, description or tag…'),
                label: t('assetGroups.search.label', 'Search asset groups'),
              }}
              // One filter entry per width: Add filter from 768, this button
              // (joined to the search field) on a phone, where it opens the sheet.
              filterToggle={{
                open: false,
                onToggle: () => setFilterSheetOpen(true),
                onOpenSheet: () => setFilterSheetOpen(true),
                activeCount: activeFilterCount,
                controlsId: 'asset-group-filters',
                label: t('assetGroups.filtersLabel', 'Asset group filters'),
                sheetOnly: true,
              }}
              toolbarStart={<GroupAddFilter>{facetPanel}</GroupAddFilter>}
              // On a phone the "..." menu (Refresh inside it) ends the toolbar.
              toolbarEnd={isPhone ? listActions : undefined}
              toolbarBelow={chipsRow}
              paginationNoun={t('assetGroups.noun', 'groups')}
              onRowClick={(group) => setViewGroup(group)}
              getRowId={(group) => group.id}
              // No bulk action for this user: no checkbox column either.
              bulk={groupsBulk}
              selectMode={phoneSelect.selectMode}
              resetSelectionKey={selectionEpoch}
              showSelectionCount={false}
              isFiltered={narrowed}
              onClearFilters={clearAll}
              emptyState={{
                nothingYet: (
                  <EmptyState
                    icon={FolderKanban}
                    title={t('assetGroups.empty.nothingYet', 'No asset groups yet')}
                    description={t(
                      'assetGroups.empty.none',
                      'Create a group to organize your assets'
                    )}
                    action={
                      canWrite ? (
                        <Button size="sm" onClick={() => setIsCreateOpen(true)}>
                          {t('assetGroups.newGroup', 'New group')}
                        </Button>
                      ) : undefined
                    }
                  />
                ),
                noMatch: (
                  <EmptyState
                    icon={SearchX}
                    title={t('assetGroups.empty.title', 'No asset groups found')}
                    description={t(
                      'assetGroups.empty.filtered',
                      'Try adjusting your search or filters'
                    )}
                    action={
                      <Button variant="outline" size="sm" onClick={clearAll}>
                        {t('common.table.clearFilters', 'Clear filters')}
                      </Button>
                    }
                  />
                ),
              }}
            />
          )}
          {truncated && (
            <p className="text-xs text-muted-foreground" role="status">
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

          <FilterSheet
            open={filterSheetOpen}
            onOpenChange={setFilterSheetOpen}
            title={t('assetGroups.filtersLabel', 'Asset group filters')}
          >
            {facetPanel}
          </FilterSheet>
        </PageStack>
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
          'The group is deleted for good and its assets leave it; scans and rules that target the group no longer cover them. The assets themselves are kept.'
        )}
        confirmText={t('confirm.assetGroup.deleteButton', 'Delete group')}
        destructive
        typeToConfirm={deleteGroup ? confirmName(deleteGroup.name, deleteGroup.id) : undefined}
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
          'The groups are deleted for good and their assets leave them; scans and rules that target these groups no longer cover them. The assets themselves are kept.'
        )}
        confirmText={
          selectedIds.length === 1
            ? t('confirm.assetGroup.bulkDeleteButtonOne', 'Delete 1 group')
            : t('confirm.assetGroup.bulkDeleteButton', 'Delete {count} groups', {
                count: selectedIds.length,
              })
        }
        destructive
        typeToConfirm={irreversibleTypeToConfirm(selectedNames)}
        handleConfirm={handleBulkDelete}
      >
        <ConfirmSample names={selectedNames} total={selectedIds.length} />
      </ConfirmDialog>

      {/* Bulk criticality / environment */}
      <ConfirmDialog
        open={!!pendingBulk}
        onOpenChange={(open) => !open && setPendingBulk(null)}
        title={
          pendingBulk?.action === 'change-criticality'
            ? t(
                'confirm.assetGroup.bulkCriticalityTitle',
                'Set the criticality to {value} for {count} selected?',
                { count: selectedIds.length, value: pendingBulk.label }
              )
            : t(
                'confirm.assetGroup.bulkEnvironmentTitle',
                'Set the environment to {value} for {count} selected?',
                { count: selectedIds.length, value: pendingBulk?.label ?? '' }
              )
        }
        desc={
          pendingBulk?.action === 'change-criticality'
            ? t(
                'confirm.assetGroup.bulkCriticalityDesc',
                "The value replaces each group's current criticality and can change how its findings are prioritised. You can set it back to the old value later."
              )
            : t(
                'confirm.assetGroup.bulkEnvironmentDesc',
                "The value replaces each group's current environment. You can set it back to the old value later."
              )
        }
        confirmText={t('confirm.assetGroup.bulkApplyButton', 'Update {count} selected', {
          count: selectedIds.length,
        })}
        handleConfirm={() => {
          if (pendingBulk) return handleBulkAction(pendingBulk.action, pendingBulk.value)
        }}
      >
        <ConfirmSample names={selectedNames} total={selectedIds.length} />
      </ConfirmDialog>

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
