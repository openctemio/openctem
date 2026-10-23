'use client'

import { use, useState, useMemo, useCallback } from 'react'
import NextLink from '@/components/link'
import { useRouter } from 'next/navigation'
import { replaceUrlSearch, useUrlParams } from '@/hooks/use-url-param'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import type { ColumnDef } from '@tanstack/react-table'
import {
  PageHeader,
  RiskScoreBadge,
  StatsCard,
  SeverityBadge,
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  ErrorState,
} from '@/features/shared'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { Can, Permission } from '@/lib/permissions'
import { CRITICALITY_BADGE_SOFT } from '@/lib/criticality-colors'
import { CRITICALITY_LABELS } from '@/lib/criticality'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Tabs, TabsContent, TabsList, TabsTrigger, TabsCount } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { Checkbox } from '@/components/ui/checkbox'
import { toast } from 'sonner'
import {
  ArrowLeft,
  FolderKanban,
  Pencil,
  Trash2,
  Plus,
  MoreHorizontal,
  ExternalLink,
  Copy,
  Globe,
  Server,
  Database,
  Cloud,
  GitBranch,
  Download,
  X,
  Link,
  Eye,
  Building2,
  User,
  Mail,
  Tags,
  Package,
} from 'lucide-react'
import {
  useAssetGroup,
  useGroupAssets,
  useGroupFindings,
  useUpdateAssetGroup,
  useDeleteAssetGroup,
  useRemoveAssetsFromGroup,
  useAddAssetsToGroup,
  EditGroupDialog,
  type EditGroupFormData,
  AddAssetsDialog,
  type AddAssetsSubmitData,
  type GroupAsset,
  type GroupFinding,
} from '@/features/asset-groups'
import { groupMemberHref } from '@/features/asset-groups/lib/member-link'
import { useCsvExport, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { IssuesChip } from '@/features/assets/components/service-cells'
import { SEVERITY_LEVELS, normalizeSeverity, type SeverityLevel } from '@/lib/severity'
import { useTranslation } from '@/context/i18n-provider'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'

const criticalityColors: Record<string, string> = CRITICALITY_BADGE_SOFT

/** Most severe first when sorted descending. */
const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

const assetStatusClass: Record<string, string> = {
  active: 'border-success/30 bg-success/15 text-success',
  monitoring: 'border-info/30 bg-info/15 text-info',
}

const findingStatusClass: Record<string, string> = {
  resolved: 'border-success/30 bg-success/15 text-success',
  in_progress: 'border-info/30 bg-info/15 text-info',
}

const assetTypeIcons: Record<string, React.ReactNode> = {
  domain: <Globe className="h-4 w-4" />,
  subdomain: <Globe className="h-4 w-4" />,
  ip_address: <Globe className="h-4 w-4" />,
  application: <Globe className="h-4 w-4" />,
  website: <Globe className="h-4 w-4" />,
  api: <Server className="h-4 w-4" />,
  host: <Server className="h-4 w-4" />,
  cloud: <Cloud className="h-4 w-4" />,
  project: <GitBranch className="h-4 w-4" />,
  repository: <GitBranch className="h-4 w-4" />, // @deprecated
  database: <Database className="h-4 w-4" />,
}

interface PageProps {
  params: Promise<{ id: string }>
}

type Translate = ReturnType<typeof useTranslation>['t']

function groupAssetExportFields(t: Translate): ExportFieldConfig<GroupAsset>[] {
  return [
    { header: t('assetGroups.csv.name', 'Name'), accessor: (a) => a.name },
    { header: t('assetGroups.detail.csv.type', 'Type'), accessor: (a) => a.type },
    { header: t('assetGroups.detail.csv.status', 'Status'), accessor: (a) => a.status },
    { header: t('assetGroups.csv.riskScore', 'Risk score'), accessor: (a) => a.riskScore ?? '' },
    { header: t('assetGroups.csv.findings', 'Findings'), accessor: (a) => a.findingCount ?? 0 },
    {
      header: t('assetGroups.detail.csv.lastSeen', 'Last seen'),
      accessor: (a) => a.lastSeen ?? '',
    },
  ]
}

export default function AssetGroupDetailPage({ params }: PageProps) {
  return <AssetGroupDetailContent params={params} />
}

function AssetGroupDetailContent({ params }: PageProps) {
  const { t } = useTranslation()
  const { id } = use(params)
  const router = useRouter()

  // Data fetching with hooks
  const {
    data: group,
    isLoading: groupLoading,
    error: groupError,
    mutate: refreshGroup,
  } = useAssetGroup(id)
  useBreadcrumbTitle(group?.name)
  // One page of 100 (the API default is 20). A larger group is said to be
  // partial wherever its rows are counted (see `partialNote`).
  const {
    data: assets,
    isLoading: assetsLoading,
    mutate: mutateAssets,
  } = useGroupAssets(id, { per_page: 100 })
  const {
    data: findings,
    total: findingsTotal,
    isLoading: findingsLoading,
  } = useGroupFindings(id, 1, 100)

  // Mutations
  const { trigger: updateGroup, isMutating: isUpdating } = useUpdateAssetGroup(id)
  const { trigger: deleteGroup, isMutating: isDeleting } = useDeleteAssetGroup(id)
  const { trigger: removeAssets, isMutating: isRemovingAssets } = useRemoveAssetsFromGroup(id)
  const { trigger: addAssets, isMutating: isAddingAssets } = useAddAssetsToGroup(id)

  // URL Search Params for tab sync
  const searchParams = useUrlParams()

  // Use URL as source of truth for active tab
  const activeTab = searchParams.get('tab') || 'overview'

  // Update URL when tab changes
  const handleTabChange = useCallback(
    (tab: string) => {
      const params = new URLSearchParams(searchParams.toString())
      if (tab === 'overview') {
        params.delete('tab')
      } else {
        params.set('tab', tab)
      }
      replaceUrlSearch(params)
    },
    [searchParams]
  )
  // The assets table owns its checkboxes; this mirrors the ticked ids for the
  // bulk remove, and bumping selectionEpoch clears the table's copy.
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)

  // Dialog State
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [removeAssetsDialogOpen, setRemoveAssetsDialogOpen] = useState(false)
  const [addAssetsDialogOpen, setAddAssetsDialogOpen] = useState(false)

  // Derived data from hooks - wrapped in useMemo to prevent unnecessary re-renders
  const safeAssets = useMemo(() => assets || [], [assets])
  // The group's finding count, its severity breakdown and its findings tab
  // cover the same set: open findings on the group's members.
  const safeFindings = useMemo(() => (findings || []).filter((f) => f.open), [findings])
  const { registry } = useAssetTypeRegistry()
  // The registry's label of a stored asset type (never a fixed list).
  const typeLabel = useCallback(
    (type: string) => {
      const def = registry?.types?.find((d) => d.type === type && !d.alias_of)
      return def?.label ?? type.replace(/_/g, ' ')
    },
    [registry]
  )
  // Only the first page of members and findings is loaded. Every figure
  // computed from the loaded rows (the Assets tab, the exports and the
  // breakdowns) says so instead of presenting a partial set as the whole.
  const assetsPartial = !!group && group.assetCount > safeAssets.length
  const findingsPartial = findingsTotal > (findings?.length ?? 0)
  const partialNote = (loaded: number, total: number) =>
    t('assetGroups.detail.partial', 'Based on the first {loaded} of {total}', { loaded, total })
  const findingsHref = (severity?: string) =>
    `/findings?asset_group_id=${encodeURIComponent(id)}${severity ? `&severity=${severity}` : ''}`

  const exportFields = useMemo(() => groupAssetExportFields(t), [t])
  // CSV export of the group's assets. Declared before any early return so the
  // hook order stays stable (rules-of-hooks).
  const { handleExport: exportAssetsCsv } = useCsvExport(
    safeAssets,
    exportFields,
    group ? `asset-group-${group.name}` : 'asset-group'
  )

  const assetsByType = useMemo(() => {
    const counts: Record<string, number> = {}
    safeAssets.forEach((a) => {
      counts[a.type] = (counts[a.type] || 0) + 1
    })
    return counts
  }, [safeAssets])

  const findingsBySeverity = useMemo(() => {
    const counts = Object.fromEntries(SEVERITY_LEVELS.map((s) => [s, 0])) as Record<
      SeverityLevel,
      number
    >
    safeFindings.forEach((f) => {
      const s = normalizeSeverity(f.severity)
      if (s) counts[s] += 1
    })
    return counts
  }, [safeFindings])

  // Table columns - defined before the early returns (rules-of-hooks).
  const assetColumns = useMemo<ColumnDef<GroupAsset>[]>(
    () => [
      {
        id: 'select',
        enableSorting: false,
        enableHiding: false,
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && 'indeterminate')
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label={t('assetGroups.detail.selectAll', 'Select all')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={t('assetGroups.detail.selectRow', 'Select {name}', {
              name: row.original.name,
            })}
          />
        ),
      },
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.asset', 'Asset')}
          />
        ),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-muted text-muted-foreground">
              {assetTypeIcons[row.original.type] ?? <Server className="h-4 w-4" />}
            </span>
            <span className="font-medium">{row.original.name}</span>
          </div>
        ),
      },
      {
        accessorKey: 'type',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assetGroups.detail.col.type', 'Type')} />
        ),
        cell: ({ row }) => <Badge variant="outline">{typeLabel(row.original.type)}</Badge>,
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => (
          <Badge
            variant="outline"
            className={cn(
              assetStatusClass[row.original.status] ?? 'bg-muted text-muted-foreground'
            )}
          >
            {t(`assets.status.${row.original.status}`, row.original.status.replace(/_/g, ' '))}
          </Badge>
        ),
      },
      {
        accessorKey: 'riskScore',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.riskScore', 'Risk score')}
          />
        ),
        cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
      },
      {
        accessorKey: 'findingCount',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.findings', 'Findings')}
          />
        ),
        // The shared "N issues found" chip, linking to the asset's findings.
        cell: ({ row }) =>
          row.original.findingCount > 0 ? (
            <IssuesChip assetId={row.original.id} count={row.original.findingCount} />
          ) : (
            <span className="text-muted-foreground tabular-nums">0</span>
          ),
      },
      {
        accessorKey: 'lastSeen',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.lastSeen', 'Last seen')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {new Date(row.original.lastSeen).toLocaleDateString()}
          </span>
        ),
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => router.push(groupMemberHref(row.original.id))}
            aria-label={t('assetGroups.detail.openAsset', 'Open {name}', {
              name: row.original.name,
            })}
            title={t('assetGroups.detail.viewAsset', 'View asset details')}
          >
            <ExternalLink className="h-4 w-4" />
          </Button>
        ),
      },
    ],
    [router, typeLabel, t]
  )

  const findingColumns = useMemo<ColumnDef<GroupFinding>[]>(
    () => [
      {
        accessorKey: 'title',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.finding', 'Finding')}
          />
        ),
        cell: ({ row }) => <span className="font-medium">{row.original.title}</span>,
      },
      {
        accessorKey: 'severity',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.severity', 'Severity')}
          />
        ),
        sortingFn: (a, b) =>
          (SEVERITY_RANK[a.original.severity] ?? 0) - (SEVERITY_RANK[b.original.severity] ?? 0),
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => (
          <Badge
            variant="outline"
            className={cn(
              findingStatusClass[row.original.status] ??
                'border-warning/30 bg-warning/15 text-warning'
            )}
          >
            {t(`findings.status.${row.original.status}`, row.original.status.replace(/_/g, ' '))}
          </Badge>
        ),
      },
      {
        accessorKey: 'assetName',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.asset', 'Asset')}
          />
        ),
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.assetName}</span>,
      },
      {
        accessorKey: 'discoveredAt',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assetGroups.detail.col.discovered', 'Discovered')}
          />
        ),
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {new Date(row.original.discoveredAt).toLocaleDateString()}
          </span>
        ),
      },
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => router.push(`/findings/${row.original.id}`)}
            aria-label={t('assetGroups.detail.openAsset', 'Open {name}', {
              name: row.original.title,
            })}
            title={t('assetGroups.detail.viewFinding', 'View finding details')}
          >
            <Eye className="h-4 w-4" />
          </Button>
        ),
      },
    ],
    [router, t]
  )

  // Loading state with skeleton UI
  if (groupLoading) {
    return (
      <>
        <Main>
          {/* Header skeleton */}
          <div className="flex items-center gap-4 mb-6">
            <Button variant="ghost" size="icon" disabled>
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <Skeleton className="h-12 w-12 rounded-xl" />
                <div>
                  <Skeleton className="h-7 w-48 mb-2" />
                  <Skeleton className="h-4 w-64" />
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Skeleton className="h-6 w-20 rounded-full" />
              <Skeleton className="h-6 w-16 rounded-full" />
            </div>
          </div>

          {/* Stats cards skeleton */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[...Array(4)].map((_, i) => (
              <Card key={i}>
                <CardHeader className="pb-2">
                  <Skeleton className="h-4 w-24 mb-2" />
                  <Skeleton className="h-9 w-16" />
                </CardHeader>
              </Card>
            ))}
          </div>

          {/* Tabs skeleton */}
          <Skeleton className="h-10 w-80 rounded-md mb-6" />

          {/* Content skeleton */}
          <div className="grid md:grid-cols-2 gap-6">
            {[...Array(4)].map((_, i) => (
              <Card key={i}>
                <CardHeader>
                  <Skeleton className="h-5 w-40 mb-2" />
                  <Skeleton className="h-4 w-56" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {[...Array(3)].map((_, j) => (
                      <div key={j} className="flex items-center gap-3">
                        <Skeleton className="h-8 w-8 rounded-lg" />
                        <div className="flex-1">
                          <Skeleton className="h-4 w-full max-w-[200px] mb-1" />
                          <Skeleton className="h-2 w-full" />
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </Main>
      </>
    )
  }

  // A failed request is not "not found": only a 404 says the group is gone.
  const groupNotFound = (groupError as { statusCode?: number } | null)?.statusCode === 404
  if (groupError && !groupNotFound) {
    return (
      <Main>
        <Button
          variant="ghost"
          size="sm"
          className="-ms-2 mb-2"
          onClick={() => router.push('/assets/groups')}
        >
          <ArrowLeft className="me-2 h-4 w-4" />
          {t('assetGroups.detail.back', 'Back to asset groups')}
        </Button>
        <ErrorState
          title={t('assetGroups.detail.errorTitle', 'this asset group')}
          error={groupError}
          onRetry={() => refreshGroup()}
        />
      </Main>
    )
  }

  // Not found - early return after all hooks
  if (!group) {
    return (
      <>
        <Main>
          <div className="flex flex-col items-center justify-center py-20">
            <FolderKanban className="h-16 w-16 text-muted-foreground/50 mb-4" />
            <h2 className="text-xl font-semibold mb-2">
              {t('assetGroups.detail.notFound', 'Group not found')}
            </h2>
            <p className="text-muted-foreground mb-4">
              {t(
                'assetGroups.detail.notFoundHint',
                'The asset group does not exist or was deleted.'
              )}
            </p>
            <Button onClick={() => router.push('/assets/groups')}>
              <ArrowLeft className="me-2 h-4 w-4" />
              {t('assetGroups.detail.backToGroups', 'Back to groups')}
            </Button>
          </div>
        </Main>
      </>
    )
  }

  const envLabel = (env: string) => t(`assetGroups.environment.${env}`, env)
  const critLabel = (crit: string) =>
    t(`criticality.${crit}`, (CRITICALITY_LABELS as Record<string, string>)[crit] ?? crit)

  // Handlers
  const handleCopyId = () => {
    copyToClipboard(group.id)
    toast.success(t('assetGroups.idCopied', 'Group ID copied'))
  }

  const handleCopyLink = () => {
    copyToClipboard(window.location.href)
    toast.success(t('assetGroups.linkCopied', 'Link copied'))
  }

  const handleEdit = () => {
    setEditDialogOpen(true)
  }

  const handleSaveEdit = async (formData: EditGroupFormData) => {
    try {
      // The asset-groups PUT is a partial update: an omitted key keeps the old
      // value. Send explicit empty string / empty array (not undefined) so
      // clearing a field actually persists instead of silently reverting.
      // owner_email is the exception — the backend 422s on an empty email, so
      // it can't be cleared from here (send undefined to leave it unchanged;
      // clearing it needs a backend change to accept "").
      await updateGroup({
        name: formData.name,
        description: formData.description,
        environment: formData.environment,
        criticality: formData.criticality,
        businessUnit: formData.businessUnit,
        owner: formData.owner,
        ownerEmail: formData.ownerEmail || undefined,
        tags: formData.tags,
      })
      refreshGroup()
      setEditDialogOpen(false)
    } catch {
      // Error already handled by hook with toast
    }
  }

  const handleDelete = async () => {
    try {
      await deleteGroup()
      setDeleteDialogOpen(false)
      router.push('/assets/groups')
    } catch {
      // Error already handled by hook with toast
    }
  }

  const handleRemoveAssets = async () => {
    try {
      await removeAssets(selectedAssets)
      setSelectionEpoch((n) => n + 1)
      setRemoveAssetsDialogOpen(false)
      // Refresh data to get updated counts
      refreshGroup()
    } catch {
      // Error already handled by hook
    }
  }

  const handleAddAssets = async (data: AddAssetsSubmitData) => {
    try {
      // Add existing assets
      if (data.existingAssetIds.length > 0) {
        await addAssets(data.existingAssetIds)
      }
      // Only supports adding existing assets. New asset creation from this view planned for Phase 2.

      setAddAssetsDialogOpen(false)
      // Refresh data to get updated counts
      refreshGroup()
    } catch {
      // Error already handled by hook
    }
  }

  const handleExport = (format: 'CSV' | 'JSON') => {
    if (format === 'CSV') {
      exportAssetsCsv()
      return
    }
    // JSON: export the group plus its assets.
    const payload = {
      group,
      assets: safeAssets,
      ...(assetsPartial ? { partial: { loaded: safeAssets.length, total: group.assetCount } } : {}),
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `asset-group-${group?.name ?? id}-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <Main>
        {/* Header with Back Button */}
        <Button
          variant="ghost"
          size="sm"
          className="-ms-2 mb-2"
          onClick={() => router.push('/assets/groups')}
        >
          <ArrowLeft className="me-2 h-4 w-4" />
          {t('assetGroups.detail.back', 'Back to asset groups')}
        </Button>
        <PageHeader
          title={group.name}
          className="mb-6"
          description={
            <div className="flex flex-wrap items-center gap-2">
              <span>
                {group.description || t('assetGroups.detail.noDescription', 'No description')}
              </span>
              <Badge variant="outline">{envLabel(group.environment)}</Badge>
              <Badge variant="outline" className={criticalityColors[group.criticality]}>
                {critLabel(group.criticality)}
              </Badge>
            </div>
          }
        >
          <Button variant="outline" size="sm" onClick={handleCopyId}>
            <Copy className="me-2 h-4 w-4" />
            {t('assetGroups.detail.copyId', 'Copy ID')}
          </Button>
          <Can permission={Permission.AssetGroupsWrite}>
            <Button variant="outline" size="sm" onClick={handleEdit}>
              <Pencil className="me-2 h-4 w-4" />
              {t('assetGroups.detail.edit', 'Edit')}
            </Button>
          </Can>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                size="icon"
                aria-label={t('assetGroups.detail.moreActions', 'More actions')}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={handleCopyLink}>
                <Link className="me-2 h-4 w-4" />
                {t('assetGroups.detail.copyLink', 'Copy link')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => handleExport('JSON')}>
                <Download className="me-2 h-4 w-4" />
                {t('assetGroups.detail.exportJson', 'Export as JSON')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('CSV')}>
                <Download className="me-2 h-4 w-4" />
                {t('assetGroups.detail.exportCsv', 'Export as CSV')}
              </DropdownMenuItem>
              <Can permission={Permission.AssetGroupsDelete}>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive"
                  onClick={() => setDeleteDialogOpen(true)}
                >
                  <Trash2 className="me-2 h-4 w-4" />
                  {t('assetGroups.detail.deleteGroup', 'Delete group')}
                </DropdownMenuItem>
              </Can>
            </DropdownMenuContent>
          </DropdownMenu>
        </PageHeader>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatsCard
            title={t('assetGroups.detail.stat.assets', 'Total assets')}
            value={group.assetCount}
          />
          <StatsCard
            title={t('assetGroups.detail.stat.findings', 'Findings')}
            value={group.findingCount}
          />
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>
                {t('assetGroups.detail.stat.riskScore', 'Risk score')}
              </CardDescription>
              <div className="pt-1">
                <RiskScoreBadge score={group.riskScore} size="lg" />
              </div>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>
                {t('assetGroups.detail.stat.lastUpdated', 'Last updated')}
              </CardDescription>
              <CardTitle className="text-lg">
                {new Date(group.updatedAt).toLocaleDateString()}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={handleTabChange}>
          <TabsList>
            <TabsTrigger value="overview">
              {t('assetGroups.detail.tab.overview', 'Overview')}
            </TabsTrigger>
            <TabsTrigger value="assets">
              {t('assetGroups.detail.tab.assets', 'Assets')} <TabsCount value={group.assetCount} />
            </TabsTrigger>
            <TabsTrigger value="findings">
              {t('assetGroups.detail.tab.findings', 'Findings')}{' '}
              <TabsCount value={group.findingCount} />
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="mt-6">
            <div className="grid md:grid-cols-2 gap-6">
              {/* Asset Distribution */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">
                    {t('assets.groups.detail.typesTitle', 'Assets by type')}
                  </CardTitle>
                  <CardDescription>
                    {assetsPartial
                      ? partialNote(safeAssets.length, group.assetCount)
                      : t('assets.groups.detail.typesDesc', 'The group’s members by asset type')}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {Object.keys(assetsByType).length === 0 ? (
                    <EmptyState
                      icon={Package}
                      title={t('assetGroups.detail.noAssetsYet', 'No assets in this group yet')}
                      card={false}
                    />
                  ) : (
                    <div className="space-y-4">
                      {Object.entries(assetsByType).map(([type, count]) => (
                        <div key={type} className="flex items-center gap-3">
                          <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                            {assetTypeIcons[type] || <Server className="h-4 w-4" />}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium">{typeLabel(type)}</span>
                              <span className="text-sm text-muted-foreground">{count}</span>
                            </div>
                            <Progress
                              value={(count / Math.max(safeAssets.length, 1)) * 100}
                              className="h-2"
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Finding Severity */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">
                    {t('assets.groups.detail.severityTitle', 'Open findings by severity')}
                  </CardTitle>
                  <CardDescription>
                    {findingsPartial
                      ? partialNote(findings?.length ?? 0, findingsTotal)
                      : t(
                          'assets.groups.detail.severityDesc',
                          'The same findings as the group’s count; each row opens them'
                        )}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {Object.entries(findingsBySeverity).map(([severity, count]) => (
                      <NextLink
                        key={severity}
                        href={findingsHref(severity)}
                        className="flex items-center justify-between rounded-md px-1 py-0.5 hover:bg-muted"
                        aria-label={t(
                          'assets.groups.detail.severityLink',
                          'Open {count} {severity} findings of this group',
                          { count, severity }
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={severity as GroupFinding['severity']} />
                        </div>
                        <span className="font-medium tabular-nums">{count}</span>
                      </NextLink>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Risk Score */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">
                    {t('assetGroups.detail.riskAssessment', 'Risk assessment')}
                  </CardTitle>
                  <CardDescription>
                    {t('assetGroups.detail.riskAssessmentDesc', 'Overall group risk score')}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-4">
                    <RiskScoreBadge score={group.riskScore} size="lg" />
                    <div className="flex-1">
                      <Progress
                        value={group.riskScore}
                        className={`h-3 ${
                          group.riskScore >= 80
                            ? '[&>div]:bg-red-500'
                            : group.riskScore >= 60
                              ? '[&>div]:bg-orange-500'
                              : group.riskScore >= 40
                                ? '[&>div]:bg-yellow-500'
                                : '[&>div]:bg-green-500'
                        }`}
                      />
                      <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                        <span>{t('severity.low', 'Low')}</span>
                        <span>{t('severity.medium', 'Medium')}</span>
                        <span>{t('severity.high', 'High')}</span>
                        <span>{t('severity.critical', 'Critical')}</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Group Info */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">
                    {t('assetGroups.detail.info.title', 'Group information')}
                  </CardTitle>
                  <CardDescription>
                    {t('assetGroups.detail.info.desc', 'Metadata and details')}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {t('assetGroups.detail.info.id', 'Group ID')}
                      </span>
                      <span className="font-mono">{group.id}</span>
                    </div>
                    <Separator />
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {t('assetGroups.detail.info.created', 'Created')}
                      </span>
                      <span>{new Date(group.createdAt).toLocaleDateString()}</span>
                    </div>
                    <Separator />
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {t('assetGroups.detail.info.updated', 'Updated')}
                      </span>
                      <span>{new Date(group.updatedAt).toLocaleDateString()}</span>
                    </div>
                    <Separator />
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {t('assetGroups.detail.info.environment', 'Environment')}
                      </span>
                      <Badge variant="outline">{envLabel(group.environment)}</Badge>
                    </div>
                    <Separator />
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {t('assetGroups.detail.info.criticality', 'Criticality')}
                      </span>
                      <Badge variant="outline" className={criticalityColors[group.criticality]}>
                        {critLabel(group.criticality)}
                      </Badge>
                    </div>
                    {group.businessUnit && (
                      <>
                        <Separator />
                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground flex items-center gap-1">
                            <Building2 className="h-3 w-3" />
                            {t('assetGroups.detail.info.businessUnit', 'Business unit')}
                          </span>
                          <span>{group.businessUnit}</span>
                        </div>
                      </>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Owner Info */}
              {(group.owner || group.ownerEmail) && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <User className="h-4 w-4" />
                      {t('assetGroups.detail.owner', 'Owner')}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                        <User className="h-5 w-5" />
                      </div>
                      <div>
                        <p className="font-medium">
                          {group.owner || t('assetGroups.detail.notAssigned', 'Not assigned')}
                        </p>
                        {group.ownerEmail && (
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <Mail className="h-3 w-3" />
                            {group.ownerEmail}
                          </p>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Tags */}
              {group.tags && group.tags.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Tags className="h-4 w-4" />
                      {t('assetGroups.detail.tags', 'Tags')}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {group.tags.map((tag) => (
                        <Badge key={tag} variant="secondary">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Assets Tab */}
          <TabsContent value="assets" className="mt-6">
            {assetsPartial && (
              <p className="mb-2 text-xs text-muted-foreground">
                {partialNote(safeAssets.length, group.assetCount)}
              </p>
            )}
            <DataTable
              columns={assetColumns}
              data={safeAssets}
              getRowId={(a) => a.id}
              isLoading={assetsLoading}
              searchKey="name"
              searchPlaceholder={t('assetGroups.detail.searchAssets', 'Search assets…')}
              onSelectionChange={(rows) => setSelectedAssets(rows.map((a) => a.id))}
              resetSelectionKey={selectionEpoch}
              showSelectionCount={false}
              onRowClick={(a) => router.push(groupMemberHref(a.id))}
              toolbarEnd={
                <>
                  {selectedAssets.length > 0 && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-9"
                      onClick={() => setRemoveAssetsDialogOpen(true)}
                    >
                      <X className="me-2 h-4 w-4" />
                      {t('assetGroups.detail.removeSelected', 'Remove {count} from group', {
                        count: selectedAssets.length,
                      })}
                    </Button>
                  )}
                  <Button size="sm" className="h-9" onClick={() => setAddAssetsDialogOpen(true)}>
                    <Plus className="me-2 h-4 w-4" />
                    {t('assetGroups.detail.addAssets', 'Add assets')}
                  </Button>
                </>
              }
              emptyMessage={t('assetGroups.detail.emptyAssets', 'No assets in this group')}
              emptyDescription={t(
                'assetGroups.detail.emptyAssetsHint',
                'Add assets to this group to track and manage them together'
              )}
            />
          </TabsContent>

          {/* Findings Tab */}
          <TabsContent value="findings" className="mt-6">
            {findingsPartial && (
              <p className="mb-2 text-xs text-muted-foreground">
                {partialNote(findings?.length ?? 0, findingsTotal)}
              </p>
            )}
            <DataTable
              columns={findingColumns}
              data={safeFindings}
              getRowId={(f) => f.id}
              isLoading={findingsLoading}
              searchPlaceholder={t('assetGroups.detail.searchFindings', 'Search findings…')}
              onRowClick={(f) => router.push(`/findings/${f.id}`)}
              emptyMessage={
                group.findingCount > 0
                  ? t('assetGroups.detail.noOpenLoaded', 'No open findings in the loaded rows')
                  : t('assetGroups.detail.emptyFindings', 'No findings')
              }
              emptyDescription={
                group.findingCount > 0
                  ? t(
                      'assetGroups.detail.noOpenLoadedHint',
                      '{count} findings belong to this group; open the findings list to see them all.',
                      { count: group.findingCount }
                    )
                  : t(
                      'assetGroups.detail.emptyFindingsHint',
                      'No security findings have been discovered for assets in this group'
                    )
              }
            />
          </TabsContent>
        </Tabs>
      </Main>

      {/* Edit Dialog */}
      <EditGroupDialog
        open={editDialogOpen}
        onOpenChange={setEditDialogOpen}
        group={group}
        onSubmit={handleSaveEdit}
        isSubmitting={isUpdating}
      />

      {/* Delete Dialog */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t('confirm.assetGroup.deleteTitle', 'Delete the asset group "{name}"?', {
          name: group.name,
        })}
        desc={t(
          'confirm.assetGroup.deleteDesc',
          'The group is deleted and its assets leave it; scans and rules that target the group no longer cover them. The assets themselves are not deleted. This cannot be undone.'
        )}
        confirmText={
          isDeleting ? t('confirm.deleting', 'Deleting…') : t('confirm.delete', 'Delete')
        }
        destructive
        isLoading={isDeleting}
        handleConfirm={handleDelete}
      />

      {/* Remove Assets Dialog */}
      <ConfirmDialog
        open={removeAssetsDialogOpen}
        onOpenChange={setRemoveAssetsDialogOpen}
        title={
          selectedAssets.length === 1
            ? t('confirm.assetGroup.removeAssetsTitleOne', 'Remove 1 asset from {group}?', {
                group: group.name,
              })
            : t('confirm.assetGroup.removeAssetsTitle', 'Remove {count} assets from {group}?', {
                count: selectedAssets.length,
                group: group.name,
              })
        }
        desc={t(
          'confirm.assetGroup.removeAssetsDesc',
          'The selected assets leave the group, so scans and rules that target the group no longer cover them. The assets themselves are not deleted.'
        )}
        confirmText={
          isRemovingAssets ? t('confirm.removing', 'Removing…') : t('confirm.remove', 'Remove')
        }
        destructive
        isLoading={isRemovingAssets}
        handleConfirm={handleRemoveAssets}
      />

      {/* Add Assets Dialog */}
      <AddAssetsDialog
        open={addAssetsDialogOpen}
        onOpenChange={setAddAssetsDialogOpen}
        groupName={group.name}
        groupAssets={safeAssets}
        onSubmit={handleAddAssets}
        onRemove={async (assetId) => {
          await removeAssets([assetId])
          mutateAssets()
          refreshGroup()
        }}
        isSubmitting={isAddingAssets}
        isRemoving={isRemovingAssets}
      />
    </>
  )
}
