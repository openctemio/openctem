'use client'

/**
 * The All-Assets table: the shared DataTable in server mode (the page fetches
 * one page at a time; sorting and paging go through the URL), with the
 * inventory's columns and the read-only asset detail sheet on row click.
 *
 * Column ids are the names shown in the Columns menu; SORT_FIELDS (in
 * inventory-url) maps the sortable ones to the API's sort fields. Columns the
 * API cannot sort (internet, owner, tags) have sorting turned off rather than
 * reordering only the rows on screen.
 *
 * Typed mode (research/77): when the list is one type, its registry columns
 * follow the name (AttributeCell), the redundant Type column goes, and a
 * scannable type gets the scope gate's answer per row. Every row has a menu:
 * the type's actions (lib/type-actions), Edit and Delete.
 */

import Link from '@/components/link'
import { useCallback, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import {
  ChevronRight,
  ExternalLink,
  MoreHorizontal,
  Pencil,
  Trash2,
  User,
  Users,
} from 'lucide-react'
import { toast } from 'sonner'
import { Checkbox } from '@/components/ui/checkbox'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ScopeCheckBadge, useScopeCheck } from '@/features/scope'
import { ScopeTriageBadge } from './scope-triage-badge'
import { useTranslation } from '@/context/i18n-provider'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'
import { rowActionsFor } from '../../lib/type-actions'
import { AttributeCell } from './attribute-cell'
import { DataTable, DataTableColumnHeader, RiskScoreBadge, riskScoreState } from '@/features/shared'
import { AssetStatusBadge } from '@/features/asset-lifecycle'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { CriticalityBadge, ExposureBadge } from '../classification-badges'
import { AssetDetailSheet } from '../asset-detail-sheet'
import { getAsset, updateAsset } from '../../hooks'
import { useAssetTags } from '../../hooks/use-asset-tags'
import { isPlainLeftClick } from '../../lib/plain-click'
import { AssetTypeIcon } from '../../lib/asset-type-icon'
import { AssetNameCell } from './asset-name-cell'
import { typeKeyOf } from '../../lib/inventory-lenses'
import { Permission, usePermissions } from '@/lib/permissions'
import type { Asset } from '../../types/asset.types'
import { SORT_FIELDS, sortToSorting, sortingToSort } from '../../lib/inventory-url'
import {
  IssuesChip,
  LabelChips,
  SurfaceFacts,
  cellsForType,
  hasSurfaceFacts,
  surfaceCellsCovered,
} from '../service-cells'

const PAGE_SIZES = [10, 20, 30, 50, 100]

/** A one-type list shows "Service facts" only when its own columns do not already. */
function showsServiceFacts(view: TypeView): boolean {
  const cells = cellsForType(view.type, view.subType)
  return (
    cells !== null &&
    !surfaceCellsCovered(
      cells,
      view.columns.map((c) => c.key)
    )
  )
}

function daysSinceISO(iso?: string | null): number | undefined {
  if (!iso) return undefined
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return undefined
  const diff = Date.now() - t
  if (diff < 0) return undefined
  return Math.floor(diff / (1000 * 60 * 60 * 24))
}

interface InventoryTableProps {
  assets: Asset[]
  total: number
  /** 1-based page, as in the URL. */
  page: number
  pageSize: number
  sort?: string
  onPageChange: (page: number, pageSize: number) => void
  onSortChange: (sort: string | undefined) => void
  onSelectionChange: (assets: Asset[]) => void
  resetSelectionKey: number
  toolbarStart?: ReactNode
  toolbarEnd?: ReactNode
  /** A full-width row under the toolbar: the filter chips. */
  toolbarBelow?: ReactNode
  hasFilters: boolean
  /** Called after an asset is edited from the detail sheet (e.g. tags), to refetch the list. */
  onAssetUpdated?: () => void
  /** The list is one type: its registry columns, scope and actions. */
  typeView?: TypeView | null
  /** Open the edit form (shown with assets:write). */
  onEditAsset?: (asset: Asset) => void
  /** Ask to delete (shown with assets:delete). */
  onDeleteAsset?: (asset: Asset) => void
  /** Overrides the empty-table text (typed mode says how to find the type). */
  emptyMessage?: string
  emptyDescription?: string
  /** The tags the list is filtered by (their chips show as active). */
  filterTags?: string[]
  /** Clicking a tag chip (row or detail sheet) adds it to, or removes it from, the filter. */
  onToggleTagFilter?: (tag: string) => void
}

export function InventoryTable({
  assets,
  total,
  page,
  pageSize,
  sort,
  onPageChange,
  onSortChange,
  onSelectionChange,
  resetSelectionKey,
  toolbarStart,
  toolbarEnd,
  toolbarBelow,
  hasFilters,
  onAssetUpdated,
  typeView = null,
  onEditAsset,
  onDeleteAsset,
  emptyMessage,
  emptyDescription,
  filterTags,
  onToggleTagFilter,
}: InventoryTableProps) {
  const [selectedSnapshot, setSelectedAsset] = useState<Asset | null>(null)
  // The asset the drawer asked to delete: once the refreshed list no longer
  // holds it, the drawer closes instead of staying open on a deleted row.
  const [deleteRequestedId, setDeleteRequestedId] = useState<string | null>(null)
  // The drawer shows the row as the list now has it (an edit refreshes the
  // list), falling back to the snapshot for an asset opened from elsewhere.
  const selectedAsset = useMemo(() => {
    if (!selectedSnapshot) return null
    const inList = assets.find((a) => a.id === selectedSnapshot.id)
    if (!inList && deleteRequestedId === selectedSnapshot.id) return null
    return inList ?? selectedSnapshot
  }, [selectedSnapshot, assets, deleteRequestedId])
  const { t } = useTranslation()
  const { can } = usePermissions()
  const canWriteAssets = can(Permission.AssetsWrite)
  const canDeleteAssets = can(Permission.AssetsDelete)
  // The scope gate's own answer per row, one request per page, for a type
  // scanners can scan (the same check a scan runs).
  const scopeNames = useMemo(
    () => (typeView?.scannable ? assets.map((a) => a.name).filter(Boolean) : []),
    [typeView, assets]
  )
  const {
    resultFor: scopeResultFor,
    isLoading: scopeChecking,
    available: scopeAvailable,
  } = useScopeCheck(scopeNames)
  // Tag suggestions only load once someone can actually edit tags.
  const { tags: tagSuggestions } = useAssetTags(undefined, canWriteAssets)
  const sorting = useMemo(() => sortToSorting(sort), [sort])
  // RFC-042 class and lens of each row ("Code repository · Code").
  const { registry, classAndLens } = useAssetTypeRegistry()

  // "+ Add label" on a row: one PUT of that asset's tags, then a refetch.
  const saveRowLabels = useCallback(
    async (id: string, tags: string[]) => {
      try {
        await updateAsset(id, { tags })
        toast.success(t('assets.inv.labelAdded', 'Label added'))
        onAssetUpdated?.()
      } catch (err) {
        toast.error(
          err instanceof Error
            ? err.message
            : t('assets.inv.labelAddFailed', 'Failed to add the label')
        )
        throw err
      }
    },
    [onAssetUpdated, t]
  )

  const columns = useMemo<ColumnDef<Asset>[]>(() => {
    const sortable = (id: string) => id in SORT_FIELDS
    const all: ColumnDef<Asset>[] = [
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
            onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
            aria-label={t('assets.inv.selectAllRows', 'Select all rows on this page')}
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(v) => row.toggleSelected(!!v)}
            aria-label={t('assets.inv.selectRow', 'Select row')}
            onClick={(e) => e.stopPropagation()}
          />
        ),
      },
      {
        id: 'name',
        accessorKey: 'name',
        enableHiding: false,
        enableSorting: sortable('name'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.properties.columns.name', 'Name')}
          />
        ),
        // Name cut in the middle with a copy button; a certificate shows its
        // subject name with the asset name below (research/242 D9). The
        // description moved to the drawer, so a row stays one line.
        cell: ({ row }) => (
          <AssetNameCell
            asset={row.original}
            href={assetDetailHref(row.original.id)}
            onOpen={(e) => {
              // Plain click opens the drawer; ctrl/cmd/middle-click follow the link.
              if (!isPlainLeftClick(e)) return
              e.preventDefault()
              setSelectedAsset(row.original)
            }}
          />
        ),
      },
      ...(typeView?.columns ?? []).map((attribute): ColumnDef<Asset> => ({
        id: `attr:${attribute.key}`,
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={propertyLabel(attribute.key)} />
        ),
        cell: ({ row }) => <AttributeCell asset={row.original} attribute={attribute} />,
      })),
      {
        id: 'type',
        accessorKey: 'type',
        enableSorting: sortable('type'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.properties.columns.type', 'Type')}
          />
        ),
        // One line: the registry's name for the row's type (an alias such as
        // "HTTP Service" when the sub-type has one); class and lens are in
        // the tooltip, since the open view already names the lens.
        cell: ({ row }) => {
          const key = typeKeyOf(registry, row.original.type, row.original.subType)
          return (
            <span
              className="block truncate text-sm text-muted-foreground"
              title={classAndLens(row.original.type, row.original.subType)}
            >
              {t(`assets.typeLabel.${key.type}`, key.label)}
            </span>
          )
        },
      },
      // The scope standing from each row's triage, when the typed scope
      // check column below is not shown (research/124).
      ...(!(typeView?.scannable && scopeAvailable)
        ? [
            {
              id: 'scan_scope',
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader column={column} title={t('scope.check.column', 'Scope')} />
              ),
              cell: ({ row }) => <ScopeTriageBadge triage={row.original.triage} />,
            } as ColumnDef<Asset>,
          ]
        : []),
      {
        // External-surface facts (status, IP, technologies, TLS …) for the
        // types cellsForType lists; other types have none to show here.
        // Only known facts are shown; a row with none shows the muted dash.
        id: 'service',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.facts.title', 'Service facts')} />
        ),
        cell: ({ row }) =>
          cellsForType(row.original.type, row.original.subType) ? (
            <SurfaceFacts asset={row.original} className="max-w-[380px]" />
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        id: 'criticality',
        accessorKey: 'criticality',
        enableSorting: sortable('criticality'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.badge.criticality', 'Criticality')}
          />
        ),
        cell: ({ row }) => (
          <CriticalityBadge criticality={row.original.criticality} size="sm" showTooltip={false} />
        ),
      },
      {
        id: 'exposure',
        accessorKey: 'exposure',
        enableSorting: sortable('exposure'),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.badge.exposure', 'Exposure')} />
        ),
        cell: ({ row }) => (
          <ExposureBadge exposure={row.original.exposure} size="sm" showTooltip={false} />
        ),
      },
      {
        id: 'owner',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.inv.col.owner', 'Owner')} />
        ),
        cell: ({ row }) => {
          const owner = row.original.primaryOwner
          if (owner) {
            const Icon = owner.type === 'group' ? Users : User
            return (
              <div className="flex max-w-[160px] items-center gap-1.5">
                <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate text-sm">{owner.name}</span>
              </div>
            )
          }
          if (row.original.ownerRef) {
            return <span className="truncate text-sm">{row.original.ownerRef}</span>
          }
          return (
            <span className="text-sm text-muted-foreground">
              {t('assets.views.unowned', 'Unowned')}
            </span>
          )
        },
      },
      {
        id: 'risk',
        accessorKey: 'riskScore',
        enableSorting: sortable('risk'),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('components.col.risk', 'Risk')} />
        ),
        cell: ({ row }) => (
          <RiskScoreBadge
            score={row.original.riskScore}
            state={riskScoreState(row.original)}
            size="sm"
          />
        ),
      },
      {
        id: 'findings',
        accessorKey: 'findingCount',
        enableSorting: sortable('findings'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.sheet.tab.findings', 'Findings')}
          />
        ),
        cell: ({ row }) =>
          row.original.findingCount > 0 ? (
            <IssuesChip assetId={row.original.id} count={row.original.findingCount} />
          ) : (
            <span className="text-muted-foreground tabular-nums">0</span>
          ),
      },
      {
        id: 'last_seen',
        accessorKey: 'lastSeen',
        enableSorting: sortable('last_seen'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.lastSeen', 'Last seen')}
          />
        ),
        cell: ({ row }) => (
          <AssetStatusBadge
            status={row.original.status}
            daysSinceLastSeen={daysSinceISO(row.original.lastSeen)}
            snoozedUntil={row.original.lifecyclePausedUntil}
          />
        ),
      },
      {
        id: 'tags',
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.inv.col.labels', 'Labels')} />
        ),
        cell: ({ row }) => (
          <LabelChips
            className="max-w-[240px]"
            labels={row.original.tags ?? []}
            onSave={canWriteAssets ? (tags) => saveRowLabels(row.original.id, tags) : undefined}
            activeLabels={filterTags}
            onLabelClick={onToggleTagFilter}
          />
        ),
      },
      ...(typeView?.scannable && scopeAvailable
        ? [
            {
              id: 'scope',
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader column={column} title={t('scope.check.column', 'Scope')} />
              ),
              cell: ({ row }) => (
                <ScopeCheckBadge
                  result={scopeResultFor(row.original.name)}
                  loading={scopeChecking}
                />
              ),
            } as ColumnDef<Asset>,
          ]
        : []),
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        header: () => <span className="sr-only">{t('components.col.actions', 'Actions')}</span>,
        cell: ({ row }) => {
          const asset = row.original
          const actions = rowActionsFor(asset, typeView, t).filter((a) =>
            a.permissions.every((p) => can(p))
          )
          const canEdit = canWriteAssets && !!onEditAsset
          const canDelete = canDeleteAssets && !!onDeleteAsset
          return (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label={t('assets.inv.actionsFor', 'Actions for {name}', {
                    name: asset.name,
                  })}
                  onClick={(e) => e.stopPropagation()}
                >
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
                <DropdownMenuItem asChild>
                  <Link href={assetDetailHref(asset.id)}>
                    <ExternalLink className="me-2 h-4 w-4" />
                    {t('assets.inv.openDetails', 'Open details page')}
                  </Link>
                </DropdownMenuItem>
                {actions.map((a) => (
                  <DropdownMenuItem key={a.id} onClick={() => void a.run(asset)}>
                    <a.icon className="me-2 h-4 w-4" />
                    {a.label}
                  </DropdownMenuItem>
                ))}
                {canEdit && (
                  <DropdownMenuItem onClick={() => onEditAsset?.(asset)}>
                    <Pencil className="me-2 h-4 w-4" />
                    {t('assets.inv.edit', 'Edit')}
                  </DropdownMenuItem>
                )}
                {canDelete && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      className="text-destructive"
                      onClick={() => onDeleteAsset?.(asset)}
                    >
                      <Trash2 className="me-2 h-4 w-4" />
                      {t('assets.inv.delete', 'Delete')}
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )
        },
      },
    ]
    return all.filter(
      (c) => !typeView || (c.id !== 'type' && (c.id !== 'service' || showsServiceFacts(typeView)))
    )
  }, [
    classAndLens,
    registry,
    canWriteAssets,
    canDeleteAssets,
    can,
    saveRowLabels,
    typeView,
    scopeAvailable,
    scopeResultFor,
    scopeChecking,
    onEditAsset,
    onDeleteAsset,
    t,
    filterTags,
    onToggleTagFilter,
  ])

  return (
    <>
      <DataTable
        columns={columns}
        data={assets}
        showSearch={false}
        toolbarStart={toolbarStart}
        toolbarEnd={toolbarEnd}
        toolbarBelow={toolbarBelow}
        getRowId={(a) => a.id}
        manualPagination
        rowCount={total}
        pagination={{ pageIndex: Math.max(0, page - 1), pageSize }}
        onPaginationChange={(p) => onPageChange(p.pageIndex + 1, p.pageSize)}
        pageSize={pageSize}
        pageSizeOptions={PAGE_SIZES}
        sorting={sorting}
        onSortingChange={(next) => onSortChange(sortingToSort(next))}
        onSelectionChange={onSelectionChange}
        resetSelectionKey={resetSelectionKey}
        showSelectionCount={false}
        onRowClick={setSelectedAsset}
        // Single-line rows (research/242 D9) until the viewer picks a density.
        defaultDensity="compact"
        // Labels are a working column, not a reading one: on under Columns.
        initialColumnVisibility={{ tags: false }}
        mobileRow={(a) => {
          const typeKey = typeKeyOf(registry, a.type, a.subType)
          const typeLabel = t(`assets.typeLabel.${typeKey.type}`, typeKey.label)
          const context = a.groupName || a.description
          // A card shows the facts row only when it has something known in it.
          const hasFacts = a.findingCount > 0 || hasSurfaceFacts(a)
          // The card opens the drawer (a stretched button); the chip row sits
          // above it so its links and "+N" tooltips are not nested inside a
          // button.
          return (
            <div className="relative px-3 py-3 transition-colors hover:bg-muted/50">
              <button
                type="button"
                onClick={() => setSelectedAsset(a)}
                className="flex w-full items-start gap-3 text-start after:absolute after:inset-0 focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring"
              >
                <AssetTypeIcon
                  type={a.type}
                  className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground"
                />
                <div className="min-w-0 flex-1">
                  <p className="line-clamp-2 break-all text-sm font-medium">{a.name}</p>
                  <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    {typeLabel}
                    {context && ` · ${context}`}
                  </p>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                    <CriticalityBadge criticality={a.criticality} size="sm" showTooltip={false} />
                    {/* Scope standing only when a scan may not reach it (research/124). */}
                    {a.triage && !a.triage.scanAllowed && <ScopeTriageBadge triage={a.triage} />}
                    {/* Most assets are active; say so only when one is not. */}
                    {a.status !== 'active' && (
                      <AssetStatusBadge
                        status={a.status}
                        daysSinceLastSeen={daysSinceISO(a.lastSeen)}
                        snoozedUntil={a.lifecyclePausedUntil}
                      />
                    )}
                    {(a.riskScore > 0 || riskScoreState(a) !== 'scored') && (
                      <RiskScoreBadge score={a.riskScore} state={riskScoreState(a)} size="sm" />
                    )}
                  </div>
                </div>
                <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
              </button>
              {hasFacts && (
                <div className="relative z-10 mt-1.5 flex flex-wrap items-center gap-1 ps-7">
                  <IssuesChip assetId={a.id} count={a.findingCount} />
                  <SurfaceFacts asset={a} empty={null} />
                </div>
              )}
            </div>
          )
        }}
        emptyMessage={emptyMessage ?? 'No assets match these filters'}
        emptyDescription={
          emptyDescription ??
          (hasFilters ? 'Try removing a filter or clearing them all.' : 'No assets yet.')
        }
      />

      <AssetDetailSheet
        asset={selectedAsset}
        open={!!selectedAsset}
        onOpenChange={(open) => !open && setSelectedAsset(null)}
        // Icon and title come from the asset's own type ("Repository details").
        onEdit={() => {
          if (selectedAsset) onEditAsset?.(selectedAsset)
        }}
        onDelete={() => {
          if (selectedAsset) {
            setDeleteRequestedId(selectedAsset.id)
            onDeleteAsset?.(selectedAsset)
          }
        }}
        canEdit={canWriteAssets && !!onEditAsset}
        canDelete={canDeleteAssets && !!onDeleteAsset}
        tagSuggestions={tagSuggestions}
        activeTags={filterTags}
        onTagClick={onToggleTagFilter}
        onUpdateTags={
          canWriteAssets
            ? async (tags: string[]) => {
                if (!selectedAsset) return
                try {
                  const updated = await updateAsset(selectedAsset.id, { tags })
                  toast.success(t('assets.inv.tagsUpdated', 'Tags updated'))
                  // Lift the fresh asset into the sheet so it re-renders with the
                  // saved tags, then refetch the list in the background.
                  setSelectedAsset(updated)
                  onAssetUpdated?.()
                } catch (err) {
                  toast.error(
                    err instanceof Error
                      ? err.message
                      : t('assets.inv.tagsUpdateFailed', 'Failed to update tags')
                  )
                  throw err
                }
              }
            : undefined
        }
        onNavigateToAsset={async (id: string) => {
          const local = assets.find((a) => a.id === id)
          if (local) {
            setSelectedAsset(local)
            return
          }
          try {
            setSelectedAsset(await getAsset(id))
          } catch {
            // getAsset surfaces its own errors; keep navigation silent.
          }
        }}
      />
    </>
  )
}
