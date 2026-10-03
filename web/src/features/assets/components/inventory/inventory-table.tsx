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
 */

import { useCallback, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { ChevronRight, Globe, MinusCircle, User, Users } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { DataTable, DataTableColumnHeader, RiskScoreBadge } from '@/features/shared'
import { AssetStatusBadge } from '@/features/asset-lifecycle'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { CriticalityBadge, ExposureBadge } from '../classification-badges'
import { AssetDetailSheet } from '../asset-detail-sheet'
import { getAsset, updateAsset } from '../../hooks'
import { useAssetTags } from '../../hooks/use-asset-tags'
import { AssetTypeIcon } from '../../lib/asset-type-icon'
import { Permission, usePermissions } from '@/lib/permissions'
import { ASSET_TYPE_LABELS, type Asset } from '../../types/asset.types'
import { SORT_FIELDS, sortToSorting, sortingToSort } from '../../lib/inventory-url'
import {
  IssuesChip,
  LabelChips,
  SurfaceFacts,
  cellsForType,
  hasSurfaceFacts,
} from '../service-cells'

const PAGE_SIZES = [10, 20, 30, 50, 100]

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
  hasFilters: boolean
  /** Called after an asset is edited from the detail sheet (e.g. tags), to refetch the list. */
  onAssetUpdated?: () => void
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
  hasFilters,
  onAssetUpdated,
}: InventoryTableProps) {
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const { can } = usePermissions()
  const canWriteAssets = can(Permission.AssetsWrite)
  // Tag suggestions only load once someone can actually edit tags.
  const { tags: tagSuggestions } = useAssetTags(undefined, canWriteAssets)
  const sorting = useMemo(() => sortToSorting(sort), [sort])
  // RFC-042 class and lens of each row ("Code repository · Code").
  const { classAndLens } = useAssetTypeRegistry()

  // "+ Add label" on a row: one PUT of that asset's tags, then a refetch.
  const saveRowLabels = useCallback(
    async (id: string, tags: string[]) => {
      try {
        await updateAsset(id, { tags })
        toast.success('Label added')
        onAssetUpdated?.()
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Failed to add the label')
        throw err
      }
    },
    [onAssetUpdated]
  )

  const columns = useMemo<ColumnDef<Asset>[]>(() => {
    const sortable = (id: string) => id in SORT_FIELDS
    return [
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
            aria-label="Select all rows on this page"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(v) => row.toggleSelected(!!v)}
            aria-label="Select row"
            onClick={(e) => e.stopPropagation()}
          />
        ),
      },
      {
        id: 'name',
        accessorKey: 'name',
        enableHiding: false,
        enableSorting: sortable('name'),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => (
          <div className="flex min-w-0 items-center gap-2">
            <AssetTypeIcon
              type={row.original.type}
              className="h-4 w-4 shrink-0 text-muted-foreground"
            />
            <div className="min-w-0">
              <p className="truncate font-medium">{row.original.name}</p>
              {row.original.description && (
                <p className="line-clamp-1 text-xs text-muted-foreground">
                  {row.original.description}
                </p>
              )}
            </div>
          </div>
        ),
      },
      {
        id: 'type',
        accessorKey: 'type',
        enableSorting: sortable('type'),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Type" />,
        cell: ({ row }) => (
          <div className="flex min-w-0 flex-col items-start gap-0.5">
            <Badge variant="outline" className="font-normal">
              {ASSET_TYPE_LABELS[row.original.type] ?? row.original.type}
            </Badge>
            <span className="truncate text-xs text-muted-foreground">
              {classAndLens(row.original.type, row.original.subType)}
            </span>
          </div>
        ),
      },
      {
        // External-surface facts (status, IP, technologies, TLS …) for the
        // types cellsForType lists; other types have none to show here.
        // Only known facts are shown; a row with none shows the muted dash.
        id: 'service',
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Service facts" />,
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Criticality" />,
        cell: ({ row }) => (
          <CriticalityBadge criticality={row.original.criticality} size="sm" showTooltip={false} />
        ),
      },
      {
        id: 'exposure',
        accessorKey: 'exposure',
        enableSorting: sortable('exposure'),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Exposure" />,
        cell: ({ row }) => (
          <ExposureBadge exposure={row.original.exposure} size="sm" showTooltip={false} />
        ),
      },
      {
        id: 'internet',
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Internet" />,
        cell: ({ row }) => {
          const v = row.original.isInternetAccessible
          if (v === undefined) return <span className="text-muted-foreground">—</span>
          return v ? (
            <span className="inline-flex items-center gap-1 text-xs text-warning">
              <Globe className="h-3.5 w-3.5" />
              Facing
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <MinusCircle className="h-3.5 w-3.5" />
              No
            </span>
          )
        },
      },
      {
        id: 'owner',
        enableSorting: false,
        header: ({ column }) => <DataTableColumnHeader column={column} title="Owner" />,
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
          return <span className="text-sm text-muted-foreground">Unowned</span>
        },
      },
      {
        id: 'risk',
        accessorKey: 'riskScore',
        enableSorting: sortable('risk'),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Risk" />,
        cell: ({ row }) => <RiskScoreBadge score={row.original.riskScore} size="sm" />,
      },
      {
        id: 'findings',
        accessorKey: 'findingCount',
        enableSorting: sortable('findings'),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Findings" />,
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Last seen" />,
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
        header: ({ column }) => <DataTableColumnHeader column={column} title="Labels" />,
        cell: ({ row }) => (
          <LabelChips
            className="max-w-[240px]"
            labels={row.original.tags ?? []}
            onSave={canWriteAssets ? (tags) => saveRowLabels(row.original.id, tags) : undefined}
          />
        ),
      },
    ]
  }, [classAndLens, canWriteAssets, saveRowLabels])

  return (
    <>
      <DataTable
        columns={columns}
        data={assets}
        showSearch={false}
        toolbarStart={toolbarStart}
        toolbarEnd={toolbarEnd}
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
        mobileRow={(a) => {
          const typeLabel = ASSET_TYPE_LABELS[a.type] ?? a.type
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
                    {/* Most assets are active; say so only when one is not. */}
                    {a.status !== 'active' && (
                      <AssetStatusBadge
                        status={a.status}
                        daysSinceLastSeen={daysSinceISO(a.lastSeen)}
                        snoozedUntil={a.lifecyclePausedUntil}
                      />
                    )}
                    {a.riskScore > 0 && <RiskScoreBadge score={a.riskScore} size="sm" />}
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
        emptyMessage="No assets match these filters"
        emptyDescription={
          hasFilters ? 'Try removing a filter or clearing them all.' : 'No assets yet.'
        }
      />

      <AssetDetailSheet
        asset={selectedAsset}
        open={!!selectedAsset}
        onOpenChange={(open) => !open && setSelectedAsset(null)}
        // Icon and title come from the asset's own type ("Repository details").
        // Edit/delete stay on the per-type pages, so those actions are gated
        // off here; tags are editable inline like on every other asset page.
        onEdit={() => {}}
        onDelete={() => {}}
        canEdit={false}
        canDelete={false}
        tagSuggestions={tagSuggestions}
        onUpdateTags={
          canWriteAssets
            ? async (tags: string[]) => {
                if (!selectedAsset) return
                try {
                  const updated = await updateAsset(selectedAsset.id, { tags })
                  toast.success('Tags updated')
                  // Lift the fresh asset into the sheet so it re-renders with the
                  // saved tags, then refetch the list in the background.
                  setSelectedAsset(updated)
                  onAssetUpdated?.()
                } catch (err) {
                  toast.error(err instanceof Error ? err.message : 'Failed to update tags')
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
