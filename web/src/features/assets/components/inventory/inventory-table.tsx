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

import { useCallback, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Boxes, User, UserX, Users } from 'lucide-react'
import { formatLocalized, formatRelative } from '@/lib/format-date'
import { toast } from 'sonner'
import { Checkbox } from '@/components/ui/checkbox'
import { ScopeCheckBadge, useScopeCheck } from '@/features/scope'
import { ScopeTriageBadge } from './scope-triage-badge'
import { MonitoringStateControl } from './monitoring-state-control'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { MetaLine } from '@/features/shared/components/text-layout'
import { toDisplayText } from '@/lib/untrusted-text'
import { assetDetailHref } from '@/features/findings/lib/asset-link'
import type { TypeView } from '@/features/asset-types/lib/type-view'
import { propertyLabel } from '@/features/asset-types/lib/property-schema'
import { rowActionsFor } from '../../lib/type-actions'
import { AttributeCell } from './attribute-cell'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  RiskScoreBadge,
  riskScoreState,
  type DataTableBulk,
  type DataTableEmptyStates,
  type DataTableSearch,
  type DataTableSelectMode,
  type FilterPanelToggleProps,
} from '@/features/shared'
import { AssetRowMenu } from './asset-row-menu'
import { AssetLivenessBadge, AssetStatusBadge } from '@/features/asset-lifecycle'
import { useAssetTypeRegistry } from '@/features/asset-types/api/use-asset-type-registry'
import { CriticalityBadge, ExposureBadge } from '../classification-badges'
import { AssetDetailSheet } from '../asset-detail-sheet'
import { ScanConfirmDialog } from '../scan-confirm-dialog'
import { getAsset, updateAsset } from '../../hooks'
import { tagChange } from '../../lib/tag-change'
import { useAssetTags } from '../../hooks/use-asset-tags'
import { isPlainLeftClick } from '../../lib/plain-click'
import { AssetTypeIcon } from '../../lib/asset-type-icon'
import { AssetNameCell } from './asset-name-cell'
import { typeKeyOf } from '../../lib/inventory-lenses'
import { NamesCell, NetworkCell, PortsCell } from './ip-cells'
import { Permission, usePermissions } from '@/lib/permissions'
import type { Asset } from '../../types/asset.types'
import { SORT_FIELDS, sortToSorting, sortingToSort } from '../../lib/inventory-url'
import {
  OpenFindingsCell,
  OpenFindingsLink,
  LabelChips,
  SurfaceFactsLine,
  cellsForType,
  hasSurfaceFacts,
  surfaceCellsCovered,
} from '../service-cells'
import { BreakText } from '@/features/shared/components/break-text'

/**
 * Column widths in px (each holds its cell padding). A width fits the column's
 * header word with its sort arrow and its longest standard value, in English
 * and Vietnamese, so no chip is cut and no header folds.
 */
const WIDTH = {
  select: 40,
  // The name's floor: the least it gets before a column drops.
  name: 200,
  // The kit's `risk` kind (the badge's longest state whole).
  risk: 148,
  type: 140,
  // "Guardrail hold", "Giữ bởi rào chắn".
  scope: 136,
  // The state chip with its menu arrow: "Không hoạt động".
  monitoring: 152,
  service: 268,
  // The header sets these three: "Mức độ quan trọng", "Mức phơi nhiễm",
  // "Phát hiện đang mở", each with its sort arrow.
  criticality: 140,
  exposure: 124,
  findings: 150,
  // "No owner", "Chưa có chủ sở hữu" with its icon.
  owner: 160,
  last_seen: 160,
  actions: 48,
} as const

/** What always shows: the checkbox, name, risk, scope, service facts and the row menu. */
const BASE_ROOM =
  WIDTH.select + WIDTH.name + WIDTH.risk + WIDTH.scope + WIDTH.service + WIDTH.actions

/**
 * Column priority: the table frame width each lower-priority column needs
 * before it shows, so a narrow screen drops columns instead of scrolling the
 * table sideways. Name, risk, scope and service facts always show; then open
 * findings, monitoring, criticality, exposure, owner and last seen join in
 * that order. Each value is the running sum of the widths shown at it. A
 * column turned on or off under Columns keeps that choice.
 */
const COLUMN_ROOM = {
  findings: BASE_ROOM + WIDTH.findings,
  monitoring: BASE_ROOM + WIDTH.findings + WIDTH.monitoring,
  criticality: BASE_ROOM + WIDTH.findings + WIDTH.monitoring + WIDTH.criticality,
  exposure: BASE_ROOM + WIDTH.findings + WIDTH.monitoring + WIDTH.criticality + WIDTH.exposure,
  owner:
    BASE_ROOM +
    WIDTH.findings +
    WIDTH.monitoring +
    WIDTH.criticality +
    WIDTH.exposure +
    WIDTH.owner,
  last_seen:
    BASE_ROOM +
    WIDTH.findings +
    WIDTH.monitoring +
    WIDTH.criticality +
    WIDTH.exposure +
    WIDTH.owner +
    WIDTH.last_seen,
} as const

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

/**
 * Criticality on a phone card, in plain words that name themselves (never a
 * bare "High", which a risk band also is). An asset not rated yet says nothing.
 */
const CARD_CRITICALITY = {
  critical: { key: 'assets.card.criticality.critical', text: 'Business-critical' },
  high: { key: 'assets.card.criticality.high', text: 'High criticality' },
  medium: { key: 'assets.card.criticality.medium', text: 'Medium criticality' },
  low: { key: 'assets.card.criticality.low', text: 'Low criticality' },
} as const

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
  /** More than 10,000 match: `total` is then 10,000 (shown as "10,000+"). */
  totalCapped?: boolean
  /** 1-based page, as in the URL. */
  page: number
  pageSize: number
  sort?: string
  onPageChange: (page: number, pageSize: number) => void
  onSortChange: (sort: string | undefined) => void
  /**
   * Several assets at once: the table adds the checkbox column and the bulk
   * bar. Absent when the viewer holds no bulk permission (no checkbox column).
   */
  bulk?: DataTableBulk<Asset>
  /** Phone select mode, held by the page (its More offers "Select"). */
  selectMode?: DataTableSelectMode
  resetSelectionKey: number
  /** The first read: skeleton rows under a toolbar that stays mounted. */
  isLoading?: boolean
  /** Rows already on screen are being re-read (the thin bar on the frame's top edge). */
  isRefreshing?: boolean
  /** What an empty list shows: one block, or the first-run and no-match pair. */
  emptyState?: ReactNode | DataTableEmptyStates
  /** Clears the search and the filters (the no-match action). */
  onClearFilters?: () => void
  /** Shown in place of the rows when the read failed; the toolbar stays. */
  errorState?: ReactNode
  /** The list's search box (the toolbar draws it). */
  search?: DataTableSearch
  /** The facet panel's trigger (side panel from lg, sheet below), joined to the search. */
  filterToggle?: FilterPanelToggleProps
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
  /** A click on an address's network filters the list to it (the IP addresses tab). */
  onFilterNetwork?: (network: string) => void
}

export function InventoryTable({
  assets,
  total,
  totalCapped,
  page,
  pageSize,
  sort,
  onPageChange,
  onSortChange,
  bulk,
  selectMode,
  resetSelectionKey,
  isLoading,
  isRefreshing,
  emptyState,
  onClearFilters,
  errorState,
  search,
  filterToggle,
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
  onFilterNetwork,
}: InventoryTableProps) {
  const [selectedSnapshot, setSelectedAsset] = useState<Asset | null>(null)
  // The repository a row's Scan was clicked on, until the user confirms it.
  const [scanTarget, setScanTarget] = useState<Asset | null>(null)
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
  const { t, locale } = useTranslation()
  const isPhone = useIsMobile()
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

  // "+ Add label" on a row: the label added to that asset's tags (never the
  // row's whole list: a tag stored since the list loaded stays), then a refetch.
  const saveRowLabels = useCallback(
    async (id: string, shown: string[], tags: string[]) => {
      try {
        await updateAsset(id, tagChange(shown, tags))
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

  // One menu for the table row and the phone card.
  const rowMenu = useCallback(
    (asset: Asset, size?: 'icon') => (
      <AssetRowMenu
        asset={asset}
        typeView={typeView}
        size={size}
        onScan={setScanTarget}
        onEdit={canWriteAssets ? onEditAsset : undefined}
        onDelete={canDeleteAssets ? onDeleteAsset : undefined}
      />
    ),
    [typeView, canWriteAssets, canDeleteAssets, onEditAsset, onDeleteAsset]
  )

  // The IP addresses list (the tab, or the type picked another way) has its own columns.
  const ipColumns = typeView?.type === 'ip_address' && !typeView.subType
  const columns = useMemo<ColumnDef<Asset>[]>(() => {
    const sortable = (id: string) => id in SORT_FIELDS
    const all: ColumnDef<Asset>[] = [
      {
        id: 'name',
        accessorKey: 'name',
        // The row's identifying column: frozen while the table scrolls sideways.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: WIDTH.name,
          label: t('assets.properties.columns.name', 'Name'),
        },
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
            // Every-type list: the type under the name (research/266), so the
            // Type column is off by default and the name keeps its width.
            subtitle={
              typeView
                ? undefined
                : (() => {
                    const key = typeKeyOf(registry, row.original.type, row.original.subType)
                    return t(`assets.typeLabel.${key.type}`, key.label)
                  })()
            }
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
        meta: {
          kind: 'text',
          minWidth: 120,
          maxWidth: 240,
          label: propertyLabel(attribute.key, locale),
        },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={propertyLabel(attribute.key, locale)} />
        ),
        cell: ({ row }) => <AttributeCell asset={row.original} attribute={attribute} />,
      })),
      // The IP addresses tab: where an address sits, what resolves to it, what listens.
      ...(ipColumns
        ? ([
            {
              id: 'ip_network',
              meta: { kind: 'text', width: 152, label: t('assets.ip.network', 'Network /24') },
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader
                  column={column}
                  title={t('assets.ip.network', 'Network /24')}
                />
              ),
              cell: ({ row }) => <NetworkCell ip={row.original.ip} onFilter={onFilterNetwork} />,
            },
            {
              id: 'ip_names',
              meta: {
                kind: 'text',
                minWidth: 160,
                maxWidth: 280,
                label: t('assets.ip.names', 'Names'),
              },
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader column={column} title={t('assets.ip.names', 'Names')} />
              ),
              cell: ({ row }) => <NamesCell ip={row.original.ip} />,
            },
            {
              id: 'ip_ports',
              meta: {
                kind: 'text',
                minWidth: 140,
                maxWidth: 240,
                label: t('assets.ip.ports', 'Open ports'),
              },
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader column={column} title={t('assets.ip.ports', 'Open ports')} />
              ),
              cell: ({ row }) => <PortsCell ip={row.original.ip} />,
            },
          ] satisfies ColumnDef<Asset>[])
        : []),
      {
        id: 'risk',
        meta: { kind: 'risk', label: t('components.col.risk', 'Risk') },
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
        id: 'type',
        meta: {
          kind: 'text',
          width: WIDTH.type,
          label: t('assets.properties.columns.type', 'Type'),
        },
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
              meta: { kind: 'status', width: WIDTH.scope, label: t('scope.check.column', 'Scope') },
              enableSorting: false,
              header: ({ column }) => (
                <DataTableColumnHeader column={column} title={t('scope.check.column', 'Scope')} />
              ),
              cell: ({ row }) => <ScopeTriageBadge triage={row.original.triage} />,
            } as ColumnDef<Asset>,
          ]
        : []),
      {
        // The one derived lifecycle state (monitored, pending decision, ...).
        id: 'monitoring_state',
        meta: {
          kind: 'status-edit',
          width: WIDTH.monitoring,
          hideBelow: COLUMN_ROOM.monitoring,
          label: t('assets.monitoring.column', 'Monitoring'),
        },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.monitoring.column', 'Monitoring')}
          />
        ),
        cell: ({ row }) => (
          <MonitoringStateControl
            assetId={row.original.id}
            assetName={row.original.name}
            state={row.original.monitoringState}
            attributionState={row.original.triage?.attributionState}
            canWrite={canWriteAssets}
            onChanged={onAssetUpdated}
          />
        ),
      },
      {
        // External-surface facts (status, IP, technologies, TLS …) for the
        // types cellsForType lists; other types have none to show here.
        // Only known facts are shown; a row with none shows the muted dash.
        id: 'service',
        meta: {
          kind: 'text',
          width: WIDTH.service,
          label: t('assets.facts.title', 'Service facts'),
        },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.facts.title', 'Service facts')} />
        ),
        // One line (research/266) in a fixed width: as many whole facts as
        // fit (status code, port, edge, what runs there), then "+N" opening
        // every fact, so rows keep one height and no chip is cut.
        cell: ({ row }) => (
          <div className="w-64">
            {cellsForType(row.original.type, row.original.subType) ? (
              <SurfaceFactsLine asset={row.original} />
            ) : (
              <span className="text-muted-foreground">—</span>
            )}
          </div>
        ),
      },
      {
        id: 'criticality',
        meta: {
          kind: 'severity',
          width: WIDTH.criticality,
          hideBelow: COLUMN_ROOM.criticality,
          label: t('assets.badge.criticality', 'Criticality'),
        },
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
        meta: {
          kind: 'status',
          width: WIDTH.exposure,
          hideBelow: COLUMN_ROOM.exposure,
          label: t('assets.badge.exposure', 'Exposure'),
        },
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
        id: 'findings',
        meta: {
          kind: 'number',
          width: WIDTH.findings,
          hideBelow: COLUMN_ROOM.findings,
          label: t('assets.col.openFindings', 'Open findings'),
        },
        accessorKey: 'findingCount',
        enableSorting: sortable('findings'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('assets.col.openFindings', 'Open findings')}
          />
        ),
        cell: ({ row }) => (
          <OpenFindingsCell assetId={row.original.id} count={row.original.findingCount} />
        ),
      },
      {
        id: 'owner',
        meta: {
          kind: 'owner',
          width: WIDTH.owner,
          hideBelow: COLUMN_ROOM.owner,
          label: t('assets.inv.col.owner', 'Owner'),
        },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.inv.col.owner', 'Owner')} />
        ),
        cell: ({ row }) => {
          const owner = row.original.primaryOwner
          if (owner) {
            const Icon = owner.type === 'group' ? Users : User
            return (
              <div className="flex min-w-0 items-center gap-1.5">
                <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate text-sm">{owner.name}</span>
              </div>
            )
          }
          if (row.original.ownerRef) {
            return <span className="truncate text-sm">{row.original.ownerRef}</span>
          }
          // A gap, not a value: muted, dashed icon (Needs attention lists them).
          return (
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-muted-foreground">
              <UserX className="h-3.5 w-3.5 shrink-0" aria-hidden />
              {t('assets.inv.noOwner', 'No owner')}
            </span>
          )
        },
      },
      {
        id: 'last_seen',
        // The time, then the lifecycle state when it is not active: start
        // aligned, since the state follows the time.
        meta: {
          kind: 'text',
          width: WIDTH.last_seen,
          sortFirst: 'desc',
          hideBelow: COLUMN_ROOM.last_seen,
          label: t('components.col.lastSeen', 'Last seen'),
        },
        accessorKey: 'lastSeen',
        enableSorting: sortable('last_seen'),
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('components.col.lastSeen', 'Last seen')}
          />
        ),
        // The time it was last seen (the column's name); the lifecycle state
        // only when it is not active, since nearly every row is.
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-2 whitespace-nowrap">
            <time
              dateTime={row.original.lastSeen || undefined}
              title={formatLocalized(row.original.lastSeen, locale, { time: true })}
              className="text-sm tabular-nums text-muted-foreground"
            >
              {formatRelative(row.original.lastSeen, '—', locale)}
            </time>
            {row.original.status !== 'active' && (
              <AssetStatusBadge
                status={row.original.status}
                daysSinceLastSeen={daysSinceISO(row.original.lastSeen)}
                snoozedUntil={row.original.lifecyclePausedUntil}
              />
            )}
            <AssetLivenessBadge liveness={row.original.liveness} />
          </span>
        ),
      },
      {
        id: 'tags',
        meta: { kind: 'tags', label: t('assets.inv.col.labels', 'Labels') },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.inv.col.labels', 'Labels')} />
        ),
        cell: ({ row }) => (
          <LabelChips
            className="max-w-[240px]"
            labels={row.original.tags ?? []}
            onSave={
              canWriteAssets
                ? (tags) => saveRowLabels(row.original.id, row.original.tags ?? [], tags)
                : undefined
            }
            activeLabels={filterTags}
            onLabelClick={onToggleTagFilter}
          />
        ),
      },
      ...(typeView?.scannable && scopeAvailable
        ? [
            {
              id: 'scope',
              meta: { kind: 'status', width: WIDTH.scope, label: t('scope.check.column', 'Scope') },
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
        meta: { kind: 'actions', label: t('components.col.actions', 'Actions') },
        enableSorting: false,
        enableHiding: false,
        header: () => <span className="sr-only">{t('components.col.actions', 'Actions')}</span>,
        // One menu component for the table row and the phone card.
        cell: ({ row }) => rowMenu(row.original),
      },
    ]
    return all.filter(
      (c) =>
        !typeView ||
        (c.id !== 'type' &&
          // An address's ports have their own column here.
          (c.id !== 'service' || (!ipColumns && showsServiceFacts(typeView))))
    )
  }, [
    ipColumns,
    onFilterNetwork,
    classAndLens,
    registry,
    canWriteAssets,
    rowMenu,
    saveRowLabels,
    typeView,
    scopeAvailable,
    scopeResultFor,
    scopeChecking,
    t,
    locale,
    filterTags,
    onToggleTagFilter,
    onAssetUpdated,
  ])

  // The two kinds of empty list: nothing yet (the organization, or this type,
  // has no asset: how to get some), and no match (the filters left no row:
  // clear them).
  const emptyStates: DataTableEmptyStates = {
    nothingYet: (
      <EmptyState
        icon={Boxes}
        title={emptyMessage ?? t('assets.inv.emptyNoneTitle', 'No assets in this organization yet')}
        description={
          emptyDescription ??
          t(
            'assets.inv.emptyNoneHint',
            'Add an asset, or set up discovery to find the names, addresses and services your organization exposes.'
          )
        }
      />
    ),
    // The table keeps its icon, layout and Clear filters action.
    noMatch: {
      title: t('assets.inv.emptyFiltered', 'No assets match these filters'),
      hint: t('assets.inv.emptyFilteredHint', 'Try removing a filter or clearing them all.'),
    },
  }

  return (
    <>
      <ScanConfirmDialog
        open={!!scanTarget}
        onOpenChange={(open) => !open && setScanTarget(null)}
        names={scanTarget ? [scanTarget.name] : []}
        onConfirm={async () => {
          const target = scanTarget
          setScanTarget(null)
          if (target)
            await rowActionsFor(target, typeView, t)
              .find((a) => a.id === 'scan')
              ?.run(target)
        }}
      />
      <DataTable
        columns={columns}
        data={assets}
        showSearch={false}
        search={search}
        filterToggle={filterToggle}
        emptyState={emptyState ?? emptyStates}
        errorState={errorState}
        toolbarStart={toolbarStart}
        toolbarEnd={toolbarEnd}
        toolbarBelow={toolbarBelow}
        getRowId={(a) => a.id}
        manualPagination
        rowCount={total}
        rowCountCapped={totalCapped}
        pagination={{ pageIndex: Math.max(0, page - 1), pageSize }}
        onPaginationChange={(p) => onPageChange(p.pageIndex + 1, p.pageSize)}
        pageSize={pageSize}
        paginationNoun={t('assets.inv.paginationNoun', 'assets')}
        // A phone list that shows every asset has no footer: its count is
        // already beside the view name.
        showPagination={!(isPhone && page === 1 && total <= assets.length)}
        sorting={sorting}
        onSortingChange={(next) => onSortChange(sortingToSort(next))}
        // No bulk action for this user: no checkbox column either.
        bulk={bulk}
        selectMode={selectMode}
        resetSelectionKey={resetSelectionKey}
        showSelectionCount={false}
        isLoading={isLoading}
        isRefreshing={isRefreshing}
        refreshingLabel={t('assets.inv.refreshing', 'Refreshing assets')}
        // A list of one type with no other filter is "nothing yet", not "no match".
        isFiltered={hasFilters && !emptyMessage}
        onClearFilters={onClearFilters}
        onRowClick={setSelectedAsset}
        // Labels are a working column, not a reading one: on under Columns.
        // The type is the name's second line, so its own column is off too.
        initialColumnVisibility={{ tags: false, type: false }}
        mobileRow={(a, selection) => {
          const typeKey = typeKeyOf(registry, a.type, a.subType)
          const typeLabel = t(`assets.typeLabel.${typeKey.type}`, typeKey.label)
          const context = a.groupName || a.description
          const riskState = riskScoreState(a)
          const scored = (riskState === 'scored' || riskState === 'pending') && a.riskScore > 0
          const criticality = CARD_CRITICALITY[a.criticality as keyof typeof CARD_CRITICALITY]
          // The card has fixed slots, so every card reads the same way: the
          // name (two lines at most), one line saying what it is (the type,
          // then its group or description, as separate items), one line of
          // plain facts (criticality in words, open findings, and a standing
          // only when it is not the usual one), and the risk slot at the end,
          // always there: the score under the word "Risk", or a dash while
          // there is none. The whole card opens the drawer (a stretched
          // button); the checkbox, the facts' links and the row menu sit
          // above it.
          return (
            <div
              data-testid="asset-phone-card"
              data-state={selection.selected ? 'selected' : undefined}
              className="relative flex items-start gap-1 ps-3 pe-1 transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted"
            >
              {selection.selectable && (
                <div className="relative z-10 flex h-10 shrink-0 items-center pt-2">
                  <Checkbox
                    checked={selection.selected}
                    onCheckedChange={(v) => selection.onSelectedChange(!!v)}
                    aria-label={t('assets.inv.selectAsset', 'Select asset {name}', {
                      name: toDisplayText(a.name, 80),
                    })}
                  />
                </div>
              )}
              <div className="min-w-0 flex-1 py-3">
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
                    <p className="line-clamp-2 break-words text-sm font-medium"><BreakText>{a.name}</BreakText></p>
                    <MetaLine
                      className="mt-0.5 flex-nowrap"
                      items={[
                        <span key="type" className="shrink-0">
                          {typeLabel}
                        </span>,
                        context && (
                          <span key="context" className="min-w-0 truncate">
                            {context}
                          </span>
                        ),
                      ]}
                    />
                  </div>
                  <div
                    data-slot="asset-card-risk"
                    className="flex w-10 shrink-0 flex-col items-end"
                  >
                    <span className="text-xs leading-4 text-muted-foreground">
                      {t('components.col.risk', 'Risk')}
                    </span>
                    {scored ? (
                      <RiskScoreBadge
                        score={a.riskScore}
                        state={riskState}
                        size="md"
                        className="font-semibold"
                      />
                    ) : (
                      <span
                        className="text-sm text-muted-foreground"
                        title={t('riskScore.notScored', 'Not yet scored')}
                      >
                        <span aria-hidden>—</span>
                        <span className="sr-only">
                          {t('riskScore.notScored', 'Not yet scored')}
                        </span>
                      </span>
                    )}
                  </div>
                </button>
                <div
                  data-slot="asset-card-meta"
                  className="pointer-events-none relative z-10 mt-1.5 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 ps-7 text-xs text-muted-foreground [&_a]:pointer-events-auto [&_button]:pointer-events-auto"
                >
                  {criticality && (
                    <span data-slot="asset-card-criticality">
                      {t(criticality.key, criticality.text)}
                    </span>
                  )}
                  <OpenFindingsLink assetId={a.id} count={a.findingCount} />
                  {/* Scope standing only when a scan may not reach it. */}
                  {a.triage && !a.triage.scanAllowed && <ScopeTriageBadge triage={a.triage} />}
                  {/* Most assets are active; say so only when one is not. */}
                  {a.status !== 'active' && (
                    <AssetStatusBadge
                      status={a.status}
                      daysSinceLastSeen={daysSinceISO(a.lastSeen)}
                      snoozedUntil={a.lifecyclePausedUntil}
                    />
                  )}
                  <AssetLivenessBadge liveness={a.liveness} />
                </div>
                {hasSurfaceFacts(a) && (
                  <div className="pointer-events-none relative z-10 mt-1.5 min-w-0 ps-7 [&_a]:pointer-events-auto [&_button]:pointer-events-auto">
                    <SurfaceFactsLine asset={a} max={2} />
                  </div>
                )}
              </div>
              <div className="relative z-10 flex h-10 shrink-0 items-center pt-2">
                {rowMenu(a, 'icon')}
              </div>
            </div>
          )
        }}
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
                  const updated = await updateAsset(
                    selectedAsset.id,
                    tagChange(selectedAsset.tags ?? [], tags)
                  )
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
