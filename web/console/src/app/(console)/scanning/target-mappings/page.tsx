'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, Waypoints } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  DataTable,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  MetricStrip,
  PageHeader,
  RelativeTime,
  StackedCell,
  type MetricStripItem,
} from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { AssetTypeIcon, getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  deleteTargetMapping,
  updateTargetMapping,
  useTargetMappingStats,
  useTargetMappings,
} from '@console/features/admin-console/api/use-target-mappings'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { TargetMappingDialog } from '@console/features/admin-console/components/target-mapping-dialog'
import {
  MAPPABLE_ASSET_TYPES,
  TARGET_TYPE_OPTIONS,
  targetTypeHint,
  targetTypeLabel,
} from '@console/features/admin-console/lib/target-mappings'
import { adminCan, type TargetMapping } from '@console/features/admin-console/types'
import { useTranslation } from '@/context/i18n-provider'

const ALL = 'all'
const PAGE_SIZES = [20, 50, 100]

const ASSET_FILTER_OPTIONS = MAPPABLE_ASSET_TYPES.map((v) => ({
  value: v,
  label: getAssetTypeLabel(v),
})).sort((a, b) => a.label.localeCompare(b.label))

function withStoredValues(
  options: { value: string; label: string }[],
  stored: Record<string, number> | undefined,
  label: (v: string) => string
) {
  const extra = Object.keys(stored ?? {})
    .filter((v) => !options.some((o) => o.value === v))
    .map((v) => ({ value: v, label: label(v) }))
  return [...options, ...extra].sort((a, b) => a.label.localeCompare(b.label))
}

type Pending =
  { kind: 'toggle'; mapping: TargetMapping } | { kind: 'delete'; mapping: TargetMapping }

const pairLabel = (m: TargetMapping) =>
  `${targetTypeLabel(m.target_type)} → ${getAssetTypeLabel(m.asset_type)}`

export default function TargetMappingsPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  // The API is the authority (ops_admin+ writes, super_admin deletes); these
  // only decide which controls to show.
  const canWrite = adminCan(me.role, 'ops_admin')
  const canDelete = adminCan(me.role, 'super_admin')

  const [targetType, setTargetType] = useUrlFilter('target_type', '')
  const [assetType, setAssetType] = useUrlFilter('asset_type', '')
  const [status, setStatus] = useUrlFilter('status', '')
  const listParams = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 50 })
  const { page, perPage } = listParams
  const filtered = !!(targetType || assetType || status)

  const list = useTargetMappings({ targetType, assetType, status, page, perPage })
  const stats = useTargetMappingStats()

  const [dialog, setDialog] = useState<{ mapping: TargetMapping | null } | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(() => {
    void list.mutate()
    void stats.mutate()
  }, [list, stats])

  const resetPage = () => listParams.setPage(1)
  const toggleStatus = (next: string) => {
    setStatus(status === next ? '' : next)
    resetPage()
  }

  const confirm = async () => {
    if (!pending) return
    setBusy(true)
    try {
      if (pending.kind === 'delete') {
        await deleteTargetMapping(pending.mapping.id)
        toast.success(
          t('admin.scanningTargetMappingsPage.deleted', '{pair} deleted', {
            pair: pairLabel(pending.mapping),
          })
        )
      } else {
        await updateTargetMapping(pending.mapping.id, { is_active: !pending.mapping.is_active })
        toast.success(
          pending.mapping.is_active
            ? t('admin.scanningTargetMappingsPage.deactivated', '{pair} deactivated', {
                pair: pairLabel(pending.mapping),
              })
            : t('admin.scanningTargetMappingsPage.activated', '{pair} activated', {
                pair: pairLabel(pending.mapping),
              })
        )
      }
      refresh()
      setPending(null)
    } catch (e) {
      toast.error(
        e instanceof AdminApiError
          ? e.message
          : t('admin.scanningTargetMappingsPage.theChangeFailed', 'The change failed')
      )
    } finally {
      setBusy(false)
    }
  }

  const s = stats.data
  // A scanner declaring one of these target types matches no asset at all.
  const unmappedTargets = s
    ? TARGET_TYPE_OPTIONS.map((o) => o.value).filter((v) => !s.by_target_type[v])
    : []
  // Filter choices: every accepted value plus any older value still stored, so
  // every row stays reachable through the filters.
  const targetFilterOptions = withStoredValues(
    TARGET_TYPE_OPTIONS.map((o) => ({ value: o.value, label: o.label })),
    s?.by_target_type,
    targetTypeLabel
  )
  const assetFilterOptions = withStoredValues(
    ASSET_FILTER_OPTIONS,
    s?.by_asset_type,
    getAssetTypeLabel
  )
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('admin.scanningTargetMappingsPage.mappings', 'Mappings'),
      value: s?.total ?? '—',
      active: !status,
      onClick: () => {
        setStatus('')
        resetPage()
      },
    },
    {
      key: 'active',
      label: t('admin.scanningTargetMappingsPage.active', 'Active'),
      value: s?.active_count ?? '—',
      onClick: () => toggleStatus('active'),
      active: status === 'active',
    },
    {
      key: 'inactive',
      label: t('admin.scanningTargetMappingsPage.inactive', 'Inactive'),
      value: s?.inactive_count ?? '—',
      hint: t(
        'admin.scanningTargetMappingsPage.ignoredBySmartFiltering',
        'Ignored by smart filtering'
      ),
      onClick: () => toggleStatus('inactive'),
      active: status === 'inactive',
    },
    {
      key: 'targets',
      label: t('admin.scanningTargetMappingsPage.targetTypesMapped', 'Target types mapped'),
      value: s ? Object.keys(s.by_target_type).length : '—',
      hint: unmappedTargets.length
        ? t('admin.scanningTargetMappingsPage.unmapped', '{length} unmapped', {
            length: unmappedTargets.length,
          })
        : undefined,
    },
    {
      key: 'assets',
      label: t('admin.scanningTargetMappingsPage.assetTypesCovered', 'Asset types covered'),
      value: s ? Object.keys(s.by_asset_type).length : '—',
    },
  ]

  const columns = useMemo<ColumnDef<TargetMapping>[]>(() => {
    const cols: ColumnDef<TargetMapping>[] = [
      {
        accessorKey: 'target_type',
        header: t('admin.scanningTargetMappingsPage.targetType', 'Target type'),
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            primary={targetTypeLabel(row.original.target_type)}
            secondary={targetTypeHint(row.original.target_type)}
          />
        ),
      },
      {
        accessorKey: 'asset_type',
        header: t('admin.scanningTargetMappingsPage.assetType', 'Asset type'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex items-center gap-2 text-sm">
            <AssetTypeIcon
              type={row.original.asset_type}
              className="size-4 shrink-0 text-muted-foreground"
            />
            {getAssetTypeLabel(row.original.asset_type)}
          </span>
        ),
      },
      {
        accessorKey: 'priority',
        header: t('admin.scanningTargetMappingsPage.priority', 'Priority'),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex items-center gap-2">
            <span className="text-sm tabular-nums">{row.original.priority}</span>
            {row.original.is_primary && (
              <Badge variant="secondary">
                {t('admin.scanningTargetMappingsPage.primary', 'Primary')}
              </Badge>
            )}
          </span>
        ),
      },
      {
        accessorKey: 'is_active',
        header: t('admin.scanningTargetMappingsPage.status', 'Status'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.is_active ? (
            <Badge variant="secondary">
              {t('admin.scanningTargetMappingsPage.active', 'Active')}
            </Badge>
          ) : (
            <Badge variant="outline">
              {t('admin.scanningTargetMappingsPage.inactive', 'Inactive')}
            </Badge>
          ),
      },
      {
        accessorKey: 'description',
        header: t('admin.scanningTargetMappingsPage.description', 'Description'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.description ? (
            <span className="line-clamp-2 max-w-xs text-sm">{row.original.description}</span>
          ) : (
            <span className="text-sm text-muted-foreground">-</span>
          ),
      },
      {
        accessorKey: 'updated_at',
        header: t('admin.scanningTargetMappingsPage.updated', 'Updated'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.updated_at} className="text-sm" />,
      },
    ]
    if (canWrite) {
      cols.push({
        id: 'actions',
        enableSorting: false,
        cell: ({ row }) => {
          const m = row.original
          return (
            <DataTableRowActions
              actions={[
                {
                  label: t('admin.scanningTargetMappingsPage.edit', 'Edit'),
                  onClick: () => setDialog({ mapping: m }),
                },
                {
                  label: m.is_active
                    ? t('admin.scanningTargetMappingsPage.deactivate', 'Deactivate')
                    : t('admin.scanningTargetMappingsPage.activate', 'Activate'),
                  onClick: () => setPending({ kind: 'toggle', mapping: m }),
                },
                ...(canDelete
                  ? [
                      {
                        label: t('admin.scanningTargetMappingsPage.delete', 'Delete'),
                        onClick: () => setPending({ kind: 'delete', mapping: m }),
                        destructive: true,
                        separatorBefore: true,
                      },
                    ]
                  : []),
              ]}
            />
          )
        },
      })
    }
    return cols
  }, [canWrite, canDelete, t])

  const newButton = canWrite ? (
    <Button size="sm" onClick={() => setDialog({ mapping: null })}>
      <Plus className="me-2 size-4" />
      {t('admin.scanningTargetMappingsPage.newMapping', 'New mapping')}
    </Button>
  ) : null

  const noMappingsAtAll = !list.isLoading && !filtered && list.data?.total === 0

  return (
    <Main>
      <PageHeader
        title={t('admin.scanningTargetMappingsPage.targetMappings', 'Target mappings')}
        description={t(
          'admin.scanningTargetMappingsPage.whichAssetTypesEachScanner',
          'Which asset types each scanner target type can scan. Scans skip assets that no active mapping covers.'
        )}
      >
        {newButton}
      </PageHeader>
      <div className="mt-5 space-y-5">
        <MetricStrip items={metrics} loading={stats.isLoading} />
        {list.error ? (
          <ErrorState
            title={t('admin.scanningTargetMappingsPage.targetMappings2', 'target mappings')}
            error={list.error}
            onRetry={refresh}
          />
        ) : noMappingsAtAll ? (
          <EmptyState
            icon={Waypoints}
            title={t('admin.targetMappings.emptyTitle', 'No target mappings')}
            description={t(
              'admin.targetMappings.empty',
              'Without mappings, scans skip every asset. Map each scanner target type to the asset types it can scan.'
            )}
            action={newButton}
          />
        ) : (
          <DataTable
            columns={columns}
            data={list.data?.data ?? []}
            getRowId={(m) => m.id}
            isLoading={list.isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            emptyMessage={t(
              'admin.scanningTargetMappingsPage.noMappingMatchesTheseFilters',
              'No mapping matches these filters'
            )}
            manualPagination
            pageCount={list.data?.total_pages ?? 1}
            rowCount={list.data?.total ?? 0}
            pageSizeOptions={PAGE_SIZES}
            pagination={{ pageIndex: page - 1, pageSize: perPage }}
            onPaginationChange={listParams.setPagination}
            toolbarStart={
              <div className="flex w-full flex-col gap-2 sm:flex-row">
                <Select
                  value={targetType || ALL}
                  onValueChange={(v) => {
                    setTargetType(v === ALL ? '' : v)
                    resetPage()
                  }}
                >
                  <SelectTrigger
                    className="sm:w-48"
                    aria-label={t(
                      'admin.scanningTargetMappingsPage.filterByTargetType',
                      'Filter by target type'
                    )}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL}>
                      {t('admin.scanningTargetMappingsPage.allTargetTypes', 'All target types')}
                    </SelectItem>
                    {targetFilterOptions.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={assetType || ALL}
                  onValueChange={(v) => {
                    setAssetType(v === ALL ? '' : v)
                    resetPage()
                  }}
                >
                  <SelectTrigger
                    className="sm:w-56"
                    aria-label={t(
                      'admin.scanningTargetMappingsPage.filterByAssetType',
                      'Filter by asset type'
                    )}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ALL}>
                      {t('admin.scanningTargetMappingsPage.allAssetTypes', 'All asset types')}
                    </SelectItem>
                    {assetFilterOptions.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {filtered && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="sm:self-center"
                    onClick={() => {
                      setTargetType('')
                      setAssetType('')
                      setStatus('')
                      resetPage()
                    }}
                  >
                    {t('admin.scanningTargetMappingsPage.clearFilters', 'Clear filters')}
                  </Button>
                )}
              </div>
            }
          />
        )}
      </div>

      {dialog && (
        <TargetMappingDialog
          key={dialog.mapping?.id ?? 'new'}
          open
          onOpenChange={(open) => !open && setDialog(null)}
          mapping={dialog.mapping}
          defaultTargetType={targetType || undefined}
          onSaved={refresh}
        />
      )}

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => !open && setPending(null)}
        title={
          pending?.kind === 'delete'
            ? t('confirm.targetMapping.deleteTitle', 'Delete the target mapping {pair}?', {
                pair: pairLabel(pending.mapping),
              })
            : pending?.mapping.is_active
              ? t(
                  'confirm.targetMapping.deactivateTitle',
                  'Deactivate the target mapping {pair}?',
                  {
                    pair: pairLabel(pending.mapping),
                  }
                )
              : t('confirm.targetMapping.activateTitle', 'Activate the target mapping {pair}?', {
                  pair: pending ? pairLabel(pending.mapping) : '',
                })
        }
        desc={
          pending?.kind === 'delete'
            ? t(
                'confirm.targetMapping.deleteDesc',
                'Scanners that only reach {type} assets through it will skip them. To pause it instead, deactivate it.',
                { type: getAssetTypeLabel(pending.mapping.asset_type) }
              )
            : pending?.mapping.is_active
              ? t(
                  'confirm.targetMapping.deactivateDesc',
                  'It is kept but ignored: scanners that only reach these assets through it will skip them.'
                )
              : t('confirm.targetMapping.activateDesc', 'It is used again when scans are filtered.')
        }
        confirmText={
          pending?.kind === 'delete'
            ? t('confirm.delete', 'Delete')
            : pending?.mapping.is_active
              ? t('confirm.targetMapping.deactivate', 'Deactivate')
              : t('confirm.targetMapping.activate', 'Activate')
        }
        destructive={pending?.kind === 'delete' || !!pending?.mapping.is_active}
        isLoading={busy}
        handleConfirm={() => void confirm()}
      />
    </Main>
  )
}
