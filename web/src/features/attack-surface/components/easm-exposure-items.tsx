'use client'

/**
 * Attack surface > Exposure items: every exposure of the external surface as
 * one table, with the counts by severity and by type above it. By default
 * the open exposures (active and in progress) of monitored assets; a
 * group-by-asset view; the severity cell changes the severity (reason
 * required, audited) and the row menu moves the status through the typed
 * exposure commands. Rows come from the data-scoped read-layer endpoint;
 * titles, summaries and asset names are scan output, shown as text.
 */

import { useCallback, useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import {
  AlertTriangle,
  Check,
  Download,
  Gauge,
  LayoutList,
  PlayCircle,
  RefreshCw,
  Server,
  ShieldX,
  Star,
  X,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DataTable,
  DataTableRowActions,
  EmptyState,
  ErrorState,
  FilterSelect,
  MetricStrip,
  RelativeTime,
  SeverityBadge,
  StackedCell,
  ViewSwitcher,
  type MetricStripItem,
} from '@/features/shared'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import {
  APPROVE_REQUIRED_REASON,
  ExposureActionDialog,
  ExposureSeverityCell,
  ExposureSeverityDialog,
  ExposureStateBadge,
  ExposureSummaryLine,
  PendingDispositionBadge,
  useCanApproveExposures,
  useCanChangeExposureSeverity,
  type ExposureActionType,
} from '@/features/exposures/components'
import { exposureSummaryText } from '@/features/exposures/lib/summary'
import { MonitoringStateChip } from '@/features/assets/components/inventory/monitoring-state-chip'
import {
  MONITORING_STATES,
  MONITORING_STATE_FALLBACK,
  type MonitoringState,
} from '@/features/assets/lib/monitoring-state'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { downloadCsv } from '@/hooks/use-csv-export'
import { Permission, useHasPermission } from '@/lib/permissions'
import { ACTIONABLE_SEVERITIES, SEVERITY_LABELS } from '@/lib/severity'
import { cn } from '@/lib/utils'
import {
  EXPOSURE_DISPLAY_CATEGORIES,
  type ExposureDisplayCategory,
  type ExposureSeverity,
  type ExposureState,
} from '@/lib/api/exposure-types'
import {
  fetchAllExposureItems,
  useExposureAssetGroups,
  useExposureItemStats,
  useExposureItems,
} from '../hooks/use-exposure-items'
import {
  ANY,
  DEFAULT_MONITORING_PARAM,
  DEFAULT_STATE_PARAM,
  ITEM_STATES,
  exposureItemsCsv,
  filtersFromParams,
  toggleValue,
  visibleCategories,
  type ExposureAssetGroupRow,
  type ExposureItemFilters,
  type ExposureItemRow,
  type ExposureItemStats,
} from '../lib/exposure-items'

const PAGE_SIZES = [20, 50, 100]
const SORT_FIELDS = ['severity', 'last_seen', 'first_seen', 'asset_name', 'state'] as const
type View = 'list' | 'assets'

const STATE_FALLBACK: Record<ExposureState, string> = {
  active: 'Active',
  in_progress: 'In progress',
  resolved: 'Resolved',
  accepted: 'Accepted',
  false_positive: 'False positive',
}

const CATEGORY_FALLBACK: Record<string, string> = Object.fromEntries(
  EXPOSURE_DISPLAY_CATEGORIES.map((c) => [c.key, c.label])
)

function useLabels() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      severity: (s: ExposureSeverity) => t(`severity.${s}`, SEVERITY_LABELS[s]),
      state: (s: ExposureState) => t(`exposures.state.${s}`, STATE_FALLBACK[s]),
      category: (c: string) => t(`exposures.category.${c}`, CATEGORY_FALLBACK[c] ?? c),
      monitoring: (m: MonitoringState) =>
        t(`assets.monitoring.state.${m}`, MONITORING_STATE_FALLBACK[m]),
    }),
    [t]
  )
}

/** The primary-asset marker: one of the organization's root domains. */
export function PrimaryAssetMarker() {
  const { t } = useTranslation()
  const label = t('attackSurface.exposures.primary', 'Primary asset')
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex shrink-0 text-primary">
          <Star className="h-3.5 w-3.5 fill-current" aria-hidden />
          <span className="sr-only">{label}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        {t(
          'attackSurface.exposures.primaryHint',
          'Primary asset: one of your root domains, the names your external attack surface is discovered from.'
        )}
      </TooltipContent>
    </Tooltip>
  )
}

/** The asset cell: primary marker, name (links to the asset) and its monitoring state. */
function AssetCell({
  id,
  name,
  primary,
  monitoring,
}: {
  id?: string
  name?: string
  primary: boolean
  monitoring?: string
}) {
  const { t } = useTranslation()
  if (!id || !name) {
    return (
      <span className="text-muted-foreground">
        {t('attackSurface.exposures.noAsset', 'No asset')}
      </span>
    )
  }
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      <span className="flex min-w-0 items-center gap-1.5">
        {primary && <PrimaryAssetMarker />}
        <Link
          href={`/assets/${id}`}
          className="truncate font-medium hover:underline"
          title={name}
          onClick={(e) => e.stopPropagation()}
        >
          {name}
        </Link>
      </span>
      <MonitoringStateChip state={monitoring} />
    </div>
  )
}

interface RowHandlers {
  onAction: (row: ExposureItemRow, action: ExposureActionType) => void
  onSeverity?: (row: ExposureItemRow) => void
  canApprove: boolean
}

function useItemColumns(h: RowHandlers): ColumnDef<ExposureItemRow>[] {
  const { t } = useTranslation()
  const labels = useLabels()
  return useMemo<ColumnDef<ExposureItemRow>[]>(
    () => [
      {
        id: 'title',
        header: t('attackSurface.exposures.col.exposure', 'Exposure'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="min-w-0 max-w-[420px] space-y-1">
            <p className="line-clamp-1 font-medium" title={row.original.title}>
              {row.original.title}
            </p>
            <ExposureSummaryLine exposure={row.original} />
            <p className="text-xs text-muted-foreground">
              {labels.category(row.original.display_category ?? 'other')}
            </p>
          </div>
        ),
      },
      {
        id: 'asset_name',
        accessorFn: (r) => r.asset_name ?? '',
        header: t('attackSurface.exposures.col.asset', 'Asset'),
        cell: ({ row }) => (
          <div className="max-w-[260px]">
            <AssetCell
              id={row.original.asset_id}
              name={row.original.asset_name}
              primary={row.original.asset_primary}
              monitoring={row.original.asset_monitoring_state}
            />
          </div>
        ),
      },
      {
        id: 'severity',
        accessorFn: (r) => r.severity,
        header: t('attackSurface.exposures.col.severity', 'Severity'),
        cell: ({ row }) =>
          h.onSeverity ? (
            <button
              type="button"
              className="rounded-sm text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={t(
                'attackSurface.exposures.changeSeverityOf',
                'Change severity of {title}',
                {
                  title: row.original.title,
                }
              )}
              onClick={(e) => {
                e.stopPropagation()
                h.onSeverity?.(row.original)
              }}
            >
              <ExposureSeverityCell exposure={row.original} />
            </button>
          ) : (
            <ExposureSeverityCell exposure={row.original} />
          ),
      },
      {
        id: 'state',
        accessorFn: (r) => r.state,
        header: t('attackSurface.exposures.col.status', 'Status'),
        cell: ({ row }) => (
          <div className="flex flex-wrap items-center gap-1">
            <ExposureStateBadge state={row.original.state} />
            <PendingDispositionBadge exposure={row.original} />
          </div>
        ),
      },
      {
        id: 'first_seen',
        accessorFn: (r) => r.first_seen_at,
        header: t('attackSurface.exposures.col.firstSeen', 'First seen'),
        cell: ({ row }) => <RelativeTime date={row.original.first_seen_at} />,
      },
      {
        id: 'last_seen',
        accessorFn: (r) => r.last_seen_at,
        header: t('attackSurface.exposures.col.lastSeen', 'Last seen'),
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const e = row.original
          const open = e.state === 'active' || e.state === 'in_progress'
          return (
            <div onClick={(ev) => ev.stopPropagation()}>
              <DataTableRowActions
                actions={[
                  ...(open
                    ? [
                        e.state === 'active'
                          ? {
                              label: t('exposures.quick.start', 'Start progress'),
                              icon: PlayCircle,
                              onClick: () => h.onAction(e, 'start_progress'),
                            }
                          : {
                              label: t('exposures.quick.stop', 'Stop progress'),
                              icon: RefreshCw,
                              onClick: () => h.onAction(e, 'reactivate'),
                            },
                        {
                          label: t('exposures.quick.resolve', 'Resolve'),
                          icon: Check,
                          onClick: () => h.onAction(e, 'resolve'),
                        },
                        {
                          label: t('exposures.quick.accept', 'Accept'),
                          icon: AlertTriangle,
                          onClick: () => h.onAction(e, 'accept'),
                          disabled: !h.canApprove,
                          disabledReason: APPROVE_REQUIRED_REASON,
                        },
                        {
                          label: t('exposures.quick.falsePositive', 'False positive'),
                          icon: X,
                          onClick: () => h.onAction(e, 'false_positive'),
                          disabled: !h.canApprove,
                          disabledReason: APPROVE_REQUIRED_REASON,
                        },
                      ]
                    : [
                        {
                          label: t('exposures.quick.reactivate', 'Reactivate'),
                          icon: RefreshCw,
                          onClick: () => h.onAction(e, 'reactivate'),
                        },
                      ]),
                  ...(h.onSeverity
                    ? [
                        {
                          label: t('attackSurface.exposures.changeSeverity', 'Change severity'),
                          icon: Gauge,
                          onClick: () => h.onSeverity?.(e),
                          separatorBefore: true,
                        },
                      ]
                    : []),
                ]}
              />
            </div>
          )
        },
      },
    ],
    [t, labels, h]
  )
}

function useAssetColumns(): ColumnDef<ExposureAssetGroupRow>[] {
  const { t } = useTranslation()
  const labels = useLabels()
  return useMemo<ColumnDef<ExposureAssetGroupRow>[]>(
    () => [
      {
        id: 'asset',
        header: t('attackSurface.exposures.col.asset', 'Asset'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="max-w-[320px]">
            <AssetCell
              id={row.original.asset_id}
              name={row.original.asset_name}
              primary={row.original.asset_primary}
              monitoring={row.original.asset_monitoring_state}
            />
          </div>
        ),
      },
      {
        id: 'top_severity',
        header: t('attackSurface.exposures.col.topSeverity', 'Highest severity'),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.top_severity ? (
            <SeverityBadge severity={row.original.top_severity} />
          ) : (
            <span className="text-muted-foreground">-</span>
          ),
      },
      {
        id: 'total',
        header: t('attackSurface.exposures.col.exposures', 'Exposures'),
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            primary={<span className="font-medium tabular-nums">{row.original.total}</span>}
            secondary={ACTIONABLE_SEVERITIES.filter((s) => (row.original.by_severity[s] ?? 0) > 0)
              .map((s) =>
                t('attackSurface.exposures.severityCount', '{count} {severity}', {
                  count: row.original.by_severity[s] ?? 0,
                  severity: labels.severity(s),
                })
              )
              .join(', ')}
          />
        ),
      },
      {
        id: 'last_seen',
        header: t('attackSurface.exposures.col.lastSeen', 'Last seen'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
    ],
    [t, labels]
  )
}

/** Counts by display category: one toggle button per type, the active ones pressed. */
export function ExposureTypeSummary({
  counts,
  selected,
  onToggle,
  loading,
}: {
  counts: ExposureItemStats['by_category'] | undefined
  selected: readonly ExposureDisplayCategory[]
  onToggle: (c: ExposureDisplayCategory) => void
  loading?: boolean
}) {
  const { t } = useTranslation()
  const labels = useLabels()
  const keys = visibleCategories(counts)
  return (
    <section aria-label={t('attackSurface.exposures.byType', 'By type')} className="space-y-2">
      <h2 className="text-sm font-medium text-muted-foreground">
        {t('attackSurface.exposures.byType', 'By type')}
      </h2>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {keys.map((k) => {
          const n = counts?.[k] ?? 0
          const pressed = selected.includes(k)
          return (
            <button
              key={k}
              type="button"
              aria-pressed={pressed}
              onClick={() => onToggle(k)}
              className={cn(
                'flex min-w-0 items-center justify-between gap-2 rounded-md border px-3 py-2 text-start text-sm transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                pressed && 'border-primary bg-primary/10',
                n === 0 && !pressed && 'text-muted-foreground'
              )}
            >
              <span className="truncate">{labels.category(k)}</span>
              <span className="shrink-0 font-semibold tabular-nums">{loading ? '' : n}</span>
            </button>
          )
        })}
      </div>
    </section>
  )
}

export function EASMExposureItems() {
  const { t } = useTranslation()
  const labels = useLabels()
  const canReadFindings = useHasPermission(Permission.FindingsRead)
  const canReadExposures = useHasPermission(Permission.ExposuresRead)
  const canRead = canReadFindings && canReadExposures
  const canApprove = useCanApproveExposures()
  const canSeverity = useCanChangeExposureSeverity()
  const {
    q,
    searchTerm,
    setSearch,
    sort,
    sorting,
    setSorting,
    filters: urlFilters,
    setFilter,
    pagination,
    setPagination,
  } = useListParams({
    pageSizes: PAGE_SIZES,
    defaultPageSize: 20,
    sortFields: SORT_FIELDS,
    defaultSort: '-severity',
    filters: {
      severity: '',
      state: DEFAULT_STATE_PARAM,
      category: '',
      monitoring: DEFAULT_MONITORING_PARAM,
      primary: '',
      asset: '',
      view: 'list',
    },
  })
  const view: View = urlFilters.view === 'assets' ? 'assets' : 'list'
  const filters: ExposureItemFilters = useMemo(
    () =>
      filtersFromParams({
        q: searchTerm,
        severity: urlFilters.severity,
        state: urlFilters.state,
        category: urlFilters.category,
        monitoring: urlFilters.monitoring,
        primary: urlFilters.primary,
        asset: urlFilters.asset,
      }),
    [searchTerm, urlFilters]
  )
  const page = { page: pagination.pageIndex + 1, perPage: pagination.pageSize }
  const list = useExposureItems(filters, page, sort, view === 'list')
  const groups = useExposureAssetGroups(filters, page, view === 'assets')
  const stats = useExposureItemStats(filters)
  const [exporting, setExporting] = useState(false)
  const [action, setAction] = useState<{
    row: ExposureItemRow
    type: ExposureActionType
  } | null>(null)
  const [severityRow, setSeverityRow] = useState<ExposureItemRow | null>(null)

  const refresh = useCallback(() => {
    void list.mutate()
    void groups.mutate()
    void stats.mutate()
  }, [list, groups, stats])

  const handlers: RowHandlers = useMemo(
    () => ({
      onAction: (row, type) => setAction({ row, type }),
      onSeverity: canSeverity ? (row) => setSeverityRow(row) : undefined,
      canApprove,
    }),
    [canSeverity, canApprove]
  )
  const columns = useItemColumns(handlers)
  const assetColumns = useAssetColumns()

  const severities = filters.severities ?? []
  const categories = filters.categories ?? []
  const setList = (name: 'severity' | 'category', values: string[]) =>
    setFilter(name, values.join(','))

  const exportCsv = async () => {
    setExporting(true)
    try {
      const rows = await fetchAllExposureItems(filters, sort)
      downloadCsv(
        exposureItemsCsv(
          rows,
          [
            t('attackSurface.exposures.col.exposure', 'Exposure'),
            t('attackSurface.exposures.csv.summary', 'Summary'),
            t('attackSurface.exposures.csv.type', 'Type'),
            t('attackSurface.exposures.col.severity', 'Severity'),
            t('attackSurface.exposures.csv.reportedSeverity', 'Reported severity'),
            t('attackSurface.exposures.col.status', 'Status'),
            t('attackSurface.exposures.col.asset', 'Asset'),
            t('attackSurface.exposures.primary', 'Primary asset'),
            t('attackSurface.exposures.csv.monitoring', 'Monitoring state'),
            t('attackSurface.exposures.csv.source', 'Source'),
            t('attackSurface.exposures.col.firstSeen', 'First seen'),
            t('attackSurface.exposures.col.lastSeen', 'Last seen'),
          ],
          {
            category: labels.category,
            severity: labels.severity,
            state: labels.state,
            summary: (r) => exposureSummaryText(r, t) || r.description || '',
          }
        ),
        'exposure-items.csv'
      )
    } catch {
      toast.error(t('attackSurface.exposures.exportFailed', 'Could not export. Try again.'))
    } finally {
      setExporting(false)
    }
  }

  if (!canRead) {
    return (
      <EmptyState
        icon={ShieldX}
        title={t('attackSurface.exposures.noAccess.title', 'Access denied')}
        description={t(
          'attackSurface.exposures.noAccess.description',
          "You don't have permission to view exposures. Ask your administrator for access."
        )}
      />
    )
  }

  const s = stats.data
  const sevItem = (sev: ExposureSeverity, tone?: MetricStripItem['tone']): MetricStripItem => ({
    key: sev,
    label: labels.severity(sev),
    value: s?.by_severity?.[sev] ?? 0,
    tone,
    active: severities.includes(sev),
    onClick: () => setList('severity', toggleValue(severities, sev)),
  })
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('attackSurface.exposures.metric.total', 'Exposures'),
      value: s?.total ?? 0,
      active: severities.length === 0,
      onClick: () => setList('severity', []),
    },
    sevItem('critical', 'danger'),
    sevItem('high', 'danger'),
    sevItem('medium', 'warning'),
    sevItem('low'),
  ]

  const stateOptions = [
    { value: DEFAULT_STATE_PARAM, label: t('attackSurface.exposures.state.open', 'Open') },
    ...ITEM_STATES.map((v) => ({ value: v, label: labels.state(v) })),
  ]
  const monitoringOptions = MONITORING_STATES.map((m) => ({
    value: m,
    label: labels.monitoring(m),
  }))

  const removeLabel = (filter: string) =>
    t('attackSurface.exposures.chip.remove', 'Remove filter {filter}', { filter })
  const chips = [
    ...severities.map((sev) => (
      <RemovableFilterChip
        key={`sev-${sev}`}
        text={labels.severity(sev)}
        onRemove={() => setList('severity', toggleValue(severities, sev))}
        removeLabel={removeLabel(labels.severity(sev))}
      />
    )),
    ...categories.map((c) => (
      <RemovableFilterChip
        key={`cat-${c}`}
        text={labels.category(c)}
        onRemove={() => setList('category', toggleValue(categories, c))}
        removeLabel={removeLabel(labels.category(c))}
      />
    )),
    ...(filters.primaryOnly
      ? [
          <RemovableFilterChip
            key="primary"
            text={t('attackSurface.exposures.chip.primary', 'Primary assets only')}
            onRemove={() => setFilter('primary', '')}
            removeLabel={removeLabel(t('attackSurface.exposures.primary', 'Primary asset'))}
          />,
        ]
      : []),
    ...(filters.assetId
      ? [
          <RemovableFilterChip
            key="asset"
            text={t('attackSurface.exposures.chip.asset', 'One asset')}
            onRemove={() => setFilter('asset', '')}
            removeLabel={removeLabel(t('attackSurface.exposures.col.asset', 'Asset'))}
          />,
        ]
      : []),
  ]
  const active = view === 'list' ? list : groups
  const toolbarStart = (
    <>
      <FilterSelect<string>
        label={t('attackSurface.exposures.filter.status', 'Status')}
        value={urlFilters.state}
        allValue={ANY}
        options={stateOptions}
        onChange={(v) => setFilter('state', v)}
      />
      <FilterSelect<string>
        label={t('attackSurface.exposures.filter.monitoring', 'Asset monitoring')}
        value={urlFilters.monitoring}
        allValue={ANY}
        options={monitoringOptions}
        onChange={(v) => setFilter('monitoring', v)}
      />
      <Button
        variant={filters.primaryOnly ? 'secondary' : 'outline'}
        size="sm"
        aria-pressed={!!filters.primaryOnly}
        onClick={() => setFilter('primary', filters.primaryOnly ? '' : 'true')}
      >
        <Star className="me-2 h-4 w-4" aria-hidden />
        {t('attackSurface.exposures.filter.primary', 'Primary assets')}
      </Button>
    </>
  )
  const toolbarEnd = (
    <>
      <ViewSwitcher<View>
        value={view}
        onChange={(v) => setFilter('view', v)}
        options={[
          {
            value: 'list',
            label: t('attackSurface.exposures.view.list', 'Exposures'),
            icon: LayoutList,
          },
          {
            value: 'assets',
            label: t('attackSurface.exposures.view.assets', 'Group by asset'),
            icon: Server,
          },
        ]}
      />
      <Button variant="outline" size="sm" onClick={exportCsv} disabled={exporting}>
        <Download className="me-2 h-4 w-4" aria-hidden />
        {t('attackSurface.exposures.export', 'Export CSV')}
      </Button>
    </>
  )
  const toolbarBelow =
    chips.length > 0 ? (
      <FilterChipsRow
        label={t('attackSurface.exposures.activeFilters', 'Active filters')}
        chips={chips}
        end={
          view === 'list'
            ? t('attackSurface.exposures.count', '{count} exposures', { count: list.total })
            : t('attackSurface.exposures.assetCount', '{count} assets', { count: groups.total })
        }
      />
    ) : undefined
  const errorState =
    active.error && !active.isLoading ? (
      <ErrorState
        title={t('attackSurface.exposures.error', 'exposures')}
        error={active.error}
        onRetry={() => active.mutate()}
      />
    ) : undefined
  const common = {
    showSearch: false,
    search: {
      value: q,
      onChange: setSearch,
      placeholder: t('attackSurface.exposures.search', 'Search exposure or asset…'),
    },
    showColumnToggle: false,
    toolbarStart,
    toolbarEnd,
    toolbarBelow,
    errorState,
    manualPagination: true,
    pagination,
    onPaginationChange: setPagination,
    pageSizeOptions: PAGE_SIZES,
    emptyMessage: t('attackSurface.exposures.empty.title', 'No exposures match'),
    emptyDescription: t(
      'attackSurface.exposures.empty.description',
      'Exposures appear here once scans of your external assets find open ports, weak TLS, takeover risks and similar issues. Clear filters to see resolved ones or assets that are not monitored.'
    ),
  } as const

  return (
    <>
      <MetricStrip loading={stats.isLoading && !s} items={metrics} />
      <ExposureTypeSummary
        counts={s?.by_category}
        selected={categories}
        loading={stats.isLoading && !s}
        onToggle={(c) => setList('category', toggleValue(categories, c))}
      />
      {view === 'list' ? (
        <DataTable
          {...common}
          columns={columns}
          data={list.rows}
          getRowId={(r) => r.id}
          sorting={sorting}
          onSortingChange={setSorting}
          isLoading={list.isLoading && list.rows.length === 0}
          rowCount={list.total}
        />
      ) : (
        <DataTable
          {...common}
          columns={assetColumns}
          data={groups.rows}
          getRowId={(r) => r.asset_id}
          onRowClick={(r) => {
            setFilter('asset', r.asset_id)
            setFilter('view', 'list')
          }}
          isLoading={groups.isLoading && groups.rows.length === 0}
          rowCount={groups.total}
        />
      )}
      <ExposureActionDialog
        exposure={action?.row ?? null}
        actionType={action?.type ?? null}
        open={action !== null}
        onOpenChange={(open) => !open && setAction(null)}
        onSuccess={refresh}
      />
      <ExposureSeverityDialog
        exposure={severityRow}
        open={severityRow !== null}
        onOpenChange={(open) => !open && setSeverityRow(null)}
        onSuccess={refresh}
      />
    </>
  )
}
