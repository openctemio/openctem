'use client'

import { useTranslation } from '@/context/i18n-provider'

import { useState, useCallback, useEffect, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent } from '@/components/ui/tabs'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Main } from '@/components/layout'
import {
  DataTable,
  ErrorState,
  EmptyState,
  GatedButton,
  MetricStrip,
  PageHeader,
  PageStack,
  ViewSwitcher,
  SeverityBadge,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
} from '@/features/shared'
import type { MetricStripItem } from '@/features/shared'
import { usePhoneSelectMode, type DataTableBulk } from '@/features/shared/components/data-table'
import {
  FacetOption,
  FacetPanel,
  FacetSection,
} from '@/features/shared/components/facet-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { FilterSheet } from '@/features/shared/components/filter-sheet'
import {
  ListCount,
  ListTitleRow,
  ListViewChanged,
} from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { ExposurePhoneCard } from '@/features/exposures/components/exposure-phone-card'
import { accessStateOf } from '@/lib/api/access-state'
import { useIsMobile } from '@/hooks/use-mobile'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useSearchQuery } from '@/hooks/use-search-query'
import { cn } from '@/lib/utils'
import {
  RefreshCw,
  Download,
  Shield,
  ShieldCheck,
  ShieldX,
  Clock,
  Activity,
  ArrowRightLeft,
  BarChart3,
  MoreHorizontal,
  Radar,
  ChartColumn,
  List,
} from 'lucide-react'
import { toast } from 'sonner'
import { formatRelative } from '@/lib/format-date'
import { EntityActivity } from '@/features/activity/components/entity-activity'
import type { ActivityItem } from '@/features/activity/types'
import { useTenant } from '@/context/tenant-provider'
import { exportToCsv, type ExportFieldConfig } from '@/hooks/use-csv-export'
import { fetchAllPages } from '@/lib/api/fetch-all-pages'
import { exposureEndpoints } from '@/lib/api/endpoints'

import {
  useExposures,
  useExposureStats,
  useExposureHistory,
  resolveExposure,
  acceptExposure,
  markExposureFalsePositive,
} from '@/features/exposures/hooks'
import {
  ExposureStateBadge,
  ExposureSeverityBreakdown,
  ExposureStateBreakdown,
  getExposureColumns,
  ExposureRowMenu,
  ExposureActionDialog,
  ExposureSeverityDialog,
  useCanChangeExposureSeverity,
  type ExposureActionType,
  useExposureBulkActions,
  ExposureSecurityContext,
  ExposuresTabs,
  APPROVE_REQUIRED_REASON,
  useCanApproveExposures,
  PendingDispositionBadge,
  PendingDispositionPanel,
  ExposureDetailsView,
} from '@/features/exposures/components'
import { runPool, summarizeBulk } from '@/features/exposures/lib/bulk'
import {
  EXPOSURE_DISPLAY_CATEGORIES,
  isExposureDisplayCategory,
  type ExposureDisplayCategory,
  type ExposureEvent,
  type ExposureListFilters,
  type ExposureSeverity,
  type ExposureState,
} from '@/lib/api/exposure-types'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { SEVERITY_LABELS as SHARED_SEVERITY_LABELS } from '@/lib/severity'

type ActionType = ExposureActionType

// Lifecycle view — the primary filter.
type StateTab = 'needs_attention' | 'resolved' | 'all'

const STATE_VIEWS: { value: StateTab; labelKey: string; fallback: string }[] = [
  {
    value: 'needs_attention',
    labelKey: 'exposures.view.needsAttention',
    fallback: 'Needs attention',
  },
  { value: 'resolved', labelKey: 'exposures.metrics.closed', fallback: 'Closed' },
  { value: 'all', labelKey: 'exposures.view.allStates', fallback: 'All states' },
]

const SEVERITIES: ExposureSeverity[] = [...SEVERITY_LEVELS]
const SEVERITY_LABELS: Record<ExposureSeverity, string> = SHARED_SEVERITY_LABELS

// CSV columns for the Export action: every exposure matching the filters.
type Translate = (key: string, fallback: string, params?: Record<string, string | number>) => string

function exposureExportFields(t: Translate): ExportFieldConfig<ExposureEvent>[] {
  return [
    { header: t('exposures.export.col.id', 'ID'), accessor: (e) => e.id },
    { header: t('exposures.export.col.title', 'Title'), accessor: (e) => e.title },
    {
      header: t('exposures.export.col.eventType', 'Event type'),
      accessor: (e) => e.event_type.replace(/_/g, ' '),
    },
    {
      header: t('exposures.export.col.category', 'Category'),
      accessor: (e) => e.display_category ?? '',
    },
    {
      header: t('exposures.export.col.summary', 'Summary'),
      accessor: (e) => e.summary?.text ?? '',
    },
    { header: t('exposures.export.col.severity', 'Severity'), accessor: (e) => e.severity },
    { header: t('exposures.export.col.state', 'State'), accessor: (e) => e.state },
    { header: t('exposures.export.col.source', 'Source'), accessor: (e) => e.source },
    { header: t('exposures.export.col.firstSeen', 'First seen'), accessor: (e) => e.first_seen_at },
    { header: t('exposures.export.col.lastSeen', 'Last seen'), accessor: (e) => e.last_seen_at },
    {
      header: t('exposures.export.col.resolvedAt', 'Resolved at'),
      accessor: (e) => e.resolved_at ?? '',
    },
  ]
}

// Map the lifecycle view to API state filters.
function getStatesForTab(tab: StateTab): ExposureState[] | undefined {
  switch (tab) {
    case 'needs_attention':
      return ['active', 'in_progress']
    case 'resolved':
      return ['resolved', 'accepted', 'false_positive']
    default:
      return undefined // No filter = all states
  }
}

export default function ExposuresPage() {
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null

  // The whole view lives in the URL — tab, lifecycle view, severity, search,
  // page and page size — so a filtered view is shareable and survives reload.
  const [tabParam, setTabParam] = useUrlFilter('tab', 'list')
  const tab = tabParam === 'analytics' ? 'analytics' : 'list'
  const [stateParam, setStateParam] = useUrlFilter('state', 'needs_attention')
  const activeView: StateTab = STATE_VIEWS.some((v) => v.value === stateParam)
    ? (stateParam as StateTab)
    : 'needs_attention'
  const [searchQuery, setSearchQuery] = useUrlFilter('q', '')
  const debouncedSearch = useSearchQuery(searchQuery).term
  const [severityParam, setSeverityParam] = useUrlFilterList('severity')
  const selectedSeverities = useMemo(
    () =>
      severityParam.filter((s): s is ExposureSeverity =>
        SEVERITIES.includes(s as ExposureSeverity)
      ),
    [severityParam]
  )
  const [categoryParam, setCategoryParam] = useUrlFilterList('category')
  const selectedCategories = useMemo(
    () => categoryParam.filter((c): c is ExposureDisplayCategory => isExposureDisplayCategory(c)),
    [categoryParam]
  )
  const list = useListParams()
  const { pagination, setPagination, setPage } = list
  const resetPage = useCallback(() => setPage(1), [setPage])

  // Selection is owned by the DataTable; we mirror it for the bulk-action bar
  // and bump the epoch to clear the table's own checkboxes.
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [selectedNames, setSelectedNames] = useState<string[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const clearSelection = useCallback(() => {
    setSelectedIds([])
    setSelectionEpoch((e) => e + 1)
  }, [])

  // Action dialog state
  const { t } = useTranslation()
  const [selectedExposure, setSelectedExposure] = useState<ExposureEvent | null>(null)
  const [actionType, setActionType] = useState<ActionType | null>(null)
  const [severityExposure, setSeverityExposure] = useState<ExposureEvent | null>(null)

  // Detail sheet state
  const [detailExposure, setDetailExposure] = useState<ExposureEvent | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)

  const apiFilters: ExposureListFilters = useMemo(
    () => ({
      page: pagination.pageIndex + 1,
      per_page: pagination.pageSize,
      search: debouncedSearch || undefined,
      severities: selectedSeverities.length > 0 ? selectedSeverities : undefined,
      categories: selectedCategories.length > 0 ? selectedCategories : undefined,
      states: getStatesForTab(activeView),
    }),
    [pagination, debouncedSearch, selectedSeverities, selectedCategories, activeView]
  )

  const {
    exposures,
    total,
    isLoading: exposuresLoading,
    error: exposuresError,
    mutate: refreshExposures,
    response: exposuresResponse,
    canRead: canReadExposures,
  } = useExposures(tenantId, apiFilters)
  // When the rows on screen were read: the table says so once they are old.
  const [readAt, setReadAt] = useState<Date | undefined>(undefined)
  useEffect(() => {
    if (exposuresResponse) setReadAt(new Date())
  }, [exposuresResponse])

  const {
    stats,
    isLoading: statsLoading,
    error: statsError,
    mutate: refreshStats,
  } = useExposureStats(tenantId)

  const isLoading = exposuresLoading || statsLoading

  // Export EVERY exposure matching the current filters (all pages), not just
  // the page rendered in the table.
  const [isExporting, setIsExporting] = useState(false)
  const handleExport = useCallback(async () => {
    if (isExporting) return
    setIsExporting(true)
    try {
      const all = await fetchAllPages<ExposureEvent>(
        (p, per_page) => exposureEndpoints.list({ ...apiFilters, page: p, per_page }),
        {
          onTruncated: (loaded) =>
            toast.warning(
              t(
                'exposures.export.truncated',
                'Export limited to the first {count} exposures. Refine the filters to export the rest.',
                { count: loaded.toLocaleString() }
              )
            ),
        }
      )
      exportToCsv(all, exposureExportFields(t), 'exposures')
    } catch {
      toast.error(t('exposures.export.failed', 'Could not export the exposures'))
    } finally {
      setIsExporting(false)
    }
  }, [isExporting, apiFilters, t])

  const handleRefresh = useCallback(() => {
    refreshExposures()
    refreshStats()
  }, [refreshExposures, refreshStats])

  const handleSearch = useCallback(
    (value: string) => {
      setSearchQuery(value)
      resetPage()
    },
    [setSearchQuery, resetPage]
  )

  const toggleSeverity = useCallback(
    (severity: ExposureSeverity) => {
      setSeverityParam((prev) =>
        prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
      )
      resetPage()
    },
    [setSeverityParam, resetPage]
  )

  const toggleCategory = useCallback(
    (category: ExposureDisplayCategory) => {
      setCategoryParam((prev) =>
        prev.includes(category) ? prev.filter((c) => c !== category) : [...prev, category]
      )
      resetPage()
    },
    [setCategoryParam, resetPage]
  )

  const setView = useCallback(
    (view: StateTab) => {
      setStateParam(view)
      resetPage()
      clearSelection()
    },
    [setStateParam, resetPage, clearSelection]
  )

  const handleAction = useCallback((exposure: ExposureEvent, action: ActionType) => {
    setSelectedExposure(exposure)
    setActionType(action)
  }, [])

  const handleActionSuccess = useCallback(() => {
    handleRefresh()
    clearSelection()
    // Close detail sheet after successful action
    setDetailExposure(null)
  }, [handleRefresh, clearSelection])

  // Bulk handlers apply the per-exposure state-change API to every selected id.
  // They run through a pool of 5, never reject on a partial failure and return
  // the outcome; ExposureBulkActions owns the toasts and clears selection. The
  // list refreshes after every run so rows that did change are not left stale.
  const handleBulkResolve = useCallback(
    async (ids: string[]) => {
      const results = await runPool(ids, (id) => resolveExposure(id))
      handleRefresh()
      return summarizeBulk(results)
    },
    [handleRefresh]
  )

  const handleBulkAccept = useCallback(
    async (ids: string[], reason: string) => {
      const results = await runPool(ids, (id) => acceptExposure(id, { reason }))
      handleRefresh()
      return summarizeBulk(results, (r) => Boolean(r?.pending_disposition))
    },
    [handleRefresh]
  )

  const handleBulkFalsePositive = useCallback(
    async (ids: string[], reason: string) => {
      const results = await runPool(ids, (id) => markExposureFalsePositive(id, { reason }))
      handleRefresh()
      return summarizeBulk(results, (r) => Boolean(r?.pending_disposition))
    },
    [handleRefresh]
  )

  /** The chips: severity and category. */
  const clearChipFilters = useCallback(() => {
    setSeverityParam([])
    setCategoryParam([])
    resetPage()
  }, [setSeverityParam, setCategoryParam, resetPage])
  /** Back to the view as it is named: no search text, no chip. */
  const backToView = useCallback(() => {
    setSearchQuery('')
    clearChipFilters()
  }, [setSearchQuery, clearChipFilters])
  /** Everything that narrows the list, the lifecycle view included. */
  const clearFilters = useCallback(() => {
    backToView()
    setStateParam('needs_attention')
  }, [backToView, setStateParam])

  const chipCount = selectedSeverities.length + selectedCategories.length
  const viewChanged = !!searchQuery || chipCount > 0
  const hasActiveFilters = viewChanged || activeView !== 'needs_attention'

  // Accept risk / false positive need findings:approve (api#675).
  const canApprove = useCanApproveExposures()
  const canChangeSeverity = useCanChangeExposureSeverity()
  const rowHandlers = useMemo(
    () => ({
      onResolve: (e: ExposureEvent) => handleAction(e, 'resolve'),
      onAccept: (e: ExposureEvent) => handleAction(e, 'accept'),
      onMarkFalsePositive: (e: ExposureEvent) => handleAction(e, 'false_positive'),
      onReactivate: (e: ExposureEvent) => handleAction(e, 'reactivate'),
      onStartProgress: (e: ExposureEvent) => handleAction(e, 'start_progress'),
      onChangeSeverity: canChangeSeverity ? setSeverityExposure : undefined,
      onViewDetails: setDetailExposure,
      canApprove,
    }),
    [handleAction, canApprove, canChangeSeverity]
  )
  const columns = useMemo(() => getExposureColumns(rowHandlers, t), [rowHandlers, t])

  // Categories the platform produces, or that have exposures; the rest stay
  // hidden until they do.
  const categoryOptions = EXPOSURE_DISPLAY_CATEGORIES.filter(
    (c) =>
      c.produced || (stats?.by_category?.[c.key] ?? 0) > 0 || selectedCategories.includes(c.key)
  )

  // Headline numbers double as the lifecycle quick filter.
  const activeCount = stats?.active_count ?? 0
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('exposures.metrics.total', 'Total exposures'),
      value: stats?.total ?? 0,
      onClick: () => setView('all'),
      active: activeView === 'all',
    },
    {
      key: 'active',
      label: t('exposures.view.needsAttention', 'Needs attention'),
      value: activeCount,
      tone: 'danger',
      onClick: () => setView('needs_attention'),
      active: activeView === 'needs_attention',
    },
    {
      key: 'resolved',
      label: t('exposures.metrics.closed', 'Closed'),
      // Same three states the Closed view lists, so the tile equals its list.
      value:
        (stats?.by_state?.resolved ?? 0) +
        (stats?.by_state?.accepted ?? 0) +
        (stats?.by_state?.false_positive ?? 0),
      onClick: () => setView('resolved'),
      active: activeView === 'resolved',
    },
  ]

  const viewLabel = (v: StateTab) => {
    const view = STATE_VIEWS.find((x) => x.value === v)
    return view ? t(view.labelKey, view.fallback) : v
  }
  const viewTitle = viewLabel(activeView)
  const severityLabel = (sev: ExposureSeverity) => t(`severity.${sev}`, SEVERITY_LABELS[sev])
  const categoryLabel = (key: ExposureDisplayCategory) =>
    t(
      `exposures.category.${key}`,
      EXPOSURE_DISPLAY_CATEGORIES.find((c) => c.key === key)?.label ?? key
    )

  // The active filters as chips ("Field: values"), each removable on its own.
  // The lifecycle view is the toolbar's own select, so it is not a chip.
  const chipList: { key: string; text: string; clear: () => void }[] = [
    ...(selectedSeverities.length > 0
      ? [
          {
            key: 'severity',
            text: t('exposures.filter.chip', '{field}: {value}', {
              field: t('exposures.filter.severity', 'Severity'),
              value: selectedSeverities.map(severityLabel).join(', '),
            }),
            clear: () => {
              setSeverityParam([])
              resetPage()
            },
          },
        ]
      : []),
    ...(selectedCategories.length > 0
      ? [
          {
            key: 'category',
            text: t('exposures.filter.chip', '{field}: {value}', {
              field: t('exposures.category.filter', 'Category'),
              value: selectedCategories.map(categoryLabel).join(', '),
            }),
            clear: () => {
              setCategoryParam([])
              resetPage()
            },
          },
        ]
      : []),
  ]
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="exposure-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('exposures.filter.remove', 'Remove filter {filter}', { filter: c.text })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearChipFilters : undefined}
      />
    ) : undefined

  // `withState`: the phone sheet also holds the lifecycle view (the toolbar's
  // select), so every filter is in one place there.
  const facetPanel = (withState: boolean) => (
    <FacetPanel
      activeCount={chipCount + (withState && activeView !== 'needs_attention' ? 1 : 0)}
      onClearAll={withState ? clearFilters : clearChipFilters}
    >
      {withState && (
        <FacetSection
          title={t('exposures.filter.state', 'State')}
          selectedCount={activeView !== 'needs_attention' ? 1 : 0}
        >
          {STATE_VIEWS.map((v) => (
            <FacetOption
              key={v.value}
              label={t(v.labelKey, v.fallback)}
              checked={activeView === v.value}
              onCheckedChange={(on) => setView(on ? v.value : 'needs_attention')}
            />
          ))}
        </FacetSection>
      )}
      <FacetSection
        title={t('exposures.filter.severity', 'Severity')}
        selectedCount={selectedSeverities.length}
      >
        {SEVERITIES.map((severity) => (
          <FacetOption
            key={severity}
            label={severityLabel(severity)}
            checked={selectedSeverities.includes(severity)}
            onCheckedChange={() => toggleSeverity(severity)}
            adornment={
              <span className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT_COLORS[severity])} />
            }
          />
        ))}
      </FacetSection>
      <FacetSection
        title={t('exposures.category.filter', 'Category')}
        selectedCount={selectedCategories.length}
      >
        {categoryOptions.map((c) => (
          <FacetOption
            key={c.key}
            label={t('exposures.category.withCount', '{name} ({count})', {
              name: categoryLabel(c.key),
              count: (stats?.by_category?.[c.key] ?? 0).toLocaleString(),
            })}
            checked={selectedCategories.includes(c.key)}
            onCheckedChange={() => toggleCategory(c.key)}
          />
        ))}
      </FacetSection>
    </FacetPanel>
  )

  // The toolbar row after the search: Add filter (it never changes size),
  // then the lifecycle view in a box as wide as its longest value.
  const toolbarStart = (
    <>
      <AddFilterPanel>{facetPanel(false)}</AddFilterPanel>
      <FilterSelect<StateTab>
        label={t('exposures.filter.state', 'State')}
        value={activeView}
        clearable={false}
        foldLabel
        // On a phone the state lives in the Filters sheet: the toolbar's
        // second line holds the chips, which must not push a select along.
        className="max-md:hidden"
        options={STATE_VIEWS.map((v) => ({ value: v.value, label: t(v.labelKey, v.fallback) }))}
        onChange={(v) => setView(v || 'needs_attention')}
      />
    </>
  )

  // The bulk bar: Resolve and Accept risk, False positive under More, with
  // the same confirmations. The table draws the bar and the checkbox column.
  const bulkParts = useExposureBulkActions({
    selectedIds,
    selectedNames,
    onClearSelection: clearSelection,
    onBulkResolve: handleBulkResolve,
    onBulkAccept: handleBulkAccept,
    onBulkFalsePositive: handleBulkFalsePositive,
  })
  const exposuresBulk: DataTableBulk<ExposureEvent> = {
    rowLabel: (e) => e.title,
    checkboxLabel: (e) => t('exposures.table.selectRow', 'Select {title}', { title: e.title }),
    actions: bulkParts.actions,
    more: bulkParts.more,
    noun: (count) => t('exposures.bulk.noun', 'exposures selected', { count }),
    onSelectionChange: (selection) => {
      const rows = selection?.kind === 'ids' ? selection.rows : []
      setSelectedIds(rows.map((e) => e.id))
      setSelectedNames(rows.map((e) => e.title))
    },
  }
  // Phone cards have no header checkbox: "Select" starts the title row's More.
  const isPhone = useIsMobile()
  const phoneSelect = usePhoneSelectMode(isPhone)

  const refreshLabel = t('exposures.toolbar.refresh', 'Refresh')
  const exportOff = isExporting || exposuresLoading || total === 0
  const exportLabel = isExporting
    ? t('exposures.toolbar.exporting', 'Exporting…')
    : t('exposures.toolbar.export', 'Export')
  // Under 42rem of row width (and on a phone) the row's actions fold into
  // More: Select first, then Reset on a changed view, then Export.
  const moreItems: ActionMenuEntry[] = [
    ...(phoneSelect.item ? [phoneSelect.item] : []),
    ...(viewChanged
      ? [{ id: 'view-reset', label: t('common.listView.reset', 'Reset'), onSelect: backToView }]
      : []),
    {
      id: 'export',
      label: t('exposures.toolbar.export', 'Export'),
      section: 'export',
      disabledReason: isExporting
        ? t('exposures.toolbar.exporting', 'Exporting…')
        : total === 0
          ? t('exposures.toolbar.exportEmpty', 'There is nothing to export.')
          : undefined,
      onSelect: () => void handleExport(),
    },
  ]
  const titleRow = (
    <ListTitleRow
      data-testid="exposures-title-row"
      className="@container/actions"
      title={viewTitle}
      count={
        <ListCount
          total={total}
          loading={exposuresLoading && exposures.length === 0}
          label={t(
            'exposures.list.total',
            '{count, plural, one {# exposure} other {# exposures}}',
            {
              count: total,
            }
          )}
        />
      }
      start={
        <ListViewChanged
          changed={viewChanged}
          // On a row under 42rem Reset is in the row's More.
          actionsClassName="hidden @2xl/actions:flex"
          onReset={backToView}
        />
      }
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            onClick={handleRefresh}
            disabled={isLoading}
            aria-label={refreshLabel}
          >
            <RefreshCw
              className={cn('h-4 w-4', isLoading && 'animate-spin motion-reduce:animate-none')}
              aria-hidden
            />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{refreshLabel}</TooltipContent>
      </Tooltip>
      <div className="hidden @2xl/actions:block">
        <Button variant="outline" size="sm" onClick={handleExport} disabled={exportOff}>
          <Download aria-hidden />
          {exportLabel}
        </Button>
      </div>
      <div className="@2xl/actions:hidden">
        <ActionMenu
          title={viewTitle}
          label={t('common.actionMenu.label', 'Actions for {name}', { name: viewTitle })}
          items={moreItems}
          trigger={
            <Button
              variant="outline"
              size="icon"
              aria-label={t('common.actionMenu.more', 'More actions')}
            >
              <MoreHorizontal className="h-4 w-4" aria-hidden />
            </Button>
          }
        />
      </div>
    </ListTitleRow>
  )

  // A failed read with rows on screen keeps the rows (the table says how old
  // they are and offers a refresh); without rows the error takes their place.
  const noAccess = canReadExposures === false || accessStateOf(exposuresError) === 'no_access'
  const readError = exposuresError && exposures.length === 0 ? exposuresError : undefined
  const firstRun = !exposuresLoading && !exposuresError && total === 0 && !hasActiveFilters

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('exposures.page.title', 'Exposures')}
          // On a phone the list comes first: the description is read out but
          // not drawn, and the tiles follow the list.
          description={
            <span className="max-md:sr-only">
              {t(
                'exposures.page.description',
                'Changes to your attack surface that need a decision. Resolve, accept or dismiss them.'
              )}
            </span>
          }
          viewSwitcher={
            // List and analytics are two views of the same events: a view
            // switch, not a second row of tabs (research/249 R21).
            <ViewSwitcher
              options={[
                { value: 'list', label: t('exposures.view.list', 'List view'), icon: List },
                {
                  value: 'analytics',
                  label: t('exposures.view.analytics', 'Analytics view'),
                  icon: ChartColumn,
                },
              ]}
              value={tab}
              onChange={(v) => setTabParam(v === 'analytics' ? 'analytics' : '')}
            />
          }
        />

        <ExposuresTabs />

        <Tabs value={tab} onValueChange={setTabParam}>
          <TabsContent value="list">
            <PageStack>
              {statsError ? (
                <ErrorState
                  title={t('exposures.stats.errorTitle', 'exposure statistics')}
                  error={statsError}
                  onRetry={() => refreshStats()}
                />
              ) : (
                <MetricStrip loading={statsLoading} items={metrics} className="max-md:order-last" />
              )}

              {/* On a phone the list comes first: the tiles follow it. */}
              {titleRow}
              {noAccess ? (
                <NoAccessState title={t('exposures.list.subject', 'the exposures list')} />
              ) : (
                <DataTable
                  columns={columns}
                  data={exposures}
                  error={readError}
                  onRetry={handleRefresh}
                  errorTitle={t('exposures.list.subject', 'the exposures list')}
                  isLoading={exposuresLoading && exposures.length === 0}
                  // A first run has nothing to search, filter or arrange.
                  showToolbar={!firstRun}
                  staleAt={readAt}
                  refreshFailed={!!exposuresError && exposures.length > 0}
                  onRefresh={handleRefresh}
                  showSearch={false}
                  search={{
                    value: searchQuery,
                    onChange: handleSearch,
                    placeholder: t('exposures.search.placeholder', 'Search exposures…'),
                    label: t('exposures.search.label', 'Search exposures'),
                  }}
                  // One filter entry per width: Add filter from 768, this button
                  // (joined to the search field) on a phone, where it opens the sheet.
                  filterToggle={{
                    open: false,
                    onToggle: () => setFilterSheetOpen(true),
                    onOpenSheet: () => setFilterSheetOpen(true),
                    activeCount: chipCount + (activeView !== 'needs_attention' ? 1 : 0),
                    controlsId: 'exposure-filters',
                    label: t('exposures.filter.sheetTitle', 'Exposure filters'),
                    sheetOnly: true,
                  }}
                  toolbarStart={toolbarStart}
                  toolbarBelow={chipsRow}
                  getRowId={(e) => e.id}
                  manualPagination
                  rowCount={total}
                  pagination={pagination}
                  onPaginationChange={setPagination}
                  paginationNoun={t('exposures.list.noun', 'exposures')}
                  onRowClick={setDetailExposure}
                  bulk={exposuresBulk}
                  selectMode={phoneSelect.selectMode}
                  resetSelectionKey={selectionEpoch}
                  showSelectionCount={false}
                  mobileRow={(exposure, selection) => (
                    <ExposurePhoneCard
                      exposure={exposure}
                      selection={selection}
                      onOpen={setDetailExposure}
                      actions={<ExposureRowMenu exposure={exposure} handlers={rowHandlers} />}
                    />
                  )}
                  isFiltered={hasActiveFilters}
                  onClearFilters={clearFilters}
                  emptyState={{
                    nothingYet: (
                      <EmptyState
                        icon={Radar}
                        title={t('exposures.list.empty', 'No exposures')}
                        description={t(
                          'exposures.list.emptyHint',
                          'Your attack surface has no open exposure events.'
                        )}
                      />
                    ),
                    noMatch: {
                      title: t('exposures.list.emptyFiltered', 'No exposures match these filters'),
                      hint: t(
                        'exposures.list.emptyFilteredHint',
                        'Try removing a filter or clearing them all.'
                      ),
                    },
                  }}
                />
              )}
              {bulkParts.dialogs}
              <FilterSheet
                open={filterSheetOpen}
                onOpenChange={setFilterSheetOpen}
                title={t('exposures.filter.sheetTitle', 'Exposure filters')}
              >
                {facetPanel(true)}
              </FilterSheet>
            </PageStack>
          </TabsContent>

          <TabsContent value="analytics">
            <PageStack>
              {statsError ? (
                <ErrorState
                  title={t('exposures.stats.errorTitle', 'exposure statistics')}
                  error={statsError}
                  onRetry={() => refreshStats()}
                />
              ) : statsLoading ? (
                <div className="grid gap-4 md:grid-cols-2">
                  <Skeleton className="h-64 w-full rounded-xl" />
                  <Skeleton className="h-64 w-full rounded-xl" />
                </div>
              ) : (
                <>
                  <div className="grid gap-4 md:grid-cols-2">
                    <ExposureSeverityBreakdown bySeverity={stats.by_severity} />
                    <ExposureStateBreakdown byState={stats.by_state} />
                  </div>
                  <Card>
                    <CardHeader>
                      <CardTitle>{t('exposures.eventTypes.title', 'By event type')}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <EventTypeDistribution byEventType={stats.by_event_type} />
                    </CardContent>
                  </Card>
                </>
              )}
            </PageStack>
          </TabsContent>
        </Tabs>
      </PageStack>

      <ExposureSeverityDialog
        exposure={severityExposure}
        open={severityExposure !== null}
        onOpenChange={(open) => {
          if (!open) setSeverityExposure(null)
        }}
        onSuccess={handleActionSuccess}
      />

      {/* Action Dialog */}
      <ExposureActionDialog
        exposure={selectedExposure}
        actionType={actionType}
        open={actionType !== null}
        onOpenChange={(open) => {
          if (!open) {
            setActionType(null)
            setSelectedExposure(null)
          }
        }}
        onSuccess={handleActionSuccess}
      />

      {/* Detail Sheet */}
      <ExposureDetailSheet
        exposure={detailExposure}
        open={detailExposure !== null}
        onOpenChange={(open) => !open && setDetailExposure(null)}
        onAction={(action) => {
          if (detailExposure) {
            handleAction(detailExposure, action)
          }
        }}
        onChanged={() => {
          setDetailExposure(null)
          handleRefresh()
        }}
      />
    </Main>
  )
}

interface EventTypeDistributionProps {
  byEventType: Record<string, number>
}

function EventTypeDistribution({ byEventType }: EventTypeDistributionProps) {
  const { t } = useTranslation()
  const entries = Object.entries(byEventType || {}).sort((a, b) => b[1] - a[1])
  if (entries.length === 0) {
    return (
      <EmptyState
        card={false}
        icon={BarChart3}
        title={t('exposures.eventTypes.empty', 'No exposure data yet')}
      />
    )
  }
  const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1

  return (
    <div className="space-y-2">
      {entries.slice(0, 10).map(([type, count]) => {
        const percentage = ((count / total) * 100).toFixed(1)
        const label = type.replace(/_/g, ' ')
        return (
          <div key={type} className="flex items-center gap-3">
            <div className="w-40 truncate text-sm">
              {label.charAt(0).toUpperCase() + label.slice(1)}
            </div>
            <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${percentage}%` }}
              />
            </div>
            <div className="w-24 text-end text-sm text-muted-foreground tabular-nums">
              {count.toLocaleString()} ({percentage}%)
            </div>
          </div>
        )
      })}
    </div>
  )
}

interface ExposureDetailSheetProps {
  exposure: ExposureEvent | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onAction: (action: ActionType) => void
  onChanged?: () => void
}

function ExposureDetailSheet({
  exposure,
  open,
  onOpenChange,
  onAction,
  onChanged,
}: ExposureDetailSheetProps) {
  const { t } = useTranslation()
  const canApprove = useCanApproveExposures()
  const { currentTenant } = useTenant()
  const {
    history,
    isLoading: historyLoading,
    error: historyError,
    mutate: retryHistory,
  } = useExposureHistory(currentTenant?.id || null, exposure?.id || null)

  if (!exposure) return null

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      header={
        <DetailHeader
          title={exposure.title}
          badges={
            <>
              <SeverityBadge severity={exposure.severity} />
              <ExposureStateBadge state={exposure.state} />
              <PendingDispositionBadge exposure={exposure} />
            </>
          }
          meta={[
            t('exposures.detail.meta', '{type} from {source}', {
              type: exposure.event_type.replace(/_/g, ' '),
              source: exposure.source,
            }),
          ]}
          actions={
            exposure.state === 'active' ? (
              <>
                <Button size="sm" onClick={() => onAction('resolve')}>
                  <ShieldCheck className="h-4 w-4" />
                  {t('exposures.quick.resolve', 'Resolve')}
                </Button>
                <GatedButton
                  size="sm"
                  variant="outline"
                  allowed={canApprove}
                  reason={APPROVE_REQUIRED_REASON}
                  onClick={() => onAction('accept')}
                >
                  <Shield className="h-4 w-4" />
                  {t('exposures.action.acceptButton', 'Accept risk')}
                </GatedButton>
              </>
            ) : (
              <Button size="sm" variant="outline" onClick={() => onAction('reactivate')}>
                <Activity className="h-4 w-4" />
                {t('exposures.action.reactivateButton', 'Reactivate')}
              </Button>
            )
          }
          // False positive needs the same approve permission as Accept risk;
          // without it the outline Accept risk button explains why.
          menu={
            exposure.state === 'active' && canApprove
              ? [
                  {
                    label: t('exposures.action.fpButton', 'Mark false positive'),
                    icon: ShieldX,
                    onSelect: () => onAction('false_positive'),
                  },
                ]
              : undefined
          }
          onClose={() => onOpenChange(false)}
        />
      }
    >
      <DetailSections>
        <PendingDispositionPanel exposure={exposure} onChanged={onChanged} />
        {exposure.description && (
          <DetailSection title={t('exposures.detail.description', 'Description')}>
            <p className="text-sm text-muted-foreground">{exposure.description}</p>
          </DetailSection>
        )}

        {/* Security context: read-time CTEM enrichment (api #483): effective
            criticality, KEV, EPSS and attack-path reachability. Renders only
            when the API returns at least one signal. */}
        <ExposureSecurityContext exposure={exposure} />

        <DetailSection title={t('exposures.detail.timeline', 'Timeline')} icon={Clock}>
          <DetailFieldGrid>
            <DetailField label={t('exposures.detail.firstSeen', 'First seen')}>
              {formatRelative(exposure.first_seen_at)}
            </DetailField>
            <DetailField label={t('exposures.detail.lastSeen', 'Last seen')}>
              {formatRelative(exposure.last_seen_at)}
            </DetailField>
            {exposure.resolved_at && (
              <DetailField label={t('exposures.detail.resolved', 'Resolved')}>
                {formatRelative(exposure.resolved_at)}
              </DetailField>
            )}
          </DetailFieldGrid>
        </DetailSection>

        {exposure.details && Object.keys(exposure.details).length > 0 && (
          <ExposureDetailsView
            details={exposure.details}
            leakedCredentialId={
              exposure.event_type === 'credential_leaked' ? exposure.id : undefined
            }
          />
        )}

        {/* State changes: the shared trigger + panel (read only). */}
        <DetailSection title={t('exposures.detail.activity', 'Activity')} icon={Activity}>
          <EntityActivity
            entityKey={`exposure:${exposure.id}`}
            subject={exposure.title}
            items={exposureHistoryItems(history, t)}
            loading={historyLoading}
            error={historyError}
            onRetry={() => void retryHistory()}
            urlParam={false}
            emptyTitle="No state changes recorded"
          />
        </DetailSection>
      </DetailSections>
    </DetailSheet>
  )
}

// ============================================
// STATE HISTORY -> ACTIVITY ITEMS
// ============================================

function stateWords(state: string, t: Translate) {
  return t(`exposures.state.${state}`, state.replace(/_/g, ' '))
}

/** State history rows as the shared ActivityPanel's events (text only). */
function exposureHistoryItems(
  history: import('@/lib/api/exposure-types').ExposureStateHistory[],
  t: Translate
): ActivityItem[] {
  return history.map((h) => ({
    kind: 'event',
    id: h.id,
    at: h.created_at,
    actor: h.changed_by_user
      ? {
          id: h.changed_by_user.id,
          name:
            h.changed_by_user.name ||
            h.changed_by_user.email ||
            t('exposures.history.someone', 'Someone'),
          kind: 'user',
        }
      : { name: t('exposures.history.system', 'System'), kind: 'system' },
    icon: ArrowRightLeft,
    summary: t('exposures.history.changedState', 'changed state {from} → {to}', {
      from: stateWords(h.previous_state, t),
      to: stateWords(h.new_state, t),
    }),
    detail: h.reason ? `“${h.reason}”` : undefined,
  }))
}
