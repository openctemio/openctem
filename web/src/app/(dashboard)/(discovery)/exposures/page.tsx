'use client'

import { useTranslation } from '@/context/i18n-provider'

import { useState, useCallback, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Main } from '@/components/layout'
import {
  DataTable,
  ErrorState,
  EmptyState,
  GatedButton,
  MetricStrip,
  PageHeader,
  SeverityBadge,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
} from '@/features/shared'
import type { MetricStripItem } from '@/features/shared'
import { useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { useSearchQuery } from '@/hooks/use-search-query'
import { cn } from '@/lib/utils'
import {
  Search,
  RefreshCw,
  Download,
  Shield,
  AlertTriangle,
  ShieldCheck,
  ShieldX,
  X,
  Clock,
  Activity,
  ArrowRightLeft,
  ChevronDown,
  BarChart3,
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
  ExposureActionDialog,
  ExposureBulkActions,
  ExposureSecurityContext,
  ExposuresTabs,
  APPROVE_REQUIRED_REASON,
  useCanApproveExposures,
  PendingDispositionBadge,
  PendingDispositionPanel,
  ExposureDetailsView,
} from '@/features/exposures/components'
import { runPool, summarizeBulk } from '@/features/exposures/lib/bulk'
import type {
  ExposureEvent,
  ExposureListFilters,
  ExposureSeverity,
  ExposureState,
} from '@/lib/api/exposure-types'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { SEVERITY_LABELS as SHARED_SEVERITY_LABELS } from '@/lib/severity'

type ActionType = 'resolve' | 'accept' | 'false_positive' | 'reactivate'

// Lifecycle view — the primary filter.
type StateTab = 'needs_attention' | 'resolved' | 'all'

const STATE_VIEWS: { value: StateTab; label: string }[] = [
  { value: 'needs_attention', label: 'Needs attention' },
  { value: 'resolved', label: 'Closed' },
  { value: 'all', label: 'All states' },
]

const SEVERITIES: ExposureSeverity[] = [...SEVERITY_LEVELS]
const SEVERITY_LABELS: Record<ExposureSeverity, string> = SHARED_SEVERITY_LABELS

const PAGE_SIZES = [10, 20, 30, 50, 100]

// CSV columns for the Export action — every exposure matching the filters.
const EXPOSURE_EXPORT_FIELDS: ExportFieldConfig<ExposureEvent>[] = [
  { header: 'ID', accessor: (e) => e.id },
  { header: 'Title', accessor: (e) => e.title },
  { header: 'Event Type', accessor: (e) => e.event_type.replace(/_/g, ' ') },
  { header: 'Severity', accessor: (e) => e.severity },
  { header: 'State', accessor: (e) => e.state },
  { header: 'Source', accessor: (e) => e.source },
  { header: 'First Seen', accessor: (e) => e.first_seen_at },
  { header: 'Last Seen', accessor: (e) => e.last_seen_at },
  { header: 'Resolved At', accessor: (e) => e.resolved_at ?? '' },
]

// Map the lifecycle view to API state filters.
function getStatesForTab(tab: StateTab): ExposureState[] | undefined {
  switch (tab) {
    case 'needs_attention':
      return ['active']
    case 'resolved':
      return ['resolved', 'accepted', 'false_positive']
    default:
      return undefined // No filter = all states
  }
}

function ExposureTableSkeleton() {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Skeleton className="h-9 w-72" />
        <Skeleton className="h-9 w-28" />
        <Skeleton className="ms-auto h-9 w-24" />
      </div>
      <div className="space-y-2 rounded-md border p-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    </div>
  )
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
  const list = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 20 })
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

  // Detail sheet state
  const [detailExposure, setDetailExposure] = useState<ExposureEvent | null>(null)

  const apiFilters: ExposureListFilters = useMemo(
    () => ({
      page: pagination.pageIndex + 1,
      per_page: pagination.pageSize,
      search: debouncedSearch || undefined,
      severities: selectedSeverities.length > 0 ? selectedSeverities : undefined,
      states: getStatesForTab(activeView),
    }),
    [pagination, debouncedSearch, selectedSeverities, activeView]
  )

  const {
    exposures,
    total,
    isLoading: exposuresLoading,
    error: exposuresError,
    mutate: refreshExposures,
  } = useExposures(tenantId, apiFilters)

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
      exportToCsv(all, EXPOSURE_EXPORT_FIELDS, 'exposures')
    } catch {
      toast.error('Failed to export exposures')
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

  const clearFilters = useCallback(() => {
    setSearchQuery('')
    setSeverityParam([])
    setStateParam('needs_attention')
    resetPage()
  }, [setSearchQuery, setSeverityParam, setStateParam, resetPage])

  const hasActiveFilters =
    !!searchQuery || selectedSeverities.length > 0 || activeView !== 'needs_attention'

  // Accept risk / false positive need findings:approve (api#675).
  const canApprove = useCanApproveExposures()
  const columns = useMemo(
    () =>
      getExposureColumns({
        onResolve: (e) => handleAction(e, 'resolve'),
        onAccept: (e) => handleAction(e, 'accept'),
        onMarkFalsePositive: (e) => handleAction(e, 'false_positive'),
        onReactivate: (e) => handleAction(e, 'reactivate'),
        onViewDetails: setDetailExposure,
        canApprove,
      }),
    [handleAction, canApprove]
  )

  // Headline numbers double as the lifecycle quick filter.
  const activeCount = stats?.active_count ?? 0
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: 'Total exposures',
      value: stats?.total ?? 0,
      onClick: () => setView('all'),
      active: activeView === 'all',
    },
    {
      key: 'active',
      label: 'Needs attention',
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
    {
      key: 'mttr',
      label: 'Mean time to resolve',
      value: stats?.mttr_hours ? `${stats.mttr_hours.toFixed(1)}h` : '—',
    },
  ]

  const rangeStart = total === 0 ? 0 : pagination.pageIndex * pagination.pageSize + 1
  const rangeEnd = Math.min(total, (pagination.pageIndex + 1) * pagination.pageSize)

  const toolbarStart = (
    <>
      <div className="relative min-w-40 flex-1 sm:max-w-sm">
        <Search className="pointer-events-none absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
          placeholder="Search exposures…"
          aria-label="Search exposures"
          className="h-9 ps-9"
        />
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="h-9">
            Severity
            {selectedSeverities.length > 0 && (
              <Badge variant="secondary" className="ms-2 px-1.5 tabular-nums">
                {selectedSeverities.length}
              </Badge>
            )}
            <ChevronDown className="ms-2 h-4 w-4 text-muted-foreground" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuLabel>Severity</DropdownMenuLabel>
          {SEVERITIES.map((severity) => (
            <DropdownMenuCheckboxItem
              key={severity}
              checked={selectedSeverities.includes(severity)}
              onCheckedChange={() => toggleSeverity(severity)}
              onSelect={(e) => e.preventDefault()}
            >
              {SEVERITY_LABELS[severity]}
            </DropdownMenuCheckboxItem>
          ))}
          {selectedSeverities.length > 0 && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setSeverityParam([])}>Clear</DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="h-9">
            {STATE_VIEWS.find((v) => v.value === activeView)?.label}
            <ChevronDown className="ms-2 h-4 w-4 text-muted-foreground" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuLabel>State</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={activeView} onValueChange={(v) => setView(v as StateTab)}>
            {STATE_VIEWS.map((v) => (
              <DropdownMenuRadioItem key={v.value} value={v.value}>
                {v.label}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
      {hasActiveFilters && (
        <Button variant="ghost" size="sm" className="h-9" onClick={clearFilters}>
          <X className="me-1 h-4 w-4" />
          Clear
        </Button>
      )}
    </>
  )

  const toolbarEnd = (
    <>
      <span className="hidden text-sm tabular-nums text-muted-foreground xl:inline">
        {total === 0 ? 'No results' : `${rangeStart}–${rangeEnd} of ${total.toLocaleString()}`}
      </span>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="icon"
            className="h-9 w-9"
            onClick={handleRefresh}
            disabled={isLoading}
            aria-label="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Refresh</TooltipContent>
      </Tooltip>
      <Button
        variant="outline"
        size="sm"
        className="h-9"
        onClick={handleExport}
        disabled={isExporting || exposuresLoading || total === 0}
      >
        <Download className="h-4 w-4 xl:me-2" />
        <span className="sr-only xl:not-sr-only">{isExporting ? 'Exporting…' : 'Export'}</span>
      </Button>
    </>
  )

  return (
    <Main>
      <PageHeader
        title="Exposures"
        description={t(
          'exposures.page.description',
          'Changes to your attack surface that need a decision. Resolve, accept or dismiss them.'
        )}
      />

      <ExposuresTabs />

      <Tabs value={tab} onValueChange={setTabParam} className="mt-4">
        <TabsList>
          <TabsTrigger value="list">All exposures</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
        </TabsList>

        <TabsContent value="list" className="mt-5 space-y-5">
          {statsError ? (
            <ErrorState
              title={t('exposures.stats.errorTitle', 'exposure statistics')}
              error={statsError}
              onRetry={() => refreshStats()}
            />
          ) : (
            <MetricStrip loading={statsLoading} items={metrics} />
          )}

          {exposuresError ? (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Could not load exposures</AlertTitle>
              <AlertDescription className="flex flex-wrap items-center gap-3">
                The exposure list failed to load.
                <Button variant="outline" size="sm" onClick={handleRefresh}>
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          ) : exposuresLoading && exposures.length === 0 ? (
            <ExposureTableSkeleton />
          ) : (
            <DataTable
              columns={columns}
              data={exposures}
              showSearch={false}
              toolbarStart={toolbarStart}
              toolbarEnd={toolbarEnd}
              getRowId={(e) => e.id}
              manualPagination
              rowCount={total}
              pagination={pagination}
              onPaginationChange={setPagination}
              pageSizeOptions={PAGE_SIZES}
              onRowClick={setDetailExposure}
              onSelectionChange={(rows) => {
                setSelectedIds(rows.map((e) => e.id))
                setSelectedNames(rows.map((e) => e.title))
              }}
              resetSelectionKey={selectionEpoch}
              showSelectionCount={false}
              emptyMessage={hasActiveFilters ? 'No exposures match these filters' : 'No exposures'}
              emptyDescription={
                hasActiveFilters
                  ? 'Try removing a filter or clearing them all.'
                  : 'Your attack surface has no open exposure events.'
              }
            />
          )}

          <ExposureBulkActions
            selectedIds={selectedIds}
            selectedNames={selectedNames}
            onClearSelection={clearSelection}
            onBulkResolve={handleBulkResolve}
            onBulkAccept={handleBulkAccept}
            onBulkFalsePositive={handleBulkFalsePositive}
          />
        </TabsContent>

        <TabsContent value="analytics" className="mt-5 space-y-5">
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
                  <CardTitle>By event type</CardTitle>
                </CardHeader>
                <CardContent>
                  <EventTypeDistribution byEventType={stats.by_event_type} />
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>

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
  const entries = Object.entries(byEventType || {}).sort((a, b) => b[1] - a[1])
  if (entries.length === 0) {
    return <EmptyState card={false} icon={BarChart3} title="No exposure data yet" />
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
          meta={[`${exposure.event_type.replace(/_/g, ' ')} from ${exposure.source}`]}
          actions={
            exposure.state === 'active' ? (
              <>
                <Button size="sm" onClick={() => onAction('resolve')}>
                  <ShieldCheck className="h-4 w-4" />
                  Resolve
                </Button>
                <GatedButton
                  size="sm"
                  variant="outline"
                  allowed={canApprove}
                  reason={APPROVE_REQUIRED_REASON}
                  onClick={() => onAction('accept')}
                >
                  <Shield className="h-4 w-4" />
                  Accept risk
                </GatedButton>
              </>
            ) : (
              <Button size="sm" variant="outline" onClick={() => onAction('reactivate')}>
                <Activity className="h-4 w-4" />
                Reactivate
              </Button>
            )
          }
          // False positive needs the same approve permission as Accept risk;
          // without it the outline Accept risk button explains why.
          menu={
            exposure.state === 'active' && canApprove
              ? [
                  {
                    label: 'Mark false positive',
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
          <DetailSection title="Description">
            <p className="text-sm text-muted-foreground">{exposure.description}</p>
          </DetailSection>
        )}

        {/* Security context: read-time CTEM enrichment (api #483): effective
            criticality, KEV, EPSS and attack-path reachability. Renders only
            when the API returns at least one signal. */}
        <ExposureSecurityContext exposure={exposure} />

        <DetailSection title="Timeline" icon={Clock}>
          <DetailFieldGrid>
            <DetailField label="First seen">{formatRelative(exposure.first_seen_at)}</DetailField>
            <DetailField label="Last seen">{formatRelative(exposure.last_seen_at)}</DetailField>
            {exposure.resolved_at && (
              <DetailField label="Resolved">{formatRelative(exposure.resolved_at)}</DetailField>
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
        <DetailSection title="Activity" icon={Activity}>
          <EntityActivity
            entityKey={`exposure:${exposure.id}`}
            subject={exposure.title}
            items={exposureHistoryItems(history)}
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

function stateWords(state: string) {
  const s = state.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** State history rows as the shared ActivityPanel's events (text only). */
function exposureHistoryItems(
  history: import('@/lib/api/exposure-types').ExposureStateHistory[]
): ActivityItem[] {
  return history.map((h) => ({
    kind: 'event',
    id: h.id,
    at: h.created_at,
    actor: h.changed_by_user
      ? {
          id: h.changed_by_user.id,
          name: h.changed_by_user.name || h.changed_by_user.email || 'Someone',
          kind: 'user',
        }
      : { name: 'System', kind: 'system' },
    icon: ArrowRightLeft,
    summary: `changed state ${stateWords(h.previous_state)} → ${stateWords(h.new_state)}`,
    detail: h.reason ? `“${h.reason}”` : undefined,
  }))
}
