'use client'

import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  FacetOption,
  FacetPanel,
  FacetSection,
  FacetToggle,
  FilterSheet,
  SettingsPage,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
} from '@/features/shared'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { ListCount } from '@/features/shared/components/list-title-row'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { RefreshCw, ScrollText, ShieldX, Copy, Download } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  useAuditLogs,
  toAuditApiPage,
  useAuditExport,
  type AuditLog,
  type AuditLogFilters,
  type AuditResult,
  type AuditSeverity,
  RESULT_DISPLAY,
  SEVERITY_DISPLAY,
  formatAction,
} from '@/features/organization'
import { copyToClipboard } from '@/lib/clipboard'
import { toast } from 'sonner'
import { canonicalAuditMetadataKey, canonicalAuditResourceType } from '@/lib/api/audit-types'
import { humanizeIdentifier } from '@/lib/humanize-identifier'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { useSearchQuery } from '@/hooks/use-search-query'
import { replaceUrlSearch, useUrlFilter, useUrlFilterList } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { toDisplayText } from '@/lib/untrusted-text'
import {
  formatDate as localeFormatDate,
  formatDateTime,
  formatTime as localeFormatTime,
} from '@/lib/app-locale'

/**
 * The organization's audit log (board P4-Settings-AuditLog): one list with
 * search, Add filter (result, severity, period, hide system) and the count of
 * matching events; Export and Refresh at the toolbar end. The whole view
 * lives in the URL (`?q ?result ?severity ?period ?hide_system ?sort`) so a
 * filtered slice of the log can be shared. Reading needs `audit:read`; a
 * restricted data scope gets the "full data access" state from the API.
 */

const PAGE_SIZES = [10, 20, 30, 50, 100]
const SORTABLE = ['logged_at', 'action', 'resource_type', 'result', 'severity']
const RESULT_OPTIONS: AuditResult[] = ['success', 'failure', 'denied']
const SEVERITY_OPTIONS: readonly AuditSeverity[] = SEVERITY_LEVELS
const FILTER_PARAMS = ['q', 'result', 'severity', 'period', 'hide_system']

/** Periods the list can be narrowed to, newest events first. */
export const PERIODS = { '24h': 1, '7d': 7, '30d': 30 } as const
export type AuditPeriod = keyof typeof PERIODS
const PERIOD_WORDS: Record<AuditPeriod, [string, string]> = {
  '24h': ['auditLog.period.24h', 'Last 24 hours'],
  '7d': ['auditLog.period.7d', 'Last 7 days'],
  '30d': ['auditLog.period.30d', 'Last 30 days'],
}

/** The start of a period ending at `end`, cut to the minute (a stable request key). */
export function periodSince(period: AuditPeriod, end: number): string {
  const start = new Date(end - PERIODS[period] * 86_400_000)
  start.setUTCSeconds(0, 0)
  return start.toISOString()
}

/** The clock, read only from event handlers (a new period ends now). */
const now = () => Date.now()

type TFn = ReturnType<typeof useTranslation>['t']

const formatRelativeTime = (dateString: string, t: TFn) => {
  const date = new Date(dateString)
  const diffMs = Date.now() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return t('auditLog.time.justNow', 'Just now')
  if (diffMins < 60) return t('auditLog.time.minutesAgo', '{n}m ago', { n: diffMins })
  if (diffHours < 24) return t('auditLog.time.hoursAgo', '{n}h ago', { n: diffHours })
  if (diffDays < 7) return t('auditLog.time.daysAgo', '{n}d ago', { n: diffDays })
  return localeFormatDate(date, { year: 'numeric', month: 'short', day: 'numeric' })
}

/** Result as a badge: a problem (failure, denied) is red, success is quiet. */
function ResultBadge({ result }: { result: AuditResult }) {
  const { t } = useTranslation()
  const label = t(`auditLog.result.${result}`, RESULT_DISPLAY[result]?.label ?? result)
  return <Badge variant={result === 'success' ? 'secondary' : 'destructive'}>{label}</Badge>
}

const actorText = (log: AuditLog, t: TFn) =>
  log.actor_email ? toDisplayText(log.actor_email, 200) : t('auditLog.system', 'System')
const resourceText = (log: AuditLog) => toDisplayText(log.resource_name || log.resource_id, 200)

// Frame widths (px) under which a column gives way, so the table fits its
// frame instead of cutting a header: the severity first, then the actor, then
// the resource (all three are on the event's detail and the phone card).
const AUDIT_HIDE_BELOW = { severity: 1120, actor: 990, resource: 830 } as const

export default function AuditLogPage() {
  const { t } = useTranslation()
  const hasAuditPermission = useHasPermission(Permission.AuditRead)

  const [searchTerm, setSearchTerm] = useUrlFilter('q', '')
  const [resultParam, setResultParam] = useUrlFilterList('result')
  const [severityParam, setSeverityParam] = useUrlFilterList('severity')
  const [periodParam, setPeriodParam] = useUrlFilter('period', '')
  const [hideSystemParam, setHideSystemParam] = useUrlFilter('hide_system', '')
  const [sortParam, setSortParam] = useUrlFilter('sort', '')
  const list = useListParams({ pageSizes: PAGE_SIZES })
  const { pagination, setPagination, setPage } = list
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null)
  const [filterSheetOpen, setFilterSheetOpen] = useState(false)
  // The end of a period: fixed until the reader refreshes or picks another
  // period, so the request key does not change on every render.
  const [periodEnd, setPeriodEnd] = useState(() => Date.now())

  const debouncedSearch = useSearchQuery(searchTerm).term

  // `sort=field:dir` in the URL and the table's sorting state.
  const sorting = useMemo<SortingState>(() => {
    const [id, dir] = sortParam.split(':')
    return SORTABLE.includes(id) ? [{ id, desc: dir !== 'asc' }] : []
  }, [sortParam])
  const handleSortingChange = useCallback(
    (next: SortingState) => {
      const s = next[0]
      setSortParam(s ? `${s.id}:${s.desc ? 'desc' : 'asc'}` : '')
      setPage(1)
    },
    [setSortParam, setPage]
  )

  const results = useMemo(
    () => RESULT_OPTIONS.filter((r) => resultParam.includes(r)),
    [resultParam]
  )
  const severities = useMemo(
    () => SEVERITY_OPTIONS.filter((s) => severityParam.includes(s)),
    [severityParam]
  )
  const period = periodParam in PERIODS ? (periodParam as AuditPeriod) : null
  const hideSystem = hideSystemParam === 'true'

  // The API pages are 1-based; the table is 0-based.
  const activeFilters = useMemo<AuditLogFilters>(
    () => ({
      page: toAuditApiPage(pagination.pageIndex),
      per_page: pagination.pageSize,
      search: debouncedSearch || undefined,
      result: results.length > 0 ? results : undefined,
      severity: severities.length > 0 ? severities : undefined,
      since: period ? periodSince(period, periodEnd) : undefined,
      exclude_system: hideSystem || undefined,
      sort_by: sorting[0]?.id,
      sort_order: sorting[0] ? (sorting[0].desc ? 'desc' : 'asc') : undefined,
    }),
    [pagination, debouncedSearch, results, severities, period, periodEnd, hideSystem, sorting]
  )

  const { logs, total, isLoading, isError, error, mutate } = useAuditLogs(
    hasAuditPermission ? activeFilters : undefined
  )
  // A restricted data scope may read only its own activity: the API answers 403
  // with details.required. Show that as an access state, not a load failure.
  const needsFullData =
    isError &&
    error instanceof ApiClientError &&
    error.statusCode === 403 &&
    !!error.details?.required
  // The export carries the filters the list shows; paging and sort do not apply.
  const { run: runExport, isExporting } = useAuditExport(activeFilters)
  // The file holds members' emails and IP addresses, so a format pick asks first.
  const [pendingExport, setPendingExport] = useState<'csv' | 'jsonl' | null>(null)

  const refresh = useCallback(() => {
    // A period ends now again; without a period the key stays and SWR refetches.
    if (period) setPeriodEnd(now())
    else void mutate()
  }, [period, mutate])

  const timeLabel = t('auditLog.col.time', 'Time')
  // A type with no catalog entry reads as its humanised name.
  const resourceTypeLabel = useCallback(
    (raw: string) => {
      const type = canonicalAuditResourceType(raw)
      return t(`auditLog.resourceType.${type}`, humanizeIdentifier(type))
    },
    [t]
  )
  const actionLabel = t('auditLog.col.action', 'Action')
  const actorLabel = t('auditLog.col.actor', 'Actor')
  const resourceLabel = t('auditLog.col.resource', 'Resource')
  const resultLabel = t('auditLog.col.result', 'Result')
  const severityLabel = t('auditLog.col.severity', 'Severity')

  const columns = useMemo<ColumnDef<AuditLog>[]>(
    () => [
      {
        id: 'logged_at',
        accessorKey: 'timestamp',
        meta: { kind: 'datetime-recent', label: timeLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={timeLabel} />,
        cell: ({ row }) => (
          <div className="flex flex-col whitespace-nowrap">
            <span className="text-sm font-medium">
              {formatRelativeTime(row.original.timestamp, t)}
            </span>
            <span className="text-xs text-muted-foreground tabular-nums">
              {localeFormatTime(new Date(row.original.timestamp), {
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
          </div>
        ),
      },
      {
        id: 'action',
        accessorKey: 'action',
        meta: { kind: 'name', minWidth: 200, label: actionLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={actionLabel} />,
        cell: ({ row }) => (
          <span className="block truncate text-sm font-medium">
            {formatAction(row.original.action, t)}
          </span>
        ),
      },
      {
        id: 'actor',
        meta: { kind: 'owner', hideBelow: AUDIT_HIDE_BELOW.actor, label: actorLabel },
        header: actorLabel,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="block truncate text-sm">{actorText(row.original, t)}</span>
        ),
      },
      {
        id: 'resource_type',
        accessorKey: 'resource_type',
        meta: {
          kind: 'text',
          minWidth: 180,
          maxWidth: 320,
          hideBelow: AUDIT_HIDE_BELOW.resource,
          label: resourceLabel,
        },
        header: ({ column }) => <DataTableColumnHeader column={column} title={resourceLabel} />,
        cell: ({ row }) => (
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-sm">{resourceText(row.original)}</span>
            <span className="truncate text-xs text-muted-foreground">
              {resourceTypeLabel(row.original.resource_type)}
            </span>
          </div>
        ),
      },
      {
        id: 'result',
        accessorKey: 'result',
        meta: { kind: 'status', label: resultLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={resultLabel} />,
        cell: ({ row }) => <ResultBadge result={row.original.result} />,
      },
      {
        id: 'severity',
        accessorKey: 'severity',
        meta: { kind: 'severity', hideBelow: AUDIT_HIDE_BELOW.severity, label: severityLabel },
        header: ({ column }) => <DataTableColumnHeader column={column} title={severityLabel} />,
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
    ],
    [
      t,
      timeLabel,
      actionLabel,
      actorLabel,
      resourceLabel,
      resultLabel,
      severityLabel,
      resourceTypeLabel,
    ]
  )

  const title = t('auditLog.title', 'Audit log')
  const description = t('auditLog.description', 'Activity history and security events.')

  if (!hasAuditPermission) {
    return (
      <SettingsPage wide title={title} description={description}>
        <EmptyState
          icon={ShieldX}
          title={t('auditLog.denied.title', 'Access denied')}
          description={t(
            'auditLog.denied.description',
            "You don't have permission to view audit logs. Ask your administrator for access."
          )}
        />
      </SettingsPage>
    )
  }

  // Every filter change starts again at the first page.
  const change =
    <A extends unknown[]>(fn: (...a: A) => void) =>
    (...a: A) => {
      fn(...a)
      setPage(1)
    }
  const toggleIn = <T extends string>(set: (next: (prev: string[]) => string[]) => void) =>
    change((value: T, on: boolean) =>
      set((prev) =>
        on ? [...prev.filter((v) => v !== value), value] : prev.filter((v) => v !== value)
      )
    )
  const toggleResult = toggleIn<AuditResult>(setResultParam)
  const toggleSeverity = toggleIn<AuditSeverity>(setSeverityParam)
  const pickPeriod = change((p: AuditPeriod | null) => {
    setPeriodEnd(now())
    setPeriodParam(p ?? '')
  })
  const setHide = change((on: boolean) => setHideSystemParam(on ? 'true' : ''))

  // One URL write for several params (two setters in a row would each start
  // from the same URL).
  const clearFilters = () => {
    const next = new URLSearchParams(window.location.search)
    for (const name of FILTER_PARAMS) next.delete(name)
    next.delete('page')
    replaceUrlSearch(next)
  }
  const clearFacets = () => {
    const next = new URLSearchParams(window.location.search)
    for (const name of ['result', 'severity', 'period', 'hide_system']) next.delete(name)
    next.delete('page')
    replaceUrlSearch(next)
  }

  const resultWord = (r: AuditResult) => t(`auditLog.result.${r}`, RESULT_DISPLAY[r].label)
  const severityWord = (s: AuditSeverity) => t(`severity.${s}`, SEVERITY_DISPLAY[s].label)
  const periodWord = (p: AuditPeriod) => t(PERIOD_WORDS[p][0], PERIOD_WORDS[p][1])
  const periodLabel = t('auditLog.filter.period', 'Period')

  const chipList = [
    ...(results.length > 0
      ? [
          {
            key: 'result',
            text: t('auditLog.chip.result', 'Result: {value}', {
              value: results.map(resultWord).join(', '),
            }),
            clear: change(() => setResultParam([])),
          },
        ]
      : []),
    ...(severities.length > 0
      ? [
          {
            key: 'severity',
            text: t('auditLog.chip.severity', 'Severity: {value}', {
              value: severities.map(severityWord).join(', '),
            }),
            clear: change(() => setSeverityParam([])),
          },
        ]
      : []),
    ...(period
      ? [
          {
            key: 'period',
            text: t('auditLog.chip.period', 'Period: {value}', { value: periodWord(period) }),
            clear: () => pickPeriod(null),
          },
        ]
      : []),
    ...(hideSystem
      ? [
          {
            key: 'hide_system',
            text: t('auditLog.chip.hideSystem', 'System events hidden'),
            clear: () => setHide(false),
          },
        ]
      : []),
  ]
  const activeCount = chipList.length
  const narrowed = activeCount > 0 || searchTerm.trim() !== ''

  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="audit-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('auditLog.chip.remove', 'Remove filter {filter}', { filter: c.text })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearFacets : undefined}
      />
    ) : undefined

  const facets = (
    <FacetPanel activeCount={activeCount} onClearAll={clearFacets}>
      <FacetSection title={resultLabel} selectedCount={results.length}>
        {RESULT_OPTIONS.map((r) => (
          <FacetOption
            key={r}
            label={resultWord(r)}
            checked={results.includes(r)}
            onCheckedChange={(on) => toggleResult(r, on)}
          />
        ))}
      </FacetSection>
      <FacetSection title={severityLabel} selectedCount={severities.length}>
        {SEVERITY_OPTIONS.map((s) => (
          <FacetOption
            key={s}
            label={severityWord(s)}
            checked={severities.includes(s)}
            onCheckedChange={(on) => toggleSeverity(s, on)}
          />
        ))}
      </FacetSection>
      <FacetSection title={periodLabel} selectedCount={period ? 1 : 0}>
        {(Object.keys(PERIODS) as AuditPeriod[]).map((p) => (
          <FacetOption
            key={p}
            label={periodWord(p)}
            checked={period === p}
            onCheckedChange={(on) => pickPeriod(on ? p : null)}
          />
        ))}
      </FacetSection>
      <FacetToggle
        label={t('auditLog.hideSystem', 'Hide system')}
        description={t('auditLog.hideSystemHint', 'Hide events performed by the system itself')}
        checked={hideSystem}
        onCheckedChange={setHide}
      />
    </FacetPanel>
  )
  const filtersLabel = t('auditLog.filtersLabel', 'Audit log filters')

  const countLabel = t('auditLog.count', '{count, plural, one {# event} other {# events}}', {
    count: total,
  })

  const toolbarEnd = (
    <>
      <ListCount
        total={total}
        loading={isLoading}
        label={countLabel}
        className="hidden sm:inline-flex"
      />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          {/* Icon-only on a phone, so the search keeps its room. */}
          <Button
            variant="outline"
            size="sm"
            iconOnlyBelow="@2xl/toolbar"
            disabled={isExporting}
            title={t('auditLog.export.button', 'Export')}
          >
            <Download aria-hidden="true" />
            <span className="sr-only @2xl/toolbar:not-sr-only">
              {t('auditLog.export.button', 'Export')}
            </span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuLabel className="max-w-56 text-xs font-normal text-muted-foreground">
            {t(
              'auditLog.export.hint',
              'Exports the events that match the current filters, newest first.'
            )}
          </DropdownMenuLabel>
          <DropdownMenuItem onSelect={() => setPendingExport('csv')}>
            {t('auditLog.export.csv', 'CSV')}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setPendingExport('jsonl')}>
            {t('auditLog.export.jsonl', 'JSON lines')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Button
        variant="outline"
        size="icon-sm"
        onClick={refresh}
        aria-label={t('auditLog.refresh', 'Refresh')}
        title={t('auditLog.refresh', 'Refresh')}
      >
        <RefreshCw aria-hidden="true" />
      </Button>
    </>
  )

  // What the export will hold, in words: the count and the filters in force.
  const exportScope = [
    countLabel,
    ...(period ? [periodWord(period)] : []),
    ...chipList.filter((c) => c.key !== 'period').map((c) => c.text),
  ].join(', ')

  return (
    <>
      <SettingsPage wide title={title} description={description}>
        {needsFullData ? (
          <EmptyState
            icon={ShieldX}
            title={t('auditLog.needsFullData.title')}
            description={t('auditLog.needsFullData.description')}
          />
        ) : (
          <DataTable
            columns={columns}
            data={logs}
            isLoading={isLoading && logs.length === 0}
            error={isError ? (error ?? true) : undefined}
            onRetry={() => void mutate()}
            errorTitle={t('auditLog.errorTitle', 'the audit log')}
            getRowId={(log) => log.id}
            showSearch={false}
            search={{
              value: searchTerm,
              onChange: change(setSearchTerm),
              placeholder: t('auditLog.search.placeholder', 'Search by actor, action, resource…'),
              label: t('auditLog.search.label', 'Search audit log'),
            }}
            filterToggle={{
              open: false,
              onToggle: () => setFilterSheetOpen(true),
              onOpenSheet: () => setFilterSheetOpen(true),
              activeCount,
              controlsId: 'audit-filters',
              label: filtersLabel,
              sheetOnly: true,
            }}
            showColumnToggle={false}
            toolbarStart={<AddFilterPanel>{facets}</AddFilterPanel>}
            toolbarEnd={toolbarEnd}
            toolbarBelow={chipsRow}
            onRowClick={(log) => setSelectedLog(log)}
            manualPagination
            rowCount={total}
            pagination={pagination}
            onPaginationChange={setPagination}
            pageSizeOptions={PAGE_SIZES}
            paginationNoun={t('auditLog.noun', 'events')}
            sorting={sorting}
            onSortingChange={handleSortingChange}
            mobileRow={(log) => (
              <PersonPhoneCard
                title={formatAction(log.action, t)}
                address={`${actorText(log, t)}, ${resourceText(log)}`}
                onOpen={() => setSelectedLog(log)}
                facts={
                  <>
                    <ResultBadge result={log.result} />
                    <SeverityBadge severity={log.severity} />
                    <span className="text-cap text-muted-foreground tabular-nums">
                      {formatRelativeTime(log.timestamp, t)}
                    </span>
                  </>
                }
              />
            )}
            isFiltered={narrowed}
            onClearFilters={clearFilters}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={ScrollText}
                  title={t('auditLog.emptyTitle', 'Nothing recorded yet')}
                  description={t(
                    'auditLog.emptyHint',
                    'Events appear here as people and systems act in this organization.'
                  )}
                />
              ),
              noMatch: {
                title: t('auditLog.empty', 'No audit events found'),
                hint: t('auditLog.emptyFiltered', 'Try adjusting your search or filters.'),
              },
            }}
          />
        )}
      </SettingsPage>

      <FilterSheet open={filterSheetOpen} onOpenChange={setFilterSheetOpen} title={filtersLabel}>
        {facets}
      </FilterSheet>

      {/* Audit Log Detail Sheet */}
      {selectedLog && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setSelectedLog(null)}
          width="2xl"
          header={
            <DetailHeader
              title={formatAction(selectedLog.action, t)}
              badges={
                <>
                  <ResultBadge result={selectedLog.result} />
                  <SeverityBadge severity={selectedLog.severity} />
                </>
              }
              meta={[
                selectedLog.actor_email || t('auditLog.system', 'System'),
                formatDateTime(new Date(selectedLog.timestamp)),
              ]}
              menu={[
                {
                  label: t('auditLog.copyResourceId', 'Copy resource ID'),
                  icon: Copy,
                  onSelect: () => {
                    copyToClipboard(selectedLog.resource_id)
                    toast.success(t('auditLog.resourceIdCopied', 'Resource ID copied'))
                  },
                },
                ...(selectedLog.request_id
                  ? [
                      {
                        label: t('auditLog.copyRequestId', 'Copy request ID'),
                        icon: Copy,
                        onSelect: () => {
                          copyToClipboard(selectedLog.request_id!)
                          toast.success(t('auditLog.requestIdCopied', 'Request ID copied'))
                        },
                      },
                    ]
                  : []),
              ]}
              onClose={() => setSelectedLog(null)}
            />
          }
        >
          <DetailSections>
            {selectedLog.message && (
              <DetailSection title={t('auditLog.detail.message', 'Message')}>
                <p className="text-sm break-words text-muted-foreground">{selectedLog.message}</p>
              </DetailSection>
            )}

            <DetailSection title={t('auditLog.detail.whoWhen', 'Who and when')}>
              <DetailFieldGrid>
                <DetailField label={t('auditLog.col.actor', 'Actor')}>
                  <span className="break-words">
                    {selectedLog.actor_email || t('auditLog.system', 'System')}
                  </span>
                </DetailField>
                {selectedLog.actor_ip && (
                  <DetailField label={t('auditLog.detail.ip', 'IP address')}>
                    <span className="font-mono text-xs">{selectedLog.actor_ip}</span>
                  </DetailField>
                )}
                <DetailField label={t('auditLog.detail.date', 'Date')}>
                  {formatDateTime(new Date(selectedLog.timestamp), {
                    weekday: 'short',
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                  })}
                </DetailField>
                <DetailField label={t('auditLog.col.time', 'Time')}>
                  <span className="tabular-nums">
                    {localeFormatTime(new Date(selectedLog.timestamp))}
                  </span>
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>

            <DetailSection title={t('auditLog.col.resource', 'Resource')}>
              <DetailFieldGrid>
                <DetailField label={t('auditLog.detail.type', 'Type')}>
                  {resourceTypeLabel(selectedLog.resource_type)}
                </DetailField>
                <DetailField label={t('auditLog.detail.name', 'Name')}>
                  <span className="break-words">{selectedLog.resource_name || '-'}</span>
                </DetailField>
                <DetailField label={t('auditLog.detail.id', 'ID')} full>
                  <DetailCopyId
                    id={selectedLog.resource_id}
                    label={t('auditLog.resourceId', 'Resource ID')}
                    ariaLabel={t('auditLog.copyResourceId', 'Copy resource ID')}
                    copiedMessage={t('auditLog.resourceIdCopied', 'Resource ID copied')}
                  />
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>

            {selectedLog.changes?.field_changes &&
              Object.keys(selectedLog.changes.field_changes).length > 0 && (
                <DetailSection
                  title={t('auditLog.detail.changes', 'Changes')}
                  count={Object.keys(selectedLog.changes.field_changes).length}
                >
                  <ul className="divide-y rounded-lg border">
                    {Object.entries(selectedLog.changes.field_changes).map(([field, change]) => (
                      <li
                        key={field}
                        className="grid gap-2 px-3 py-2.5 text-sm sm:grid-cols-[1fr_2fr] sm:items-center sm:gap-4"
                      >
                        <span className="font-medium break-words text-muted-foreground">
                          {field}
                        </span>
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex items-center rounded-md bg-muted px-2 py-1 text-xs break-words text-muted-foreground line-through">
                            {String(change.old)}
                          </span>
                          <span className="text-muted-foreground">→</span>
                          <span className="inline-flex items-center rounded-md bg-accent px-2 py-1 text-xs font-medium break-words text-accent-foreground">
                            {String(change.new)}
                          </span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </DetailSection>
              )}

            {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
              <DetailSection
                title={t('auditLog.detail.metadata', 'Metadata')}
                count={Object.keys(selectedLog.metadata).length}
              >
                <DetailFieldGrid>
                  {Object.entries(selectedLog.metadata).map(([key, value]) => (
                    <DetailField key={key} label={canonicalAuditMetadataKey(key)}>
                      <span className="font-mono text-xs break-all">
                        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                      </span>
                    </DetailField>
                  ))}
                </DetailFieldGrid>
              </DetailSection>
            )}

            {selectedLog.request_id && (
              <DetailSection title={t('auditLog.detail.request', 'Request')}>
                <DetailCopyId
                  id={selectedLog.request_id}
                  label={t('auditLog.requestId', 'Request ID')}
                  ariaLabel={t('auditLog.copyRequestId', 'Copy request ID')}
                  copiedMessage={t('auditLog.requestIdCopied', 'Request ID copied')}
                />
              </DetailSection>
            )}
          </DetailSections>
        </DetailSheet>
      )}
      <ConfirmDialog
        open={pendingExport !== null}
        onOpenChange={(open) => {
          if (!open) setPendingExport(null)
        }}
        title={t('auditLog.export.confirmTitle', 'Export the audit log?')}
        desc={
          <>
            <span className="block">
              {t('auditLog.export.scope', 'This export holds {scope}.', { scope: exportScope })}
            </span>
            <span className="mt-2 block">
              {t(
                'auditLog.export.confirmDesc',
                "The file lists the events that match the current filters, newest first, with members' emails and IP addresses. Keep it where only people who may see them can read it. You may be asked to verify it's you."
              )}
            </span>
          </>
        }
        confirmText={
          pendingExport === 'jsonl'
            ? t('auditLog.export.confirmJsonl', 'Export JSON lines')
            : t('auditLog.export.confirmCsv', 'Export CSV')
        }
        handleConfirm={async () => {
          const format = pendingExport
          setPendingExport(null)
          if (format) await runExport(format)
        }}
      />
    </>
  )
}
