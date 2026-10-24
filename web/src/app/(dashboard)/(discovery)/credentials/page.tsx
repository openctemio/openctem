'use client'

import { useState, useMemo, useEffect, type ReactNode } from 'react'
import { post } from '@/lib/api/client'
import { fetchAllPages } from '@/lib/api/fetch-all-pages'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  ErrorState,
  PageHeader,
  StatusBadge,
  SeverityBadge,
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  MetricStrip,
  type MetricStripItem,
  PageStack,
} from '@/features/shared'
import {
  AssetDetailSheet,
  StatCard,
  StatsGrid,
  MetadataGrid,
  MetadataRow,
  SectionTitle,
} from '@/features/assets'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import {
  KeyRound,
  Search as SearchIcon,
  Eye,
  Download,
  Shield,
  Clock,
  CheckCircle,
  Copy,
  User,
  Calendar,
  X,
  Layers,
} from 'lucide-react'
import type { Asset } from '@/features/assets'
import type { CredentialLeakRow } from '@/features/credentials/lib'
import type { Severity, Status } from '@/features/shared/types'
import {
  useCredentialsApi,
  useCredentialIdentitiesApi,
  useCredentialStatsApi,
  useRelatedCredentialsApi,
  useCredentialEnumsApi,
  buildCredentialsEndpoint,
  CREDENTIAL_TYPES,
  mapCredentialsToAssets,
  CredentialIdentityGroups,
  invalidateCredentialsCache,
  LeakedSecretField,
} from '@/features/credentials'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { ApiCredential } from '@/features/credentials/api/credential-api.types'
import { copyToClipboard } from '@/lib/clipboard'
import { exportToCsv } from '@/hooks/use-csv-export'
import { useUrlFilter } from '@/hooks/use-url-param'
import { resetListPage, useListParams, DEFAULT_PAGE_SIZES } from '@/hooks/use-list-params'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { Permission, usePermissions } from '@/lib/permissions'

// Filter types
type StatusFilter = Status | 'all'

const STATUS_FILTERS: StatusFilter[] = ['all', 'active', 'completed', 'inactive']
const PAGE_SIZES = [...DEFAULT_PAGE_SIZES]
const SORT_FIELDS = ['severity', 'first_seen_at'] as const
const SEVERITY_FILTERS = ['critical', 'high']

/** The leak date shown in the list: the breach date when the import gave one. */
function daysSince(date: string): number {
  return Math.ceil((Date.now() - new Date(date).getTime()) / (1000 * 60 * 60 * 24))
}

export default function CredentialsPage() {
  const { t, locale } = useTranslation()
  // Build API filters based on UI filters. Filters live in the URL so a filtered
  // view is shareable and survives reload (matching the findings/assets pages).
  const [statusFilter, setStatusFilterRaw] = useUrlFilter('status', 'all') as [
    StatusFilter,
    (v: StatusFilter) => void,
  ]
  const [sourceFilter, setSourceFilterRaw] = useUrlFilter('source', 'all')
  const [severityFilter, setSeverityFilterRaw] = useUrlFilter('severity', '')
  // Search is server-side (the list and identity endpoints both take it), so it
  // lives in the URL like the other filters and is debounced per keystroke.
  const [searchQuery, setSearchQueryRaw] = useUrlFilter('q', '')
  const debouncedSearch = useSearchQuery(searchQuery).term
  // A filter change returns to page 1.
  const setStatusFilter = (v: StatusFilter) => {
    setStatusFilterRaw(v)
    resetListPage()
  }
  const setSourceFilter = (v: string) => {
    setSourceFilterRaw(v)
    resetListPage()
  }
  const setSeverityFilter = (v: string) => {
    setSeverityFilterRaw(v)
    resetListPage()
  }
  const setSearchQuery = (v: string) => {
    setSearchQueryRaw(v)
    resetListPage()
  }
  // Page, page size and sort are in the URL and go to the API as they are.
  const list = useListParams({
    pageSizes: PAGE_SIZES,
    sortFields: SORT_FIELDS,
    defaultSort: '-first_seen_at',
  })
  // Group by identity is a view of the same leaks ("Group by", in the URL). The
  // old List / By identity tabs map over: ?tab=identity → ?group=identity.
  const [groupParam, setGroupParam] = useUrlFilter('group', '')
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  useEffect(() => {
    if (tabParam === 'identity') setGroupParam('identity')
    if (tabParam) setTabParam('')
  }, [tabParam, setTabParam, setGroupParam])
  const viewMode: 'list' | 'identity' = groupParam === 'identity' ? 'identity' : 'list'

  // Map status filter to API state filter
  const apiStateFilter = useMemo(() => {
    const statusToState: Partial<Record<StatusFilter, string[]>> = {
      active: ['active'],
      completed: ['resolved'],
      inactive: ['accepted', 'false_positive'],
    }
    return statusToState[statusFilter] ?? []
  }, [statusFilter])

  const { data: enums } = useCredentialEnumsApi()
  const sourceOptions = enums?.source_types ?? []
  const sourceLabel = (v: string) => t(`credentials.source.${v}`, v.replace(/_/g, ' '))

  const listFilters = useMemo(
    () => ({
      page: list.page,
      per_page: list.perPage,
      sort: list.sort || undefined,
      state: apiStateFilter.length > 0 ? apiStateFilter : undefined,
      source: sourceFilter !== 'all' ? [sourceFilter] : undefined,
      severity: SEVERITY_FILTERS.includes(severityFilter) ? [severityFilter] : undefined,
      search: debouncedSearch.trim() || undefined,
    }),
    [
      list.page,
      list.perPage,
      list.sort,
      apiStateFilter,
      sourceFilter,
      severityFilter,
      debouncedSearch,
    ]
  )

  // Fetch credentials from API, one server page at a time.
  const {
    data: apiResponse,
    isLoading,
    error: listError,
    mutate,
  } = useCredentialsApi(listFilters, undefined, viewMode === 'list')

  // The strip and the status counts are page-level: the whole credential
  // set the caller may see, whatever the filters. They come from
  // GET /credentials/stats, built on the same scoped filter as the list, so
  // they agree with it; they used to be counted from the first 100 rows of
  // a second list request, wrong past 100 (research/81).
  const { data: credentialStats, isLoading: statsLoading } = useCredentialStatsApi()

  // Fetch identities (grouped by username/email) for identity view
  const { data: identitiesResponse, isLoading: identitiesLoading } = useCredentialIdentitiesApi(
    {
      // Client-side paginated like the credentials table above, over at most
      // 100 identities (the API maximum per page).
      page: 1,
      per_page: 100,
      state: apiStateFilter.length > 0 ? apiStateFilter : undefined,
      search: debouncedSearch.trim() || undefined,
    },
    undefined,
    viewMode === 'identity'
  )

  // Map API data to CredentialLeakRow type for UI compatibility
  const credentials = useMemo(() => {
    if (!apiResponse?.items) return []
    return mapCredentialsToAssets(apiResponse.items)
  }, [apiResponse])
  const total = apiResponse?.total ?? credentials.length

  const stats = useMemo(() => {
    const byState = credentialStats?.by_state ?? {}
    const bySeverity = credentialStats?.by_severity ?? {}
    return {
      total: credentialStats?.total ?? 0,
      active: byState.active ?? 0,
      resolved: byState.resolved ?? 0,
      accepted: byState.accepted ?? 0,
      falsePositive: byState.false_positive ?? 0,
      critical: bySeverity.critical ?? 0,
      high: bySeverity.high ?? 0,
    }
  }, [credentialStats])

  const [selectedCredential, setSelectedCredential] = useState<CredentialLeakRow | null>(null)
  const { can } = usePermissions()
  const canResolve = can(Permission.CredentialsWrite)

  // Status counts from API stats
  const statusCounts = {
    all: stats.total,
    active: stats.active,
    completed: stats.resolved,
    inactive: stats.accepted + stats.falsePositive,
  }
  const statusLabels: Record<string, string> = {
    all: t('credentials.filter.allStatuses', 'All statuses'),
    active: t('credentials.status.active', 'Active'),
    completed: t('credentials.status.resolved', 'Resolved'),
    inactive: t('credentials.status.inactive', 'Inactive'),
  }

  // Headline numbers. The status and severity metrics double as quick filters.
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('credentials.metric.total', 'Total leaks'),
      value: statusCounts.all,
      onClick: () => {
        setStatusFilter('all')
        setSeverityFilter('')
      },
      active: statusFilter === 'all' && !severityFilter,
    },
    {
      key: 'active',
      label: t('credentials.metric.active', 'Active'),
      value: statusCounts.active,
      tone: 'danger',
      onClick: () => setStatusFilter(statusFilter === 'active' ? 'all' : 'active'),
      active: statusFilter === 'active',
    },
    {
      key: 'critical',
      label: t('credentials.metric.critical', 'Critical'),
      value: stats.critical,
      onClick: () => setSeverityFilter(severityFilter === 'critical' ? '' : 'critical'),
      active: severityFilter === 'critical',
    },
    {
      key: 'high',
      label: t('credentials.metric.high', 'High'),
      value: stats.high,
      onClick: () => setSeverityFilter(severityFilter === 'high' ? '' : 'high'),
      active: severityFilter === 'high',
    },
    {
      key: 'resolved',
      label: t('credentials.metric.resolved', 'Resolved'),
      value: statusCounts.completed,
      onClick: () => setStatusFilter(statusFilter === 'completed' ? 'all' : 'completed'),
      active: statusFilter === 'completed',
    },
  ]

  const formatDate = (date: string) => new Date(date).toLocaleDateString(locale)

  // Table columns. No selection column: the page has no bulk actions, and a
  // checkbox that selects rows nothing can act on is a dead control.
  const columns: ColumnDef<CredentialLeakRow>[] = [
    {
      accessorKey: 'name',
      enableSorting: false,
      header: t('credentials.col.credential', 'Credential'),
      cell: ({ row }) => (
        <div className="flex min-w-0 items-center gap-2">
          <KeyRound className="h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0">
            <p className="truncate font-medium">{row.original.name}</p>
            {row.original.description && (
              <p className="truncate text-xs text-muted-foreground">{row.original.description}</p>
            )}
          </div>
        </div>
      ),
    },
    {
      accessorKey: 'metadata.source',
      header: t('credentials.col.source', 'Source'),
      enableSorting: false,
      cell: ({ row }) => (
        <Badge variant="outline">
          {row.original.metadata.source ? sourceLabel(row.original.metadata.source) : '-'}
        </Badge>
      ),
    },
    {
      accessorKey: 'metadata.username',
      header: t('credentials.col.username', 'Username'),
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex items-center gap-1">
          <User className="h-3 w-3 text-muted-foreground" />
          <span className="font-mono text-sm">{row.original.metadata.username || '-'}</span>
        </div>
      ),
    },
    {
      accessorKey: 'metadata.leakDate',
      header: t('credentials.col.leakDate', 'Leak date'),
      enableSorting: false,
      cell: ({ row }) => {
        const date = row.original.metadata.leakDate
        if (!date) return <span className="text-muted-foreground">-</span>
        const isRecent = daysSince(date) <= 30
        return (
          <div className="flex items-center gap-1 tabular-nums">
            <Calendar className="h-3 w-3 text-muted-foreground" />
            <span className={cn(isRecent && 'font-medium text-destructive')}>
              {formatDate(date)}
            </span>
            {isRecent && (
              <Badge variant="destructive" className="ms-1 text-xs">
                {t('credentials.badge.recent', 'Recent')}
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      id: 'first_seen_at',
      accessorKey: 'firstSeen',
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title={t('credentials.col.discovered', 'Discovered')}
        />
      ),
      cell: ({ row }) =>
        row.original.firstSeen ? (
          <span className="tabular-nums">{formatDate(row.original.firstSeen)}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      accessorKey: 'status',
      header: t('credentials.col.status', 'Status'),
      enableSorting: false,
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      id: 'severity',
      accessorFn: (row) => row.metadata.severity,
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('credentials.col.severity', 'Severity')} />
      ),
      cell: ({ row }) => <SeverityBadge severity={asSeverity(row.original.metadata.severity)} />,
    },
    {
      id: 'actions',
      enableSorting: false,
      cell: ({ row }) => {
        const credential = row.original
        return (
          <DataTableRowActions
            actions={[
              {
                label: t('credentials.action.view', 'View details'),
                icon: Eye,
                onClick: () => setSelectedCredential(credential),
              },
              {
                label: t('credentials.action.copyName', 'Copy name'),
                icon: Copy,
                onClick: () => handleCopyCredential(credential),
              },
            ]}
          />
        )
      },
    },
  ]

  // Handlers
  //
  // Read-only page: there is no create, edit or delete endpoint for
  // credentials (owner decision D-17). Credentials arrive through import and
  // sensors; their lifecycle is resolve / accept / false positive. Do not add
  // Add/Edit/Delete controls back until the backend exists.

  const handleCopyCredential = (credential: CredentialLeakRow) => {
    copyToClipboard(credential.name)
    toast.success(t('credentials.toast.nameCopied', 'Credential name copied'))
  }

  // Export every leak matching the current filters (all pages), not just the
  // page on screen.
  const [isExporting, setIsExporting] = useState(false)
  const handleExport = async () => {
    if (isExporting) return
    setIsExporting(true)
    try {
      const items = await fetchAllPages<ApiCredential>(
        (page, per_page) => buildCredentialsEndpoint({ ...listFilters, page, per_page }),
        {
          rowsKey: 'items',
          onTruncated: (loaded) =>
            toast.warning(
              t(
                'credentials.export.truncated',
                'Export limited to the first {count} leaks. Refine the filters to export the rest.',
                { count: loaded.toLocaleString(locale) }
              )
            ),
        }
      )
      exportToCsv(
        mapCredentialsToAssets(items),
        [
          { header: t('credentials.col.credential', 'Credential'), accessor: (c) => c.name },
          {
            header: t('credentials.csv.description', 'Description'),
            accessor: (c) => c.description ?? '',
          },
          { header: t('credentials.col.source', 'Source'), accessor: (c) => c.metadata.source },
          {
            header: t('credentials.col.username', 'Username'),
            accessor: (c) => c.metadata.username,
          },
          {
            header: t('credentials.col.leakDate', 'Leak date'),
            accessor: (c) => c.metadata.leakDate,
          },
          { header: t('credentials.col.discovered', 'Discovered'), accessor: (c) => c.firstSeen },
          { header: t('credentials.col.status', 'Status'), accessor: (c) => c.status },
          {
            header: t('credentials.col.severity', 'Severity'),
            accessor: (c) => c.metadata.severity,
          },
        ],
        'credential-leaks'
      )
    } catch {
      toast.error(t('credentials.export.failed', 'Could not export the credential leaks.'))
    } finally {
      setIsExporting(false)
    }
  }

  const handleMarkResolved = async (credential: CredentialLeakRow) => {
    try {
      await post(`/api/v1/credentials/${credential.id}/resolve`, { notes: '' })
      toast.success(t('credentials.drawer.resolved', 'Credential marked as resolved.'))
      setSelectedCredential(null) // Close sheet after success
      void mutate() // Refresh data after state change
      void invalidateCredentialsCache() // Invalidate all credential caches
    } catch (error) {
      console.error('Error resolving credential:', error)
      toast.error(
        getErrorMessage(
          error,
          t('credentials.drawer.resolveFailed', 'Failed to resolve the credential')
        )
      )
    }
  }

  // Search + status apply to both views (both endpoints take them); the source
  // filter only applies to the list.
  const searchInput = (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <SearchIcon className="absolute start-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        placeholder={t('credentials.search.placeholder', 'Search credentials...')}
        aria-label={t('credentials.search.aria', 'Search credentials')}
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        className="ps-9 pe-9"
      />
      {searchQuery && (
        <Button
          variant="ghost"
          size="sm"
          className="absolute end-1 top-1/2 h-6 w-6 -translate-y-1/2 p-0"
          onClick={() => setSearchQuery('')}
          aria-label={t('credentials.search.clear', 'Clear search')}
        >
          <X className="h-4 w-4" />
        </Button>
      )}
    </div>
  )
  const statusSelect = (
    <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
      <SelectTrigger
        className="h-9 w-auto min-w-36"
        aria-label={t('credentials.filter.status', 'Filter by status')}
      >
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {STATUS_FILTERS.map((value) => (
          <SelectItem key={value} value={value}>
            {statusLabels[value]} ({statusCounts[value as keyof typeof statusCounts] || 0})
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
  const sourceSelect = (
    <Select value={sourceFilter} onValueChange={setSourceFilter}>
      <SelectTrigger
        className="h-9 w-auto min-w-36"
        aria-label={t('credentials.filter.source', 'Filter by source')}
      >
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">{t('credentials.filter.allSources', 'All sources')}</SelectItem>
        {sourceOptions.map((v) => (
          <SelectItem key={v} value={v}>
            {sourceLabel(v)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
  const groupSelect = (
    <Select
      value={viewMode === 'identity' ? 'identity' : 'none'}
      onValueChange={(v) => setGroupParam(v === 'none' ? '' : v)}
    >
      <SelectTrigger
        className="h-9 w-auto gap-2 sm:min-w-36"
        aria-label={t('credentials.group.aria', 'Group credential leaks')}
      >
        <Layers className="h-4 w-4 text-muted-foreground" />
        <span className="sr-only sm:not-sr-only">
          <SelectValue />
        </span>
      </SelectTrigger>
      <SelectContent align="end">
        <SelectItem value="none">{t('credentials.group.none', 'No grouping')}</SelectItem>
        <SelectItem value="identity">{t('credentials.group.identity', 'Identity')}</SelectItem>
      </SelectContent>
    </Select>
  )

  const hasFilters =
    !!searchQuery || statusFilter !== 'all' || sourceFilter !== 'all' || !!severityFilter
  const emptyDescription = hasFilters
    ? t('credentials.empty.filtered', 'Try removing a filter or clearing the search.')
    : t('credentials.empty.none', 'Leaked credentials appear here once imported or discovered.')

  const severityValue = selectedCredential?.metadata.severity
  const leakDate = selectedCredential?.metadata.leakDate

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('credentials.page.title', 'Credential leaks')}
            description={t(
              'credentials.page.description',
              'Leaked passwords, keys and tokens tied to your organisation, from breaches, code and the dark web.'
            )}
          >
            <Button
              variant="outline"
              size="sm"
              onClick={handleExport}
              disabled={!credentials.length || isExporting}
            >
              <Download className="h-4 w-4 sm:me-2" />
              <span className="sr-only sm:not-sr-only">
                {t('credentials.export.label', 'Export')}
              </span>
            </Button>
          </PageHeader>

          <MetricStrip loading={statsLoading} items={metrics} />

          {viewMode === 'identity' ? (
            <CredentialIdentityGroups
              identities={identitiesResponse?.items ?? []}
              isLoading={identitiesLoading && !identitiesResponse}
              columns={columns}
              onRowClick={(c) => setSelectedCredential(c)}
              resetKey={`${debouncedSearch}|${statusFilter}`}
              toolbarStart={
                <>
                  {searchInput}
                  {statusSelect}
                </>
              }
              toolbarEnd={groupSelect}
              emptyMessage={t('credentials.identity.emptyTitle', 'No identities found')}
              emptyDescription={
                searchQuery || statusFilter !== 'all'
                  ? t('credentials.empty.filtered', 'Try removing a filter or clearing the search.')
                  : t(
                      'credentials.identity.emptyNone',
                      'Identities appear here once leaked credentials are imported.'
                    )
              }
            />
          ) : listError && !apiResponse ? (
            <ErrorState
              title={t('credentials.error.list', 'credential leaks')}
              error={listError}
              onRetry={() => void mutate()}
            />
          ) : isLoading ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Skeleton className="h-9 w-72" />
                <Skeleton className="h-9 w-40" />
                <Skeleton className="h-9 w-36" />
              </div>
              <div className="space-y-2 rounded-md border p-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={credentials}
              showSearch={false}
              toolbarStart={
                <>
                  {searchInput}
                  {statusSelect}
                  {sourceSelect}
                </>
              }
              toolbarEnd={groupSelect}
              getRowId={(c) => c.id}
              manualPagination
              rowCount={total}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              pageSizeOptions={PAGE_SIZES}
              sorting={list.sorting}
              onSortingChange={list.setSorting}
              onRowClick={(c) => setSelectedCredential(c)}
              emptyMessage={t('credentials.empty.title', 'No credential leaks found')}
              emptyDescription={emptyDescription}
            />
          )}
        </PageStack>
      </Main>

      {/* Detail Sheet */}
      <AssetDetailSheet
        // The sheet frames the leak (header, classification, tabs); the
        // leak's own fields render in the overview below, not as asset
        // properties, so its details type stays apart from the asset schema.
        asset={selectedCredential as unknown as Asset | null}
        open={!!selectedCredential}
        onOpenChange={(open) => !open && setSelectedCredential(null)}
        icon={KeyRound}
        canEdit={false}
        canDelete={false}
        onEdit={() => undefined}
        onDelete={() => undefined}
        assetTypeName={t('credentials.drawer.type', 'Credential')}
        showFindingsTab={false}
        extraTabs={
          selectedCredential
            ? [
                {
                  value: 'related',
                  label: t('credentials.related.tab', 'Related'),
                  content: (
                    <RelatedExposuresSection
                      credentialId={selectedCredential.id}
                      onSelectCredential={(cred) => {
                        const asset = mapCredentialsToAssets([cred])[0]
                        setSelectedCredential(asset)
                      }}
                    />
                  ),
                },
              ]
            : undefined
        }
        quickActions={
          // Resolving needs the permission the API checks (credentials write).
          selectedCredential?.status === 'active' && canResolve ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                handleMarkResolved(selectedCredential)
                // Sheet will be closed by handleMarkResolved after success
              }}
            >
              <CheckCircle className="me-2 h-4 w-4" />
              {t('credentials.drawer.markResolved', 'Mark resolved')}
            </Button>
          ) : null
        }
        statsContent={
          selectedCredential && (
            <StatsGrid columns={2}>
              <StatCard
                icon={Shield}
                iconBg="bg-muted"
                iconColor="text-muted-foreground"
                label={t('credentials.drawer.severity', 'Severity')}
                value={
                  severityValue ? t(`credentials.severity.${severityValue}`, severityValue) : '-'
                }
              />
              {leakDate && (
                <StatCard
                  icon={Clock}
                  iconBg="bg-muted"
                  iconColor="text-muted-foreground"
                  label={t('credentials.drawer.daysSinceLeak', 'Days since leak')}
                  value={daysSince(leakDate)}
                />
              )}
            </StatsGrid>
          )
        }
        overviewContent={
          selectedCredential && (
            <>
              {/* Secret Value Section */}
              <LeakedSecretField
                credentialId={selectedCredential.id}
                hasSecret={selectedCredential.metadata.hasSecret ?? false}
                masked={selectedCredential.metadata.secretMasked}
                fingerprint={selectedCredential.metadata.secretFingerprint}
                showWarning={selectedCredential.status === 'active'}
              />

              <SectionTitle>{t('credentials.drawer.leakDetails', 'Leak details')}</SectionTitle>
              <MetadataGrid>
                <MetadataRow
                  label={t('credentials.col.source', 'Source')}
                  value={
                    selectedCredential.metadata.source
                      ? sourceLabel(selectedCredential.metadata.source)
                      : undefined
                  }
                />
                <MetadataRow
                  label={t('credentials.col.username', 'Username')}
                  value={selectedCredential.metadata.username}
                />
                <MetadataRow
                  label={t('credentials.drawer.credentialType', 'Credential type')}
                  value={credentialTypeLabel(t, selectedCredential.metadata.credentialType)}
                />
                <MetadataRow
                  label={t('credentials.col.leakDate', 'Leak date')}
                  value={leakDate ? formatDate(leakDate) : '-'}
                />
                <MetadataRow
                  label={t('credentials.col.discovered', 'Discovered')}
                  value={
                    selectedCredential.firstSeen ? formatDate(selectedCredential.firstSeen) : '-'
                  }
                />
                <MetadataRow
                  label={t('credentials.drawer.group', 'Group')}
                  value={
                    selectedCredential.groupName || t('credentials.drawer.ungrouped', 'Ungrouped')
                  }
                />
              </MetadataGrid>
            </>
          )
        }
      />
    </>
  )
}

/** The translated label of an API credential type; an unknown type shows as returned. */
function credentialTypeLabel(t: ReturnType<typeof useTranslation>['t'], type: string): string {
  const known = (CREDENTIAL_TYPES as readonly string[]).includes(type || 'password')
  const value = type || 'password'
  return known ? t(`credentials.type.${value}`, value) : value
}

// ============================================
// IDENTITY ROW COMPONENT
// ============================================

/** API severities are free strings; the shared badge falls back for unknown ones. */
function asSeverity(value: string | undefined): Severity {
  return (value ?? 'none') as Severity
}

/** One leaked credential as a clickable line (identity exposures, related exposures). */
function CredentialLine({
  cred,
  onSelect,
  children,
}: {
  cred: ApiCredential
  onSelect: (cred: ApiCredential) => void
  children?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <button
      type="button"
      className="w-full px-3 py-2.5 text-start transition-colors hover:bg-muted/50"
      onClick={() => onSelect(cred)}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <KeyRound className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="truncate text-sm font-medium">{cred.identifier}</span>
          <Badge variant="outline" className="text-xs">
            {credentialTypeLabel(t, cred.credential_type ?? '')}
          </Badge>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge variant="outline" className="text-xs">
            {cred.source ? t(`credentials.source.${cred.source}`, cred.source) : ''}
          </Badge>
          <SeverityBadge severity={asSeverity(cred.severity)} />
        </div>
      </div>
      {children}
    </button>
  )
}

// ============================================
// RELATED EXPOSURES SECTION COMPONENT
// ============================================

interface RelatedExposuresSectionProps {
  credentialId: string
  onSelectCredential: (cred: ApiCredential) => void
}

function RelatedExposuresSection({
  credentialId,
  onSelectCredential,
}: RelatedExposuresSectionProps) {
  const { t } = useTranslation()
  const {
    data: relatedCredentials,
    isLoading,
    error,
    mutate,
  } = useRelatedCredentialsApi(credentialId)

  if (isLoading) {
    return (
      <div className="mt-6">
        <SectionTitle>{t('credentials.related.title', 'Related exposures')}</SectionTitle>
        <div className="space-y-2">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      </div>
    )
  }

  if (error && !relatedCredentials) {
    return (
      <div className="mt-6">
        <ErrorState
          title={t('credentials.error.related', 'related leaks')}
          error={error}
          onRetry={() => void mutate()}
        />
      </div>
    )
  }

  if (!relatedCredentials || relatedCredentials.length === 0) {
    return (
      <div className="mt-6">
        <SectionTitle>{t('credentials.related.title', 'Related exposures')}</SectionTitle>
        <p className="text-sm text-muted-foreground">
          {t('credentials.related.empty', 'No other leaks for this identity.')}
        </p>
      </div>
    )
  }

  return (
    <div className="mt-6">
      <SectionTitle>
        {t('credentials.related.title', 'Related exposures')} ({relatedCredentials.length})
      </SectionTitle>
      <p className="mb-3 text-sm text-muted-foreground">
        {t('credentials.related.hint', 'Other credentials leaked for the same identity')}
      </p>
      <div className="divide-y rounded-md border">
        {relatedCredentials.map((cred) => (
          <CredentialLine key={cred.id} cred={cred} onSelect={onSelectCredential} />
        ))}
      </div>
    </div>
  )
}
