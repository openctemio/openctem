'use client'

/**
 * /credentials: leaked credentials tied to the organization, one row per
 * leak, or grouped by identity. Filters, search, sort, page and grouping live
 * in the URL; the server filters and counts within the caller's data scope.
 * The list follows the shared list pattern (web/docs/ui-style-contract.md,
 * "Lists"). Masked values stay masked: rows and cards never carry the secret.
 */

import { useState, useMemo, useEffect, useCallback, type ReactNode } from 'react'
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
  EmptyState,
  FilterSheet,
  MetricStrip,
  type MetricStripItem,
  PageStack,
} from '@/features/shared'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import {
  ListCount,
  ListTitleRow,
  ListViewChanged,
} from '@/features/shared/components/list-title-row'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { AddFilterPanel } from '@/features/shared/components/add-filter-panel'
import { ToolbarSlot } from '@/features/shared/components/toolbar-slot'
import {
  AssetDetailSheet,
  StatCard,
  StatsGrid,
  MetadataGrid,
  MetadataRow,
  SectionTitle,
} from '@/features/assets'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
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
  Eye,
  Download,
  Shield,
  Clock,
  CheckCircle,
  Copy,
  Layers,
  MoreHorizontal,
  RefreshCw,
} from 'lucide-react'
import type { Asset } from '@/features/assets'
import type { CredentialLeakRow } from '@/features/credentials/lib'
import {
  useCredentialsApi,
  useCredentialIdentitiesApi,
  useCredentialStatsApi,
  useRelatedCredentialsApi,
  useCredentialEnumsApi,
  buildCredentialsEndpoint,
  mapCredentialsToAssets,
  CredentialIdentityGroups,
  invalidateCredentialsCache,
  LeakedSecretField,
} from '@/features/credentials'
import {
  asSeverity,
  CREDENTIAL_SEVERITIES,
  CREDENTIAL_STATUSES,
  CREDENTIAL_STATUS_STATES,
  CredentialFacetsPanel,
  type CredentialFilterName,
  CredentialPhoneCard,
  credentialSeverityLabel,
  credentialSourceLabel,
  type CredentialStatus,
  credentialStatusLabel,
  credentialTypeLabel,
  daysSince,
  LeakDate,
  listValues,
} from '@/features/credentials/components/credential-list-parts'
import { getErrorMessage } from '@/lib/api/error-handler'
import { accessStateOf } from '@/lib/api/access-state'
import type { ApiCredential } from '@/features/credentials/api/credential-api.types'
import { copyToClipboard } from '@/lib/clipboard'
import { exportToCsv } from '@/hooks/use-csv-export'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { useListParams, DEFAULT_PAGE_SIZES } from '@/hooks/use-list-params'
import { useTranslation } from '@/context/i18n-provider'
import { Skeleton } from '@/components/ui/skeleton'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { Permission, usePermissions } from '@/lib/permissions'

const PAGE_SIZES = [...DEFAULT_PAGE_SIZES]
const SORT_FIELDS = ['severity', 'first_seen_at'] as const
const DEFAULT_SORT = '-first_seen_at'
const FILTER_DEFAULTS: Record<CredentialFilterName, string> = {
  status: '',
  source: '',
  severity: '',
}
const FILTER_NAMES = Object.keys(FILTER_DEFAULTS) as CredentialFilterName[]
const PANEL_ID = 'credential-filters'

/**
 * Columns that step aside while the table frame is narrower than this (px);
 * they stay under Display > Columns. Frame = screen - 326 at 1440 and 1280.
 */
const CREDENTIAL_HIDE_BELOW = { username: 1060, discovered: 900, source: 760 } as const

/**
 * Column widths (px). Every column but the credential has a fixed width, so
 * the credential takes what is left (at least `name`). Source holds
 * "Underground forum" ("Diễn đàn ngầm"); the leak date holds a date and
 * "Recent" ("Gần đây").
 */
const CREDENTIAL_WIDTH = {
  name: 220,
  source: 152,
  username: 200,
  leakDate: 160,
  discovered: 112,
  status: 112,
  severity: 112,
} as const

export default function CredentialsPage() {
  const { t, locale } = useTranslation()
  // Page, size, sort, search and the filters are in the URL and go to the
  // API as they are. Status, source and severity take several values each.
  const list = useListParams<CredentialFilterName>({
    pageSizes: PAGE_SIZES,
    sortFields: SORT_FIELDS,
    defaultSort: DEFAULT_SORT,
    filters: { ...FILTER_DEFAULTS },
  })
  const statuses = listValues(list.filters.status, CREDENTIAL_STATUSES) as CredentialStatus[]
  const severities = listValues(list.filters.severity, CREDENTIAL_SEVERITIES)
  const sources = listValues(list.filters.source)
  // Group by identity is a view of the same leaks ("Group by", in the URL). The
  // old List / By identity tabs map over: ?tab=identity → ?group=identity.
  const [groupParam, setGroupParam] = useUrlFilter('group', '')
  const [tabParam, setTabParam] = useUrlFilter('tab', '')
  useEffect(() => {
    if (tabParam === 'identity') setGroupParam('identity')
    if (tabParam) setTabParam('')
  }, [tabParam, setTabParam, setGroupParam])
  const viewMode: 'list' | 'identity' = groupParam === 'identity' ? 'identity' : 'list'
  const identityView = viewMode === 'identity'

  // The statuses' API states.
  const apiStateFilter = useMemo(
    () => statuses.flatMap((s) => CREDENTIAL_STATUS_STATES[s]),
    // statuses is derived from the URL value each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [list.filters.status]
  )

  const { data: enums } = useCredentialEnumsApi()
  const sourceOptions = enums?.source_types ?? []
  const sourceLabel = (v: string) => credentialSourceLabel(t, v)

  const searchTerm = list.searchTerm.trim()
  const listFilters = useMemo(
    () => ({
      page: list.page,
      per_page: list.perPage,
      sort: list.sort || undefined,
      state: apiStateFilter.length > 0 ? apiStateFilter : undefined,
      source: sources.length > 0 ? sources : undefined,
      severity: severities.length > 0 ? severities : undefined,
      search: searchTerm || undefined,
    }),
    // sources and severities are derived from the URL values.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      list.page,
      list.perPage,
      list.sort,
      apiStateFilter,
      list.filters.source,
      list.filters.severity,
      searchTerm,
    ]
  )

  // Fetch credentials from API, one server page at a time.
  const {
    data: apiResponse,
    isLoading,
    isValidating,
    error: listError,
    mutate,
  } = useCredentialsApi(listFilters, undefined, viewMode === 'list')

  // The strip and the status counts are page-level: the whole credential
  // set the caller may see, whatever the filters. They come from
  // GET /credentials/stats, built on the same scoped filter as the list, so
  // they agree with it; they used to be counted from the first 100 rows of
  // a second list request, wrong past 100 (research/81).
  const {
    data: credentialStats,
    isLoading: statsLoading,
    mutate: mutateStats,
  } = useCredentialStatsApi()

  // Fetch identities (grouped by username/email) for identity view
  const {
    data: identitiesResponse,
    isLoading: identitiesLoading,
    isValidating: identitiesValidating,
    error: identitiesError,
    mutate: mutateIdentities,
  } = useCredentialIdentitiesApi(
    {
      // Client-side paginated like the credentials table above, over at most
      // 100 identities (the API maximum per page).
      page: 1,
      per_page: 100,
      state: apiStateFilter.length > 0 ? apiStateFilter : undefined,
      search: searchTerm || undefined,
    },
    undefined,
    identityView
  )

  // Map API data to CredentialLeakRow type for UI compatibility
  const credentials = useMemo(() => {
    if (!apiResponse?.items) return []
    return mapCredentialsToAssets(apiResponse.items)
  }, [apiResponse])
  const identities = identitiesResponse?.items ?? []
  const total = identityView ? identities.length : (apiResponse?.total ?? credentials.length)
  // When the rows on screen were read: on the first answer and at the end of
  // each re-read (booleans, so a new response object alone re-renders nothing).
  const [readAt, setReadAt] = useState<Date | undefined>(undefined)
  const answered = identityView ? !!identitiesResponse : !!apiResponse
  const reading = identityView ? !!identitiesValidating : !!isValidating
  useEffect(() => {
    if (answered && !reading) setReadAt(new Date())
  }, [answered, reading])

  const stats = useMemo(() => {
    const byState = credentialStats?.by_state ?? {}
    const bySeverity = credentialStats?.by_severity ?? {}
    return {
      total: credentialStats?.total ?? 0,
      active: byState.active ?? 0,
      resolved: byState.resolved ?? 0,
      critical: bySeverity.critical ?? 0,
      high: bySeverity.high ?? 0,
    }
  }, [credentialStats])

  const [selectedCredential, setSelectedCredential] = useState<CredentialLeakRow | null>(null)
  const { can } = usePermissions()
  const canResolve = can(Permission.CredentialsWrite)

  const { setFilter, setSearch } = list
  const only = (name: CredentialFilterName, value: string) =>
    list.filters[name] === value ? setFilter(name, '') : setFilter(name, value)

  // Headline numbers. The status and severity metrics double as quick filters.
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('credentials.metric.total', 'Total leaks'),
      value: stats.total,
      onClick: () => {
        setFilter('status', '')
        setFilter('severity', '')
      },
      active: !list.filters.status && !list.filters.severity,
    },
    {
      key: 'active',
      label: t('credentials.metric.active', 'Active'),
      value: stats.active,
      tone: 'danger',
      onClick: () => only('status', 'active'),
      active: list.filters.status === 'active',
    },
    {
      key: 'critical',
      label: t('credentials.metric.critical', 'Critical'),
      value: stats.critical,
      onClick: () => only('severity', 'critical'),
      active: list.filters.severity === 'critical',
    },
    {
      key: 'high',
      label: t('credentials.metric.high', 'High'),
      value: stats.high,
      onClick: () => only('severity', 'high'),
      active: list.filters.severity === 'high',
    },
    {
      key: 'resolved',
      label: t('credentials.metric.resolved', 'Resolved'),
      value: stats.resolved,
      onClick: () => only('status', 'completed'),
      active: list.filters.status === 'completed',
    },
  ]

  const formatDate = (date: string) => new Date(date).toLocaleDateString(locale)

  // One-line rows. No selection column: the page has no bulk actions, and a
  // checkbox that selects rows nothing can act on is a dead control. A row
  // opens its sheet; the row menu's View details does the same from the
  // keyboard.
  const columns: ColumnDef<CredentialLeakRow>[] = [
    {
      id: 'name',
      accessorKey: 'name',
      enableSorting: false,
      enableHiding: false,
      meta: {
        kind: 'name',
        pin: 'start',
        minWidth: CREDENTIAL_WIDTH.name,
        label: t('credentials.col.credential', 'Credential'),
      },
      header: t('credentials.col.credential', 'Credential'),
      cell: ({ row }) => {
        const name = toDisplayText(row.original.name, 200)
        const type = credentialTypeLabel(t, row.original.metadata.credentialType)
        return (
          // The identifier, then its type where the cell has room for it.
          <span
            className="@container flex min-w-0 items-center gap-2 whitespace-nowrap"
            title={`${name} (${type})`}
          >
            <span className="min-w-0 truncate font-medium">
              {name || <span className="text-muted-foreground">—</span>}
            </span>
            <span className="hidden min-w-0 shrink-0 truncate text-meta text-muted-foreground @[16rem]:inline">
              {type}
            </span>
          </span>
        )
      },
    },
    {
      id: 'source',
      accessorKey: 'metadata.source',
      enableSorting: false,
      meta: {
        kind: 'text',
        width: CREDENTIAL_WIDTH.source,
        hideBelow: CREDENTIAL_HIDE_BELOW.source,
        label: t('credentials.col.source', 'Source'),
      },
      header: t('credentials.col.source', 'Source'),
      cell: ({ row }) => (
        <span className="block truncate">
          {row.original.metadata.source ? (
            sourceLabel(row.original.metadata.source)
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </span>
      ),
    },
    {
      id: 'username',
      accessorKey: 'metadata.username',
      enableSorting: false,
      meta: {
        kind: 'text',
        width: CREDENTIAL_WIDTH.username,
        hideBelow: CREDENTIAL_HIDE_BELOW.username,
        label: t('credentials.col.username', 'Username'),
      },
      header: t('credentials.col.username', 'Username'),
      cell: ({ row }) => {
        const user = toDisplayText(row.original.metadata.username, 200)
        return (
          <span className="block truncate" title={user}>
            {user || <span className="text-muted-foreground">—</span>}
          </span>
        )
      },
    },
    {
      id: 'leak_date',
      accessorKey: 'metadata.leakDate',
      enableSorting: false,
      meta: {
        kind: 'date',
        width: CREDENTIAL_WIDTH.leakDate,
        label: t('credentials.col.leakDate', 'Leak date'),
      },
      header: t('credentials.col.leakDate', 'Leak date'),
      cell: ({ row }) => <LeakDate date={row.original.metadata.leakDate} />,
    },
    {
      id: 'first_seen_at',
      accessorKey: 'firstSeen',
      meta: {
        kind: 'date',
        width: CREDENTIAL_WIDTH.discovered,
        hideBelow: CREDENTIAL_HIDE_BELOW.discovered,
        label: t('credentials.col.discovered', 'Discovered'),
      },
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
          <span className="text-muted-foreground">—</span>
        ),
    },
    {
      id: 'status',
      accessorKey: 'status',
      enableSorting: false,
      meta: {
        kind: 'status',
        width: CREDENTIAL_WIDTH.status,
        label: t('credentials.col.status', 'Status'),
      },
      header: t('credentials.col.status', 'Status'),
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      id: 'severity',
      accessorFn: (row) => row.metadata.severity,
      meta: {
        kind: 'severity',
        width: CREDENTIAL_WIDTH.severity,
        label: t('credentials.col.severity', 'Severity'),
      },
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title={t('credentials.col.severity', 'Severity')} />
      ),
      cell: ({ row }) => <SeverityBadge severity={asSeverity(row.original.metadata.severity)} />,
    },
    {
      id: 'actions',
      enableSorting: false,
      enableHiding: false,
      meta: { kind: 'actions' },
      cell: ({ row }) => {
        const credential = row.original
        return (
          <DataTableRowActions
            title={credential.name}
            label={t('common.rowActions.actionsFor', 'Actions for {name}', {
              name: credential.name,
            })}
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
  const [confirmExport, setConfirmExport] = useState(false)
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

  // The filters that apply to the view on screen: the identities endpoint
  // takes the search and the status only.
  const appliedFilters: CredentialFilterName[] = identityView ? ['status'] : FILTER_NAMES
  // The values each filter really sends (an unknown status or severity in a
  // link is dropped, so it gets no chip either).
  const filterValues: Record<CredentialFilterName, string[]> = {
    status: statuses,
    severity: severities,
    source: sources,
  }
  const activeCount = appliedFilters.reduce((n, name) => n + filterValues[name].length, 0)
  const narrowed = activeCount > 0 || list.q !== ''
  const viewChanged = narrowed || list.sort !== DEFAULT_SORT || identityView

  const clearFilters = useCallback(() => {
    setSearch('')
    for (const name of FILTER_NAMES) setFilter(name, '')
  }, [setSearch, setFilter])
  // Back to the list as it opens: no filter, no search, no grouping, the
  // default order (the page size stays).
  const backToList = useCallback(() => {
    const next = new URLSearchParams()
    const perPage = new URLSearchParams(window.location.search).get('per_page')
    if (perPage) next.set('per_page', perPage)
    replaceUrlSearch(next)
  }, [])

  // One chip per filter, its values joined.
  const chipText: Record<CredentialFilterName, (values: string[]) => string> = {
    status: (v) =>
      t('credentials.chip.status', 'Status: {values}', {
        values: v.map((s) => credentialStatusLabel(t, s as CredentialStatus)).join(', '),
      }),
    severity: (v) =>
      t('credentials.chip.severity', 'Severity: {values}', {
        values: v.map((s) => credentialSeverityLabel(t, s)).join(', '),
      }),
    source: (v) =>
      t('credentials.chip.source', 'Source: {values}', {
        values: v.map(sourceLabel).join(', '),
      }),
  }
  const chipList = appliedFilters
    .filter((name) => filterValues[name].length > 0)
    .map((name) => ({
      key: name,
      text: toDisplayText(chipText[name](filterValues[name]), 120),
      clear: () => setFilter(name, ''),
    }))
  const chipsRow =
    chipList.length > 0 ? (
      <FilterChipsRow
        data-testid="credential-filter-chips"
        label={t('common.filterChips.label', 'Active filters')}
        chips={chipList.map((c) => (
          <RemovableFilterChip
            key={c.key}
            text={c.text}
            onRemove={c.clear}
            removeLabel={t('credentials.chip.remove', 'Remove filter {filter}', {
              filter: c.text,
            })}
          />
        ))}
        onClearAll={chipList.length > 1 ? clearFilters : undefined}
      />
    ) : undefined

  const [sheetOpen, setSheetOpen] = useState(false)
  const groupValue: 'none' | 'identity' = identityView ? 'identity' : 'none'
  const setGroup = (v: 'none' | 'identity') => setGroupParam(v === 'none' ? '' : v)
  const facets = (withGroup: boolean) => (
    <CredentialFacetsPanel
      filters={list.filters}
      sources={sourceOptions}
      activeCount={activeCount}
      identityView={identityView}
      onChange={setFilter}
      onClearAll={clearFilters}
      group={withGroup ? { value: groupValue, onChange: setGroup } : undefined}
    />
  )

  const groupLabels = [
    t('credentials.group.none', 'No grouping'),
    t('credentials.group.identity', 'Identity'),
  ]
  const groupText = groupLabels[identityView ? 1 : 0]
  // Group sits at the toolbar's end from 768 px; on a phone it is in the
  // Filters sheet, so the toolbar's second line holds only the chips.
  const groupSelect = (
    <Select value={groupValue} onValueChange={(v) => setGroup(v as 'none' | 'identity')}>
      <SelectTrigger
        iconOnlyBelow="@5xl/toolbar"
        className="w-auto gap-2 max-md:hidden"
        aria-label={t('credentials.group.aria', 'Group credential leaks')}
        title={groupText}
      >
        <Layers className="h-4 w-4 text-muted-foreground" aria-hidden />
        {/* One width whatever the grouping: sized by every label. */}
        <span className="sr-only @5xl/toolbar:not-sr-only group-data-[fold=true]/toolbar:sr-only">
          <ToolbarSlot options={groupLabels} className="max-w-40">
            <SelectValue />
          </ToolbarSlot>
        </span>
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="none">{groupLabels[0]}</SelectItem>
        <SelectItem value="identity">{groupLabels[1]}</SelectItem>
      </SelectContent>
    </Select>
  )

  // Title row: the view, its count once, Modified + Reset; Refresh, Export
  // and More at the end. Under 42rem of row width (and on a phone) Reset
  // and Export fold into More.
  const viewTitle = t('credentials.list.viewAll', 'All credential leaks')
  const refreshLabel = t('credentials.list.refresh', 'Refresh')
  const activeValidating = identityView ? false : isValidating && !isLoading
  const refresh = () => {
    void mutateStats()
    void (identityView ? mutateIdentities() : mutate())
  }
  const refreshButton = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="outline"
          size="icon"
          onClick={refresh}
          disabled={activeValidating}
          aria-label={refreshLabel}
        >
          <RefreshCw
            className={cn('h-4 w-4', activeValidating && 'animate-spin motion-reduce:animate-none')}
            aria-hidden
          />
        </Button>
      </TooltipTrigger>
      <TooltipContent>{refreshLabel}</TooltipContent>
    </Tooltip>
  )
  const exportLabel = t('credentials.export.label', 'Export')
  // Export writes the list's rows; grouped by identity there are none loaded.
  const exportBlocked = identityView
    ? t('credentials.export.listOnly', 'Export works on the ungrouped list')
    : !credentials.length
      ? t('credentials.export.nothing', 'No leaks to export')
      : isExporting
        ? t('credentials.export.running', 'Exporting…')
        : undefined
  const moreItems: ActionMenuEntry[] = [
    ...(viewChanged
      ? [{ id: 'view-reset', label: t('common.listView.reset', 'Reset'), onSelect: backToList }]
      : []),
    {
      id: 'export',
      label: exportLabel,
      section: 'io',
      disabledReason: exportBlocked,
      onSelect: () => setConfirmExport(true),
    },
  ]
  const narrowMore = (
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
  )
  const listLoading = identityView ? identitiesLoading && !identitiesResponse : isLoading
  const titleRow = (
    <ListTitleRow
      data-testid="credentials-title-row"
      className="@container/actions"
      title={viewTitle}
      count={
        <ListCount
          total={total}
          loading={listLoading}
          label={
            identityView
              ? t(
                  'credentials.list.totalIdentities',
                  '{count, plural, one {# identity} other {# identities}}',
                  { count: total }
                )
              : t('credentials.list.total', '{count, plural, one {# leak} other {# leaks}}', {
                  count: total,
                })
          }
        />
      }
      start={
        <ListViewChanged
          changed={viewChanged}
          // On a row under 42rem Reset is in the row's More.
          actionsClassName="hidden @2xl/actions:flex"
          onReset={backToList}
        />
      }
    >
      {refreshButton}
      <Button
        variant="outline"
        size="sm"
        className="hidden @2xl/actions:inline-flex"
        onClick={() => setConfirmExport(true)}
        disabled={!!exportBlocked}
        title={exportBlocked}
      >
        <Download aria-hidden />
        {exportLabel}
      </Button>
      <div className="@2xl/actions:hidden">{narrowMore}</div>
    </ListTitleRow>
  )

  const activeError = identityView ? identitiesError : listError
  const noAccess = accessStateOf(activeError) === 'no_access'
  const hasRows = identityView ? !!identitiesResponse : !!apiResponse
  const firstRun = hasRows && !activeError && total === 0 && !narrowed

  const search = {
    value: list.q,
    onChange: setSearch,
    placeholder: t('credentials.search.placeholder', 'Search credentials…'),
    label: t('credentials.search.aria', 'Search credentials'),
  }
  const filtersLabel = t('credentials.filtersLabel', 'Credential filters')
  // The table's shared parts, the same in both views.
  const tableProps = {
    showSearch: false,
    search,
    // One filter entry per width: Add filter from 768, this button (joined to
    // the search field) on a phone, where it opens the sheet.
    filterToggle: {
      open: false,
      onToggle: () => setSheetOpen(true),
      onOpenSheet: () => setSheetOpen(true),
      activeCount,
      controlsId: PANEL_ID,
      label: filtersLabel,
      sheetOnly: true,
    },
    toolbarStart: <AddFilterPanel>{facets(false)}</AddFilterPanel>,
    toolbarEnd: groupSelect,
    toolbarBelow: chipsRow,
    // A first run has nothing to search, filter or arrange.
    showToolbar: !firstRun,
    staleAt: readAt,
    onRefresh: refresh,
    onRowClick: (c: CredentialLeakRow) => setSelectedCredential(c),
    mobileRow: (c: CredentialLeakRow) => (
      <CredentialPhoneCard item={c} onOpen={() => setSelectedCredential(c)} />
    ),
    isFiltered: narrowed,
    onClearFilters: clearFilters,
    emptyState: {
      nothingYet: (
        <EmptyState
          icon={KeyRound}
          title={t('credentials.empty.title', 'No credential leaks found')}
          description={t(
            'credentials.empty.none',
            'Leaked credentials appear here once imported or discovered.'
          )}
        />
      ),
      noMatch: {
        title: identityView
          ? t('credentials.identity.emptyTitle', 'No identities found')
          : t('credentials.noMatch', 'No leaks match these filters'),
        hint: t('credentials.empty.filtered', 'Try removing a filter or clearing the search.'),
      },
    },
  }

  const severityValue = selectedCredential?.metadata.severity
  const leakDate = selectedCredential?.metadata.leakDate

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('credentials.page.title', 'Credential leaks')}
            // On a phone the list comes first: the description is read out
            // but not drawn, and the tiles follow the list.
            description={
              <span className="max-md:sr-only">
                {t(
                  'credentials.page.description',
                  'Leaked passwords, keys and tokens tied to your organization, from breaches, code and the dark web.'
                )}
              </span>
            }
          />

          <MetricStrip
            loading={statsLoading && !credentialStats}
            items={metrics}
            className="max-md:order-last"
          />
          {titleRow}

          {noAccess ? (
            <NoAccessState title={t('credentials.error.list', 'credential leaks')} />
          ) : identityView ? (
            <CredentialIdentityGroups
              identities={identities}
              isLoading={identitiesLoading && !identitiesResponse}
              columns={columns}
              onRowClick={(c) => setSelectedCredential(c)}
              resetKey={`${searchTerm}|${list.filters.status}`}
              search={search}
              emptyMessage={t('credentials.identity.emptyTitle', 'No identities found')}
              error={identitiesError && !identitiesResponse ? identitiesError : undefined}
              onRetry={() => void mutateIdentities()}
              errorTitle={t('credentials.error.identities', 'credential identities')}
              tableProps={{
                ...tableProps,
                emptyState: {
                  ...tableProps.emptyState,
                  nothingYet: (
                    <EmptyState
                      icon={KeyRound}
                      title={t('credentials.identity.emptyTitle', 'No identities found')}
                      description={t(
                        'credentials.identity.emptyNone',
                        'Identities appear here once leaked credentials are imported.'
                      )}
                    />
                  ),
                },
              }}
            />
          ) : (
            <DataTable
              columns={columns}
              data={credentials}
              {...tableProps}
              error={listError && !apiResponse ? listError : undefined}
              onRetry={() => void mutate()}
              errorTitle={t('credentials.error.list', 'credential leaks')}
              getRowId={(c) => c.id}
              manualPagination
              rowCount={total}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              pageSize={list.perPage}
              pageSizeOptions={PAGE_SIZES}
              sorting={list.sorting}
              onSortingChange={list.setSorting}
              isLoading={isLoading && !apiResponse}
              isRefreshing={activeValidating}
              refreshingLabel={t('credentials.list.refreshing', 'Refreshing credential leaks')}
              refreshFailed={!!listError && !!apiResponse}
              paginationNoun={t('credentials.list.noun', 'leaks')}
            />
          )}

          <FilterSheet open={sheetOpen} onOpenChange={setSheetOpen} title={filtersLabel}>
            {facets(true)}
          </FilterSheet>
        </PageStack>
      </Main>

      <ConfirmDialog
        open={confirmExport}
        onOpenChange={setConfirmExport}
        title={t('credentials.export.confirmTitle', 'Export the leaked credentials?')}
        desc={t(
          'credentials.export.confirmDesc',
          'The CSV lists every leak that matches the current filters with usernames, sources and leak dates. It is personal data about leaked accounts and leaves the console unprotected, so store it as you would the leaks themselves.'
        )}
        confirmText={t('credentials.export.confirmButton', 'Export CSV')}
        isLoading={isExporting}
        handleConfirm={async () => {
          setConfirmExport(false)
          await handleExport()
        }}
      />

      {/* Detail Sheet */}
      <AssetDetailSheet
        // The sheet frames the leak (header, classification, tabs); the
        // leak's own fields render in the overview below, not as asset
        // properties, so its details type stays apart from the asset schema.
        asset={selectedCredential as unknown as Asset | null}
        open={!!selectedCredential}
        onOpenChange={(open) => !open && setSelectedCredential(null)}
        icon={KeyRound}
        // A leak row is not an inventory asset: its id answers 404 on every
        // per-asset endpoint, so the sheet must not ask them.
        assetBacked={false}
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
