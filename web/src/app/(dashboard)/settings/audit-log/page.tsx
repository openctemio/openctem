'use client'

import { useState, useMemo, useCallback } from 'react'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  MetricStrip,
  SeverityBadge,
  DetailCopyId,
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Search as SearchIcon, RefreshCw, AlertCircle, ShieldX, Copy } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import {
  useAuditLogs,
  toAuditApiPage,
  useAuditStats,
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
import { useDebounce } from '@/hooks/use-debounce'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useListParams } from '@/hooks/use-list-params'

const PAGE_SIZES = [10, 20, 30, 50, 100]
const SORTABLE = ['logged_at', 'action', 'resource_type', 'result', 'severity']
const RESULT_OPTIONS: AuditResult[] = ['success', 'failure', 'denied']
const SEVERITY_OPTIONS: AuditSeverity[] = ['info', 'low', 'medium', 'high', 'critical']

// Helper functions
const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

const formatTime = (dateString: string) => {
  return new Date(dateString).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  })
}

const formatRelativeTime = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return formatDate(dateString)
}

/** Result as a token-coloured badge: only a problem (failure / denied) is red. */
function ResultBadge({ result }: { result: AuditResult }) {
  const label = RESULT_DISPLAY[result]?.label ?? result
  if (result === 'failure') return <Badge variant="destructive">{label}</Badge>
  if (result === 'denied')
    return (
      <Badge variant="outline" className="border-destructive/40 text-destructive">
        {label}
      </Badge>
    )
  return <Badge variant="secondary">{label}</Badge>
}

export default function AuditLogPage() {
  // Permission check
  const hasAuditPermission = useHasPermission(Permission.AuditRead)

  // The whole view lives in the URL so a filtered slice of the log can be shared.
  const [searchTerm, setSearchTerm] = useUrlFilter('q', '')
  const [resultParam, setResultParam] = useUrlFilter('result', 'all')
  const [severityParam, setSeverityParam] = useUrlFilter('severity', 'all')
  const [hideSystemParam, setHideSystemParam] = useUrlFilter('hide_system', 'false')
  const [sortParam, setSortParam] = useUrlFilter('sort', '')
  const list = useListParams({ pageSizes: PAGE_SIZES, defaultPageSize: 20 })
  const { pagination, setPagination, setPage } = list
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null)

  const debouncedSearch = useDebounce(searchTerm, 300)

  // `sort=field:dir` in the URL ↔ the table's sorting state.
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

  const resultFilter = RESULT_OPTIONS.includes(resultParam as AuditResult)
    ? (resultParam as AuditResult)
    : undefined
  const severityFilter = SEVERITY_OPTIONS.includes(severityParam as AuditSeverity)
    ? (severityParam as AuditSeverity)
    : undefined
  const hideSystem = hideSystemParam === 'true'

  // Build API filters. The API pages are 1-based; the table is 0-based.
  const activeFilters = useMemo<AuditLogFilters>(
    () => ({
      page: toAuditApiPage(pagination.pageIndex),
      per_page: pagination.pageSize,
      search: debouncedSearch || undefined,
      result: resultFilter ? [resultFilter] : undefined,
      severity: severityFilter ? [severityFilter] : undefined,
      exclude_system: hideSystem || undefined,
      sort_by: sorting[0]?.id,
      sort_order: sorting[0] ? (sorting[0].desc ? 'desc' : 'asc') : undefined,
    }),
    [pagination, debouncedSearch, resultFilter, severityFilter, hideSystem, sorting]
  )

  // Fetch data (tenant is extracted from JWT token by backend)
  // Only fetch if user has permission
  const { logs, total, isLoading, isError, error, mutate } = useAuditLogs(
    hasAuditPermission ? activeFilters : undefined
  )
  const { stats, isLoading: statsLoading } = useAuditStats()

  const columns = useMemo<ColumnDef<AuditLog>[]>(
    () => [
      {
        id: 'logged_at',
        accessorKey: 'timestamp',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Time" />,
        cell: ({ row }) => (
          <div className="flex flex-col whitespace-nowrap">
            <span className="text-sm font-medium">
              {formatRelativeTime(row.original.timestamp)}
            </span>
            <span className="text-xs text-muted-foreground">
              {formatTime(row.original.timestamp)}
            </span>
          </div>
        ),
      },
      {
        id: 'action',
        accessorKey: 'action',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Action" />,
        cell: ({ row }) => <span className="text-sm">{formatAction(row.original.action)}</span>,
      },
      {
        id: 'actor',
        header: 'Actor',
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <Avatar className="h-7 w-7">
              <AvatarFallback className="text-xs">
                {row.original.actor_email?.substring(0, 2).toUpperCase() || '?'}
              </AvatarFallback>
            </Avatar>
            <span className="text-sm truncate max-w-[180px]">
              {row.original.actor_email || 'System'}
            </span>
          </div>
        ),
      },
      {
        id: 'resource_type',
        accessorKey: 'resource_type',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Resource" />,
        cell: ({ row }) => (
          <div className="flex flex-col">
            <span className="text-sm">
              {row.original.resource_name || row.original.resource_id}
            </span>
            <span className="text-xs text-muted-foreground">
              {humanizeIdentifier(canonicalAuditResourceType(row.original.resource_type))}
            </span>
          </div>
        ),
      },
      {
        id: 'result',
        accessorKey: 'result',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Result" />,
        cell: ({ row }) => <ResultBadge result={row.original.result} />,
      },
      {
        id: 'severity',
        accessorKey: 'severity',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Severity" />,
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
    ],
    []
  )

  // Access denied page
  if (!hasAuditPermission) {
    return (
      <Main>
        <PageHeader title="Audit log" description="Activity history and security events." />
        <EmptyState
          className="mt-5"
          icon={ShieldX}
          title="Access denied"
          description="You don't have permission to view audit logs. Ask your administrator for access."
        />
      </Main>
    )
  }

  const activeFiltersCount = [resultFilter, severityFilter, hideSystem, searchTerm].filter(
    Boolean
  ).length

  const clearFilters = () => {
    setSearchTerm('')
    setResultParam('all')
    setSeverityParam('all')
    setHideSystemParam('false')
    setPage(1)
  }

  const toolbarStart = (
    <>
      <div className="relative min-w-0 flex-1 sm:max-w-sm">
        <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search by actor, action, resource..."
          value={searchTerm}
          onChange={(e) => {
            setSearchTerm(e.target.value)
            setPage(1)
          }}
          className="ps-9"
          aria-label="Search audit log"
        />
      </div>
      <Select
        value={resultFilter ?? 'all'}
        onValueChange={(value) => {
          setResultParam(value)
          setPage(1)
        }}
      >
        <SelectTrigger className="h-9 w-[130px]" aria-label="Result">
          <SelectValue placeholder="Result" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All results</SelectItem>
          {RESULT_OPTIONS.map((result) => (
            <SelectItem key={result} value={result}>
              {RESULT_DISPLAY[result].label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={severityFilter ?? 'all'}
        onValueChange={(value) => {
          setSeverityParam(value)
          setPage(1)
        }}
      >
        <SelectTrigger className="h-9 w-[140px]" aria-label="Severity">
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All severities</SelectItem>
          {SEVERITY_OPTIONS.map((severity) => (
            <SelectItem key={severity} value={severity}>
              {SEVERITY_DISPLAY[severity].label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {activeFiltersCount > 0 && (
        <Button variant="ghost" size="sm" onClick={clearFilters}>
          Clear
        </Button>
      )}
    </>
  )

  const toolbarEnd = (
    <>
      <div className="hidden items-center gap-2 md:flex">
        <Switch
          id="exclude-system"
          checked={hideSystem}
          onCheckedChange={(checked) => {
            setHideSystemParam(checked ? 'true' : 'false')
            setPage(1)
          }}
        />
        <Label
          htmlFor="exclude-system"
          className="cursor-pointer whitespace-nowrap text-sm font-normal"
          title="Hide events performed by the system itself"
        >
          Hide system
        </Label>
      </div>
      <Button
        variant="outline"
        size="sm"
        className="h-9"
        onClick={() => mutate()}
        aria-label="Refresh"
      >
        <RefreshCw className="h-4 w-4" />
      </Button>
    </>
  )

  return (
    <>
      <Main>
        <PageHeader title="Audit log" description="Activity history and security events." />

        <MetricStrip
          className="mt-5"
          loading={statsLoading}
          items={[
            { key: 'total', label: 'Events (7 days)', value: stats?.total_logs ?? 0 },
            {
              key: 'success',
              label: 'Successful',
              value: stats?.logs_by_result?.success ?? 0,
            },
            {
              key: 'failure',
              label: 'Failed',
              value: stats?.logs_by_result?.failure ?? 0,
              tone: 'danger',
            },
            {
              key: 'denied',
              label: 'Denied',
              value: stats?.logs_by_result?.denied ?? 0,
              tone: 'danger',
            },
          ]}
        />

        <div className="mt-5">
          {isError && !isLoading ? (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Failed to load audit logs</AlertTitle>
              <AlertDescription>
                <p>{error instanceof Error ? error.message : 'An unexpected error occurred.'}</p>
                <Button variant="outline" size="sm" className="mt-2" onClick={() => mutate()}>
                  <RefreshCw className="me-2 h-4 w-4" />
                  Retry
                </Button>
              </AlertDescription>
            </Alert>
          ) : isLoading && logs.length === 0 ? (
            <div className="space-y-2">
              <Skeleton className="h-9 w-full max-w-sm" />
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={logs}
              getRowId={(log) => log.id}
              showSearch={false}
              showColumnToggle={false}
              toolbarStart={toolbarStart}
              toolbarEnd={toolbarEnd}
              onRowClick={(log) => setSelectedLog(log)}
              manualPagination
              rowCount={total}
              pagination={pagination}
              onPaginationChange={setPagination}
              pageSizeOptions={PAGE_SIZES}
              sorting={sorting}
              onSortingChange={handleSortingChange}
              emptyMessage="No audit events found"
              emptyDescription={
                activeFiltersCount > 0
                  ? 'Try adjusting your search or filters.'
                  : 'Events appear here as people and systems act in this workspace.'
              }
            />
          )}
        </div>
      </Main>

      {/* Audit Log Detail Sheet */}
      {selectedLog && (
        <DetailSheet
          open
          onOpenChange={(open) => !open && setSelectedLog(null)}
          width="2xl"
          header={
            <DetailHeader
              title={formatAction(selectedLog.action)}
              badges={
                <>
                  <ResultBadge result={selectedLog.result} />
                  <SeverityBadge severity={selectedLog.severity} />
                </>
              }
              meta={[
                selectedLog.actor_email || 'System',
                new Date(selectedLog.timestamp).toLocaleString(),
              ]}
              menu={[
                {
                  label: 'Copy resource ID',
                  icon: Copy,
                  onSelect: () => {
                    copyToClipboard(selectedLog.resource_id)
                    toast.success('Resource ID copied to clipboard')
                  },
                },
                ...(selectedLog.request_id
                  ? [
                      {
                        label: 'Copy request ID',
                        icon: Copy,
                        onSelect: () => {
                          copyToClipboard(selectedLog.request_id!)
                          toast.success('Request ID copied to clipboard')
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
              <DetailSection title="Message">
                <p className="text-sm break-words text-muted-foreground">{selectedLog.message}</p>
              </DetailSection>
            )}

            <DetailSection title="Who and when">
              <DetailFieldGrid>
                <DetailField label="Actor">
                  <span className="break-all">{selectedLog.actor_email || 'System'}</span>
                </DetailField>
                {selectedLog.actor_ip && (
                  <DetailField label="IP address">
                    <span className="font-mono text-xs">{selectedLog.actor_ip}</span>
                  </DetailField>
                )}
                <DetailField label="Date">
                  {new Date(selectedLog.timestamp).toLocaleString(undefined, {
                    weekday: 'short',
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                  })}
                </DetailField>
                <DetailField label="Time">
                  <span className="tabular-nums">
                    {new Date(selectedLog.timestamp).toLocaleTimeString()}
                  </span>
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>

            <DetailSection title="Resource">
              <DetailFieldGrid>
                <DetailField label="Type">
                  {humanizeIdentifier(canonicalAuditResourceType(selectedLog.resource_type))}
                </DetailField>
                <DetailField label="Name">
                  <span className="break-words">{selectedLog.resource_name || '-'}</span>
                </DetailField>
                <DetailField label="ID" full>
                  <DetailCopyId id={selectedLog.resource_id} label="Resource ID" />
                </DetailField>
              </DetailFieldGrid>
            </DetailSection>

            {selectedLog.changes?.field_changes &&
              Object.keys(selectedLog.changes.field_changes).length > 0 && (
                <DetailSection
                  title="Changes"
                  count={Object.keys(selectedLog.changes.field_changes).length}
                >
                  <ul className="divide-y rounded-lg border">
                    {Object.entries(selectedLog.changes.field_changes).map(([field, change]) => (
                      <li
                        key={field}
                        className="grid gap-2 px-3 py-2.5 text-sm sm:grid-cols-[1fr_2fr] sm:items-center sm:gap-4"
                      >
                        <span className="font-medium break-all text-muted-foreground">{field}</span>
                        <span className="flex flex-wrap items-center gap-2">
                          <span className="inline-flex items-center rounded-md bg-muted px-2 py-1 text-xs break-all text-muted-foreground line-through">
                            {String(change.old)}
                          </span>
                          <span className="text-muted-foreground">→</span>
                          <span className="inline-flex items-center rounded-md bg-accent px-2 py-1 text-xs font-medium break-all text-accent-foreground">
                            {String(change.new)}
                          </span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </DetailSection>
              )}

            {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
              <DetailSection title="Metadata" count={Object.keys(selectedLog.metadata).length}>
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
              <DetailSection title="Request">
                <DetailCopyId id={selectedLog.request_id} label="Request ID" />
              </DetailSection>
            )}
          </DetailSections>
        </DetailSheet>
      )}
    </>
  )
}
