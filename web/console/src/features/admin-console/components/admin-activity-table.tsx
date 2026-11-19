'use client'

import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { History } from 'lucide-react'
import { DataTable, EmptyState, RelativeTime, type FilterPanelToggleProps } from '@/features/shared'
import { toDisplayText } from '@/lib/untrusted-text'
import { EmptyCell } from '@/features/shared/components/empty-cell'
import { auditActionLabel } from '../lib/audit-action-label'
import type { AdminAuditEntry } from '../types'

function useColumns(): ColumnDef<AdminAuditEntry>[] {
  const { t } = useTranslation()
  return [
    {
      accessorKey: 'action',
      header: t('admin.adminActivityTable.action', 'Action'),
      // The action is the row's name: what happened in words, then its code,
      // on one line. It stays in view while the table scrolls sideways.
      meta: {
        kind: 'name',
        pin: 'start',
        minWidth: 200,
        label: t('admin.adminActivityTable.action', 'Action'),
      },
      cell: ({ row }) => (
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="shrink-0 font-medium">{auditActionLabel(t, row.original.action)}</span>
          <span
            className="truncate font-mono text-code text-muted-foreground"
            title={row.original.action}
          >
            {row.original.action}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'admin_email',
      header: t('admin.adminActivityTable.administrator', 'Administrator'),
      meta: {
        kind: 'text',
        width: 200,
        label: t('admin.adminActivityTable.administrator', 'Administrator'),
      },
      cell: ({ row }) => (
        <span className="block truncate" title={toDisplayText(row.original.admin_email)}>
          {toDisplayText(row.original.admin_email)}
        </span>
      ),
    },
    {
      accessorKey: 'success',
      header: t('admin.adminActivityTable.result', 'Result'),
      meta: { kind: 'status', width: 152, label: t('admin.adminActivityTable.result', 'Result') },
      cell: ({ row }) =>
        row.original.success ? (
          <Badge variant="secondary">{t('admin.adminActivityTable.succeeded', 'Succeeded')}</Badge>
        ) : (
          <Badge variant="destructive">
            {row.original.response_status
              ? t('admin.adminActivityTable.failed', 'Failed ({response_status})', {
                  response_status: row.original.response_status,
                })
              : t('admin.adminActivityTable.failedPlain', 'Failed')}
          </Badge>
        ),
    },
    {
      accessorKey: 'ip_address',
      header: t('admin.adminActivityTable.ipAddress', 'IP address'),
      meta: {
        kind: 'text',
        width: 144,
        hideBelow: 900,
        label: t('admin.adminActivityTable.ipAddress', 'IP address'),
      },
      cell: ({ row }) =>
        row.original.ip_address ? (
          <span className="block truncate tabular-nums">{row.original.ip_address}</span>
        ) : (
          <EmptyCell title={t('admin.adminActivityTable.noIp', 'No address recorded')} />
        ),
    },
    {
      accessorKey: 'created_at',
      header: t('admin.adminActivityTable.when', 'When'),
      meta: {
        kind: 'datetime-recent',
        width: 152,
        label: t('admin.adminActivityTable.when', 'When'),
      },
      cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
    },
  ]
}

interface AdminActivityTableProps {
  entries: AdminAuditEntry[]
  isLoading?: boolean
  /** Server paging; omit for a fixed short list. */
  paging?: {
    page: number
    pageCount: number
    rowCount: number
    onPageChange: (page: number) => void
  }
  toolbarStart?: React.ReactNode
  /** The active filter chips, one row under the toolbar. */
  toolbarBelow?: React.ReactNode
  /** The phone's filter entry (a sheet), joined to the toolbar's start. */
  filterToggle?: FilterPanelToggleProps
  /** Opens one entry (the detail sheet). */
  onRowClick?: (entry: AdminAuditEntry) => void
  /** The table's accessible name. */
  caption?: string
  /** A failed read: shown in the table with Retry, the toolbar stays. */
  error?: unknown
  onRetry?: () => void
  /** A re-read while rows are shown. */
  isRefreshing?: boolean
  /** Filters narrow the list: the empty state offers Clear filters. */
  isFiltered?: boolean
  onClearFilters?: () => void
}

/** Platform admin audit trail (admin_audit_logs). */
export function AdminActivityTable({
  entries,
  isLoading,
  paging,
  toolbarStart,
  toolbarBelow,
  filterToggle,
  onRowClick,
  caption,
  error,
  onRetry,
  isRefreshing,
  isFiltered,
  onClearFilters,
}: AdminActivityTableProps) {
  const { t } = useTranslation()
  const allColumns = useColumns()
  // A read-only administrator is not sent addresses; an empty column of
  // dashes would look like missing data.
  const showIp = entries.length === 0 || entries.some((e) => !!e.ip_address)
  const columns = showIp
    ? allColumns
    : allColumns.filter((c) => !('accessorKey' in c) || c.accessorKey !== 'ip_address')

  return (
    <DataTable
      columns={columns}
      data={entries}
      caption={caption ?? t('admin.adminActivityTable.caption', 'Administrator activity')}
      getRowId={(e) => e.id}
      isLoading={isLoading}
      isRefreshing={isRefreshing}
      refreshingLabel={t('admin.adminActivityTable.refreshing', 'Refreshing activity')}
      error={error}
      onRetry={onRetry}
      errorTitle={t('admin.securityActivityPage.adminActivity', 'admin activity')}
      showSearch={false}
      showToolbar={!!toolbarStart}
      showSelectionCount={false}
      showPagination={!!paging}
      toolbarStart={toolbarStart}
      toolbarBelow={toolbarBelow}
      filterToggle={filterToggle}
      isFiltered={isFiltered}
      onClearFilters={onClearFilters}
      emptyState={{
        nothingYet: (
          <EmptyState
            icon={History}
            title={t(
              'admin.adminActivityTable.noAdministratorActivityYet',
              'No administrator activity yet'
            )}
          />
        ),
        noMatch: {
          title: t('admin.adminActivityTable.noMatch', 'No activity matches these filters'),
        },
      }}
      paginationNoun={t('admin.adminActivityTable.noun', 'events')}
      mobileCards
      onRowClick={onRowClick}
      {...(paging && {
        manualPagination: true,
        pageCount: paging.pageCount,
        rowCount: paging.rowCount,
        pagination: { pageIndex: paging.page - 1, pageSize: 50 },
        onPaginationChange: (p: { pageIndex: number }) => paging.onPageChange(p.pageIndex + 1),
      })}
    />
  )
}
