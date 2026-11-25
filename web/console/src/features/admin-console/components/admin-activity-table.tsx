'use client'

import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { History } from 'lucide-react'
import {
  DataTable,
  EmptyState,
  MetaLine,
  RelativeTime,
  type FilterPanelToggleProps,
} from '@/features/shared'
import { toDisplayText } from '@/lib/untrusted-text'
import { EmptyCell } from '@/features/shared/components/empty-cell'
import { auditActionLabel } from '../lib/audit-action-label'
import type { AdminAuditEntry } from '../types'

function ResultBadge({ entry }: { entry: AdminAuditEntry }) {
  const { t } = useTranslation()
  return entry.success ? (
    <Badge variant="secondary">{t('admin.adminActivityTable.succeeded', 'Succeeded')}</Badge>
  ) : (
    <Badge variant="destructive">
      {entry.response_status
        ? t('admin.adminActivityTable.failed', 'Failed ({response_status})', {
            response_status: entry.response_status,
          })
        : t('admin.adminActivityTable.failedPlain', 'Failed')}
    </Badge>
  )
}

/**
 * An administrator action on a phone:
 *
 *   Password changed                                       Succeeded
 *   admin@example.com
 *   8 minutes ago   192.0.2.10
 */
export function AdminActivityPhoneCard({
  entry,
  showIp,
}: {
  entry: AdminAuditEntry
  showIp: boolean
}) {
  const { t } = useTranslation()
  const email = toDisplayText(entry.admin_email)
  return (
    <div data-slot="activity-card" className="flex w-full min-w-0 flex-col gap-1 px-3 py-3">
      <div className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-medium">
          {auditActionLabel(t, entry.action)}
        </span>
        <ResultBadge entry={entry} />
      </div>
      {email && (
        <span className="truncate text-cap" title={email}>
          {email}
        </span>
      )}
      <MetaLine
        items={[
          <RelativeTime key="when" date={entry.created_at} />,
          showIp && entry.ip_address ? (
            <span key="ip" className="tabular-nums">
              {entry.ip_address}
            </span>
          ) : null,
        ]}
      />
    </div>
  )
}

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
        minWidth: 168,
        label: t('admin.adminActivityTable.action', 'Action'),
      },
      cell: ({ row }) => (
        <span className="truncate font-medium">{auditActionLabel(t, row.original.action)}</span>
      ),
    },
    {
      accessorKey: 'admin_email',
      header: t('admin.adminActivityTable.administrator', 'Administrator'),
      meta: {
        kind: 'text',
        width: 176,
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
      meta: { kind: 'status', width: 128, label: t('admin.adminActivityTable.result', 'Result') },
      cell: ({ row }) => <ResultBadge entry={row.original} />,
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
        width: 136,
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
  /** The list's name and count, leading the toolbar row (`ListToolbarTitle`). */
  toolbarTitle?: React.ReactNode
  /** The list's own actions (Export), before the Display menu. */
  toolbarEnd?: React.ReactNode
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
  toolbarTitle,
  toolbarEnd,
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
      showToolbar={!!toolbarStart || !!toolbarTitle}
      showSelectionCount={false}
      showPagination={!!paging}
      toolbarTitle={toolbarTitle}
      toolbarEnd={toolbarEnd}
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
      // A phone card with fixed slots: the action's code gets a line of its
      // own instead of breaking beside the action's words.
      mobileRow={(e) => <AdminActivityPhoneCard entry={e} showIp={showIp} />}
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
