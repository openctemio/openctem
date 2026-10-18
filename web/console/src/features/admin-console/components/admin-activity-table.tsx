'use client'

import { useTranslation } from '@/context/i18n-provider'
import type { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { DataTable, RelativeTime, StackedCell } from '@/features/shared'
import { humanizeIdentifier } from '@/lib/humanize-identifier'
import type { AdminAuditEntry } from '../types'

/** "organization.idp_create" -> "Identity provider create". */
export function humanizeAction(action: string): string {
  const [area, verb] = action.split('.')
  return humanizeIdentifier(verb ?? area)
}

function useColumns(): ColumnDef<AdminAuditEntry>[] {
  const { t } = useTranslation()
  return [
    {
      accessorKey: 'action',
      header: t('admin.adminActivityTable.action', 'Action'),
      cell: ({ row }) => (
        <StackedCell
          primary={humanizeAction(row.original.action)}
          secondary={row.original.action}
        />
      ),
    },
    {
      accessorKey: 'admin_email',
      header: t('admin.adminActivityTable.administrator', 'Administrator'),
      cell: ({ row }) => <span className="text-sm">{row.original.admin_email}</span>,
    },
    {
      accessorKey: 'success',
      header: t('admin.adminActivityTable.result', 'Result'),
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
      cell: ({ row }) => (
        <span className="text-sm tabular-nums">{row.original.ip_address || '—'}</span>
      ),
    },
    {
      accessorKey: 'created_at',
      header: t('admin.adminActivityTable.when', 'When'),
      cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
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
  /** Opens one entry (the detail sheet). */
  onRowClick?: (entry: AdminAuditEntry) => void
}

/** Platform admin audit trail (admin_audit_logs). */
export function AdminActivityTable({
  entries,
  isLoading,
  paging,
  toolbarStart,
  onRowClick,
}: AdminActivityTableProps) {
  const { t } = useTranslation()
  const columns = useColumns()

  return (
    <DataTable
      columns={columns}
      data={entries}
      getRowId={(e) => e.id}
      isLoading={isLoading}
      showSearch={false}
      showColumnToggle={false}
      showSelectionCount={false}
      showPagination={!!paging}
      toolbarStart={toolbarStart}
      emptyMessage={t(
        'admin.adminActivityTable.noAdministratorActivityYet',
        'No administrator activity yet'
      )}
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
