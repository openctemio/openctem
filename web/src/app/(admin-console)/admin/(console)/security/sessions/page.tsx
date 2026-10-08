'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { LogOut, Siren } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataTable, ErrorState, PageHeader, RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { endAdminSession, useAdminSessions } from '@/features/admin-console/api/use-admin-sessions'
import { useAdmin } from '@/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@/features/admin-console/components/admin-confirm-dialog'
import {
  ADMIN_ROLE_LABELS,
  adminCan,
  type AdminConsoleSession,
} from '@/features/admin-console/types'

export default function AdminSessionsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const isSuper = adminCan(admin.role, 'super_admin')
  const { data, error, isLoading, mutate } = useAdminSessions(isSuper)
  const [ending, setEnding] = useState<AdminConsoleSession | null>(null)

  const columns = useMemo<ColumnDef<AdminConsoleSession>[]>(
    () => [
      {
        accessorKey: 'admin_email',
        header: t('admin.sessions.col.admin', 'Administrator'),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <StackedCell
              primary={row.original.admin_name || row.original.admin_email}
              secondary={row.original.admin_email}
            />
            {row.original.current && (
              <Badge variant="secondary">{t('admin.sessions.current', 'This session')}</Badge>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'admin_role',
        header: t('admin.sessions.col.role', 'Role'),
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1">
            <Badge variant="outline">
              {t(
                `admin.role.${row.original.admin_role}`,
                ADMIN_ROLE_LABELS[row.original.admin_role]
              )}
            </Badge>
            {row.original.break_glass && (
              <Badge variant="destructive">
                <Siren className="me-1 size-3" />
                {t('admin.sessions.breakGlass', 'Break-glass')}
              </Badge>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'auth_method',
        header: t('admin.sessions.col.method', 'Signed in with'),
        cell: ({ row }) => (
          <span className="text-sm">
            {row.original.auth_method === 'idp'
              ? t('admin.sessions.idp', 'Identity provider')
              : t('admin.sessions.password', 'Password + authenticator')}
          </span>
        ),
      },
      {
        accessorKey: 'ip_address',
        header: t('admin.sessions.col.ip', 'IP address'),
        cell: ({ row }) => (
          <span className="text-sm tabular-nums" title={row.original.user_agent}>
            {row.original.ip_address || '-'}
          </span>
        ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.sessions.col.started', 'Started'),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
      },
      {
        accessorKey: 'last_seen_at',
        header: t('admin.sessions.col.lastSeen', 'Last seen'),
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} className="text-sm" />,
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          row.original.current ? null : (
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation()
                setEnding(row.original)
              }}
            >
              <LogOut className="me-1 size-4" />
              {t('admin.sessions.end', 'End')}
            </Button>
          ),
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.sessions', 'Sessions')}
        description={t(
          'admin.sessions.description',
          'Every open console session. End one that should not be there: that administrator is signed out at once.'
        )}
      />
      <div className="mt-5">
        {!isSuper ? (
          <p className="text-sm text-muted-foreground">
            {t('admin.sessions.superOnly', 'Only a super admin can see console sessions.')}
          </p>
        ) : error ? (
          <ErrorState title="sessions" error={error} onRetry={() => void mutate()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            getRowId={(s) => s.id}
            isLoading={isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            emptyMessage={t('admin.sessions.empty', 'No open session')}
          />
        )}
      </div>
      {ending && (
        <AdminConfirmDialog
          open
          onOpenChange={(open) => !open && setEnding(null)}
          title={t('admin.sessions.endTitle', 'End this console session')}
          description={
            <p>
              {t(
                'admin.sessions.endWhat',
                '{email} is signed out of the console at once (signed in from {ip}). The other administrators can see this in the audit log.',
                { email: ending.admin_email, ip: ending.ip_address || '-' }
              )}
            </p>
          }
          confirmLabel={t('admin.sessions.endConfirm', 'End session')}
          destructive
          requireCode
          onConfirm={async (proof) => {
            await endAdminSession(ending.id, proof)
            toast.success(t('admin.sessions.ended', 'Session ended.'))
            void mutate()
          }}
        />
      )}
    </Main>
  )
}
