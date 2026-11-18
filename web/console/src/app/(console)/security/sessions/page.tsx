'use client'

import { EmptyCell } from '@/features/assets/components/service-cells'
import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { MonitorSmartphone, Siren } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import {
  DataTable,
  DataTableRowActions,
  EmptyState,
  PageHeader,
  PageStack,
  RelativeTime,
} from '@/features/shared'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { useTranslation } from '@/context/i18n-provider'
import {
  endAdminSession,
  useAdminSessions,
} from '@console/features/admin-console/api/use-admin-sessions'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { AdminConfirmDialog } from '@console/features/admin-console/components/admin-confirm-dialog'
import { roleName } from '@console/features/admin-console/lib/role-name'
import { type AdminConsoleSession, adminHas } from '@console/features/admin-console/types'
import { RoleRequiredNotice } from '@console/features/admin-console/components/role-required-notice'

export default function AdminSessionsPage() {
  const admin = useAdmin()
  const { t } = useTranslation()
  const isSuper = adminHas(admin, 'platform.admins.read')
  const { data, error, isLoading, mutate } = useAdminSessions(isSuper)
  const [ending, setEnding] = useState<AdminConsoleSession | null>(null)
  const sessions = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<AdminConsoleSession>[]>(
    () => [
      {
        accessorKey: 'admin_email',
        header: t('admin.sessions.col.admin', 'Administrator'),
        // The administrator is the row's name: it stays in view while the
        // table scrolls sideways.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 200,
          label: t('admin.sessions.col.admin', 'Administrator'),
        },
        cell: ({ row }) => {
          const s = row.original
          return (
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium" title={s.admin_name || s.admin_email}>
                {s.admin_name || s.admin_email}
              </span>
              {s.admin_name && s.admin_name !== s.admin_email && (
                <span className="truncate text-muted-foreground" title={s.admin_email}>
                  {s.admin_email}
                </span>
              )}
              {s.current && (
                <Badge variant="secondary" className="shrink-0">
                  {t('admin.sessions.current', 'This session')}
                </Badge>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'admin_role',
        header: t('admin.sessions.col.role', 'Role'),
        meta: { kind: 'tags', width: 176, label: t('admin.sessions.col.role', 'Role') },
        cell: ({ row }) => (
          <div className="flex flex-wrap gap-1 md:min-w-0 md:flex-nowrap md:overflow-hidden md:*:shrink-0">
            <Badge variant="outline">{roleName(t, row.original.admin_role)}</Badge>
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
        meta: {
          kind: 'text',
          width: 184,
          hideBelow: 1100,
          label: t('admin.sessions.col.method', 'Signed in with'),
        },
        cell: ({ row }) => (
          <span className="block truncate">
            {row.original.auth_method === 'idp'
              ? t('admin.sessions.idp', 'Identity provider')
              : t('admin.sessions.methodLocal', 'Password + authenticator')}
          </span>
        ),
      },
      {
        accessorKey: 'ip_address',
        header: t('admin.sessions.col.ip', 'IP address'),
        meta: {
          kind: 'text',
          width: 144,
          hideBelow: 760,
          label: t('admin.sessions.col.ip', 'IP address'),
        },
        cell: ({ row }) => (
          <span className="block truncate tabular-nums" title={row.original.user_agent}>
            {row.original.ip_address || (
              <EmptyCell title={t('admin.sessions.noIp', 'No address recorded')} />
            )}
          </span>
        ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.sessions.col.started', 'Started'),
        meta: {
          kind: 'date',
          width: 152,
          hideBelow: 1000,
          label: t('admin.sessions.col.started', 'Started'),
        },
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        accessorKey: 'last_seen_at',
        header: t('admin.sessions.col.lastSeen', 'Last seen'),
        meta: {
          kind: 'datetime-recent',
          width: 152,
          label: t('admin.sessions.col.lastSeen', 'Last seen'),
        },
        cell: ({ row }) => <RelativeTime date={row.original.last_seen_at} />,
      },
      {
        id: 'actions',
        header: '',
        meta: { kind: 'actions' },
        // The one action ends a session: it stays behind the row's menu.
        cell: ({ row }) =>
          row.original.current ? null : (
            <DataTableRowActions
              label={t('admin.sessions.rowActions', 'Actions for the session of {admin}', {
                admin: row.original.admin_email,
              })}
              actions={[
                {
                  label: t('admin.sessions.endConfirm', 'End session'),
                  onClick: () => setEnding(row.original),
                  destructive: true,
                },
              ]}
            />
          ),
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.sessions', 'Sessions')}
          description={t(
            'admin.sessions.description',
            'Every open console session. End one that should not be there: that administrator is signed out at once.'
          )}
        />
        {!isSuper ? (
          <RoleRequiredNotice needed="super_admin" variant="page" />
        ) : (
          <>
            <ListTitleRow
              title={t('admin.sessions.viewAll', 'Open sessions')}
              count={
                <ListCount
                  total={sessions.length}
                  loading={!data}
                  label={t(
                    'admin.sessions.total',
                    '{count, plural, one {# session} other {# sessions}}',
                    { count: sessions.length }
                  )}
                />
              }
            />
            <DataTable
              columns={columns}
              data={sessions}
              caption={t('admin.nav.sessions', 'Sessions')}
              getRowId={(s) => s.id}
              error={error}
              onRetry={() => void mutate()}
              errorTitle={t('admin.securitySessionsPage.sessions', 'sessions')}
              isLoading={isLoading && !data}
              showSearch={false}
              showSelectionCount={false}
              mobileCards
              paginationNoun={t('admin.sessions.noun', 'sessions')}
              emptyState={{
                nothingYet: (
                  <EmptyState
                    icon={MonitorSmartphone}
                    title={t('admin.sessions.empty', 'No open session')}
                  />
                ),
              }}
            />
          </>
        )}
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
                  {
                    email: ending.admin_email,
                    ip: ending.ip_address || t('admin.sessions.unknownIp', 'an unknown address'),
                  }
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
      </PageStack>
    </Main>
  )
}
