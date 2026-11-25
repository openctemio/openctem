'use client'

import { BreakText } from '@/features/shared/components/break-text'
import { EmptyCell } from '@/features/shared/components/empty-cell'
import { useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { MonitorSmartphone, Siren } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import { adminActivityHref } from '@console/features/admin-console/lib/console-links'
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
  // An open break-glass session is the one thing to look at here: the page's
  // main action reviews what it did, in Admin activity.
  const breakGlass = sessions.find((s) => s.break_glass && !s.current)

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
          const name = s.admin_name || s.admin_email
          return (
            <div className="flex min-w-0 items-center gap-2">
              {/* One line, as the board draws it: the name, the session's
                  marks (plain text, never cut: a badge in a name cell
                  collapses it) and the address, which gives way first: the
                  name keeps its width up to 60 % of the cell. On a phone card
                  the name takes up to two lines and the address is left out
                  (the card's title has no room for both). */}
              <span
                className="min-w-0 truncate font-medium max-md:line-clamp-2 md:max-w-[60%] md:shrink-0"
                title={name}
              >
                <BreakText>{name}</BreakText>
              </span>
              {s.current && (
                <span className="shrink-0 text-cap-m text-muted-foreground">
                  {t('admin.sessions.current', 'This session')}
                </span>
              )}
              {s.break_glass && (
                <span className="inline-flex shrink-0 items-center gap-1 text-cap-m text-destructive max-md:hidden">
                  <Siren className="size-3" aria-hidden="true" />
                  {t('admin.sessions.breakGlass', 'Break-glass')}
                </span>
              )}
              {s.admin_name && s.admin_name !== s.admin_email && (
                <span
                  className="min-w-0 shrink-[4] truncate text-muted-foreground max-md:hidden"
                  title={s.admin_email}
                >
                  <BreakText>{s.admin_email}</BreakText>
                </span>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'admin_role',
        header: t('admin.sessions.col.role', 'Role'),
        // The role is the phone card's chip, at the end of its title line.
        meta: { kind: 'status', width: 160, label: t('admin.sessions.col.role', 'Role') },
        // On a phone a break-glass session's chip says so (the title line has
        // no room for the name, the mark and the role).
        cell: ({ row }) => (
          <>
            {row.original.break_glass && (
              <span className="md:hidden">
                <Badge variant="destructive">
                  <Siren aria-hidden="true" />
                  {t('admin.sessions.breakGlass', 'Break-glass')}
                </Badge>
              </span>
            )}
            <span className={row.original.break_glass ? 'max-md:hidden' : undefined}>
              <Badge variant="outline">{roleName(t, row.original.admin_role)}</Badge>
            </span>
          </>
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
        // Wraps ("Mật khẩu + ứng dụng xác thực" on two lines) instead of
        // being cut; a wider column made the table scroll at 1440 px.
        cell: ({ row }) => (
          <span className="block whitespace-normal break-words">
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
          // One line (the phone card's field is one line): a long IPv6
          // address ends in an ellipsis, whole in the hover text with the
          // browser.
          <span
            data-cut-tooltip
            className="block truncate tabular-nums"
            title={[row.original.ip_address, row.original.user_agent].filter(Boolean).join('\n')}
          >
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
          // "less than a minute ago" whole, with a gap before the cell on its left.
          width: 176,
          // A stale session is told by it: the phone card shows it first.
          cardFigure: true,
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
        >
          {isSuper && breakGlass && (
            <Button asChild>
              <Link
                href={adminActivityHref(breakGlass.admin_email)}
                title={t('admin.sessions.reviewTitle', 'Review the break-glass session')}
              >
                {t('admin.sessions.review', 'Review')}
              </Link>
            </Button>
          )}
        </PageHeader>
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
              searchPlaceholder={t('admin.sessions.search', 'Search email or IP address…')}
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
            reasonPlaceholder={t('admin.sessions.reasonEnd', 'Laptop reported lost, ticket 2231')}
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
