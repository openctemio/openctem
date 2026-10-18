'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import { Main } from '@/components/layout'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { DataTable, ErrorState, PageHeader, RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import {
  PLATFORM_USER_SEARCH_MIN,
  usePlatformUsers,
} from '@console/features/admin-console/api/use-platform-users'
import { PlatformUserBadges } from '@console/features/admin-console/components/platform-user-badges'
import {
  adminCan,
  PLATFORM_USER_STATES,
  type PlatformUserListItem,
  type PlatformUserState,
} from '@console/features/admin-console/types'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { RoleRequiredNotice } from '@console/features/admin-console/components/role-required-notice'

/** English tab names (i18n fallback; keys admin.users.state.<state>). */
const STATE_LABELS: Record<PlatformUserState, string> = {
  all: 'All',
  active: 'Active',
  unverified: 'Not verified',
  locked: 'Locked',
  blocked: 'Blocked',
  mfa_off: 'No MFA',
  platform_admins: 'Platform admins',
}

function isState(v: string): v is PlatformUserState {
  return (PLATFORM_USER_STATES as readonly string[]).includes(v)
}

/**
 * Customers > Users: every account of the installation, newest first, by
 * state (tabs with counts), with an optional search. Account facts only: no
 * names in the list and nothing an organization holds. Ops admin and up;
 * every view is audited.
 */
export default function AdminUsersPage() {
  const router = useRouter()
  const { t } = useTranslation()
  const me = useAdmin()
  const allowed = adminCan(me.role, 'ops_admin')
  // Search, tab and page live in the URL, so a support ticket can link to them.
  const list = useListParams({ defaultPageSize: 25, filters: { state: 'all' } })
  const state: PlatformUserState = isState(list.filters.state) ? list.filters.state : 'all'
  const q = useDebounce(list.q, 300).trim()
  const tooShort = q.length > 0 && q.length < PLATFORM_USER_SEARCH_MIN
  const { data, error, isLoading, mutate } = usePlatformUsers(
    allowed && !tooShort ? q : '',
    state,
    list.page,
    list.perPage
  )

  const columns = useMemo<ColumnDef<PlatformUserListItem>[]>(
    () => [
      {
        accessorKey: 'email',
        header: t('admin.users.col.account', 'Account'),
        cell: ({ row }) => (
          <span className="break-all text-sm font-medium">{row.original.email}</span>
        ),
      },
      {
        id: 'state',
        header: t('admin.users.col.state', 'State'),
        cell: ({ row }) => <PlatformUserBadges user={row.original} />,
      },
      {
        accessorKey: 'auth_provider',
        header: t('admin.users.col.signIn', 'Signs in with'),
        cell: ({ row }) => <span className="text-sm capitalize">{row.original.auth_provider}</span>,
      },
      {
        accessorKey: 'memberships',
        header: t('admin.users.col.orgs', 'Organizations'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.memberships}</span>,
      },
      {
        accessorKey: 'last_login_at',
        header: t('admin.users.col.lastSignIn', 'Last sign-in'),
        cell: ({ row }) =>
          row.original.last_login_at ? (
            <RelativeTime date={row.original.last_login_at} className="text-sm" />
          ) : (
            <span className="text-sm text-muted-foreground">{t('admin.users.never', 'Never')}</span>
          ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.users.col.created', 'Created'),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
      },
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.users', 'Users')}
        description={t(
          'admin.users.browseDescription',
          'Every account of this installation, newest first. Only account facts are shown, never what an organization holds; each view is recorded in the admin audit log.'
        )}
      />
      {!allowed ? (
        <RoleRequiredNotice needed="ops_admin" variant="page" />
      ) : (
        <div className="mt-5 space-y-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <Tabs value={state} onValueChange={(v) => list.setFilter('state', v)}>
              <TabsList className="h-auto flex-wrap">
                {PLATFORM_USER_STATES.map((s) => (
                  <TabsTrigger key={s} value={s} className="gap-1.5">
                    {t(`admin.users.state.${s}`, STATE_LABELS[s])}
                    {data?.counts?.[s] !== undefined && (
                      <span className="tabular-nums text-xs text-muted-foreground">
                        {data.counts[s]}
                      </span>
                    )}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
            <div className="relative w-full lg:max-w-xs">
              <Search className="absolute start-2.5 top-2.5 size-4 text-muted-foreground" />
              <Input
                placeholder={t('admin.users.search', 'Email, name or user id...')}
                value={list.q}
                onChange={(e) => list.setSearch(e.target.value)}
                className="ps-8"
                aria-label={t('admin.users.searchLabel', 'Search accounts')}
              />
            </div>
          </div>
          {tooShort && (
            <p className="text-sm text-muted-foreground">
              {t('admin.users.tooShort', 'Type at least 3 characters to search.')}
            </p>
          )}
          {error ? (
            <ErrorState
              title={t('admin.users.errorTitle', 'accounts')}
              error={error}
              onRetry={() => void mutate()}
            />
          ) : (
            <DataTable
              columns={columns}
              data={data?.data ?? []}
              getRowId={(u) => u.id}
              isLoading={isLoading}
              showSearch={false}
              showColumnToggle={false}
              showSelectionCount={false}
              mobileCards
              onRowClick={(u) => router.push(`/users/${u.id}`)}
              emptyMessage={
                q
                  ? t('admin.users.noMatch', 'No account matches this search')
                  : t('admin.users.noneInState', 'No account in this state')
              }
              manualPagination
              pageCount={data?.total_pages ?? 1}
              rowCount={data?.total ?? 0}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
            />
          )}
        </div>
      )}
    </Main>
  )
}
