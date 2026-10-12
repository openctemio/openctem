'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Search, UserSearch } from 'lucide-react'
import { Main } from '@/components/layout'
import { Input } from '@/components/ui/input'
import {
  DataTable,
  EmptyState,
  ErrorState,
  PageHeader,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import {
  PLATFORM_USER_SEARCH_MIN,
  usePlatformUsers,
} from '@/features/admin-console/api/use-platform-users'
import { PlatformUserBadges } from '@/features/admin-console/components/platform-user-badges'
import type { PlatformUser } from '@/features/admin-console/types'

export default function AdminUsersPage() {
  const router = useRouter()
  const { t } = useTranslation()
  // The search lives in the URL, so a support ticket can link to it.
  const list = useListParams({ defaultPageSize: 25 })
  const q = useDebounce(list.q, 300).trim()
  const searching = q.length >= PLATFORM_USER_SEARCH_MIN
  const { data, error, isLoading, mutate } = usePlatformUsers(q, list.page, list.perPage)

  const columns = useMemo<ColumnDef<PlatformUser>[]>(
    () => [
      {
        accessorKey: 'email',
        header: t('admin.users.col.account', 'Account'),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.name || row.original.email}
            secondary={row.original.email}
          />
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
    ],
    [t]
  )

  return (
    <Main>
      <PageHeader
        title={t('admin.nav.users', 'Users')}
        description={t(
          'admin.users.description',
          'Find an account in any organization by email, name or id, and help it sign in again. Only account details are shown, never what an organization holds.'
        )}
      />
      <div className="mt-5 space-y-4">
        <div className="relative w-full sm:max-w-md">
          <Search className="absolute start-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input
            autoFocus
            placeholder={t('admin.users.search', 'Email, name or user id...')}
            value={list.q}
            onChange={(e) => list.setSearch(e.target.value)}
            className="ps-8"
            aria-label={t('admin.users.searchLabel', 'Search accounts')}
          />
        </div>
        {!searching ? (
          <EmptyState
            icon={UserSearch}
            card
            title={t('admin.users.startTitle', 'Search for an account')}
            description={t(
              'admin.users.startHint',
              'Type at least 3 characters of an email, a name or a user id. Accounts are looked up, not listed.'
            )}
          />
        ) : error ? (
          <ErrorState title="accounts" error={error} onRetry={() => void mutate()} />
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
            onRowClick={(u) => router.push(`/admin/users/${u.id}`)}
            emptyMessage={t('admin.users.noMatch', 'No account matches this search')}
            manualPagination
            pageCount={data?.total_pages ?? 1}
            rowCount={data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
          />
        )}
      </div>
    </Main>
  )
}
