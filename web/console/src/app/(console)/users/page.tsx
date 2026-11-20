'use client'

import { authProviderLabel } from '@console/features/admin-console/lib/value-labels'
import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { UserRound } from 'lucide-react'
import { Main } from '@/components/layout'
import { DataTable, EmptyState, PageHeader, PageStack, RelativeTime } from '@/features/shared'
import { FilterSelect } from '@/features/shared/components/filter-select'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { toDisplayText } from '@/lib/untrusted-text'
import { BreakText } from '@/features/shared/components/break-text'
import {
  PLATFORM_USER_SEARCH_MIN,
  usePlatformUsers,
} from '@console/features/admin-console/api/use-platform-users'
import { PlatformUserBadges } from '@console/features/admin-console/components/platform-user-badges'
import { platformUserHref } from '@console/features/admin-console/lib/console-links'
import {
  PLATFORM_USER_STATES,
  type PlatformUserListItem,
  type PlatformUserState,
  adminHas,
} from '@console/features/admin-console/types'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { RoleRequiredNotice } from '@console/features/admin-console/components/role-required-notice'

/** English state names (i18n fallback; keys admin.users.state.<state>). */
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
 * state (a select with counts), with an optional search. Account facts only:
 * no names in the list and nothing an organization holds. Ops admin and up;
 * every view is audited.
 */
export default function AdminUsersPage() {
  const router = useRouter()
  const { t } = useTranslation()
  const me = useAdmin()
  const allowed = adminHas(me, 'platform.users.read')
  // Search, state and page live in the URL, so a support ticket can link to them.
  const list = useListParams({ defaultPageSize: 25, filters: { state: 'all' } })
  const state: PlatformUserState = isState(list.filters.state) ? list.filters.state : 'all'
  const q = list.searchTerm
  const tooShort = q.length > 0 && q.length < PLATFORM_USER_SEARCH_MIN
  const { data, error, isLoading, isValidating, mutate } = usePlatformUsers(
    allowed && !tooShort ? q : '',
    state,
    list.page,
    list.perPage
  )
  const total = data?.total ?? 0
  const narrowed = q !== '' || state !== 'all'

  const columns = useMemo<ColumnDef<PlatformUserListItem>[]>(
    () => [
      {
        accessorKey: 'email',
        header: t('admin.users.col.account', 'Account'),
        // The account is the row's name: it stays in view while the table
        // scrolls sideways and links to the account's page.
        // A floor makes the column take the room the others leave (a long
        // address ends in an ellipsis) instead of its content's width.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 200,
          label: t('admin.users.col.account', 'Account'),
        },
        cell: ({ row }) => {
          const href = platformUserHref(row.original.id)
          return (
            // A block around the link: the cell is sized by its floor and the
            // room left, never by the address.
            <div className="flex min-w-0">
              <RowNameLink
                href={href}
                onOpen={() => router.push(href)}
                title={toDisplayText(row.original.email)}
              >
                {/* On a phone card the address wraps at its dots and before
                    the @, never inside a word. */}
                <BreakText>{toDisplayText(row.original.email)}</BreakText>
              </RowNameLink>
            </div>
          )
        },
      },
      {
        id: 'state',
        header: t('admin.users.col.state', 'State'),
        // The account's state: on a phone it is the card's chip, at the end
        // of the title line.
        meta: {
          kind: 'status',
          width: 208,
          label: t('admin.users.col.state', 'State'),
        },
        cell: ({ row }) => <PlatformUserBadges user={row.original} oneLine />,
      },
      {
        accessorKey: 'auth_provider',
        header: t('admin.users.col.signIn', 'Signs in with'),
        meta: {
          kind: 'text',
          width: 136,
          hideBelow: 860,
          label: t('admin.users.col.signIn', 'Signs in with'),
        },
        cell: ({ row }) => (
          <span className="block truncate">{authProviderLabel(t, row.original.auth_provider)}</span>
        ),
      },
      {
        accessorKey: 'memberships',
        header: t('admin.users.col.orgs', 'Organizations'),
        meta: { kind: 'number', width: 112, label: t('admin.users.col.orgs', 'Organizations') },
        cell: ({ row }) => <span className="tabular-nums">{row.original.memberships}</span>,
      },
      {
        accessorKey: 'last_login_at',
        header: t('admin.users.col.lastSignIn', 'Last sign-in'),
        meta: {
          kind: 'datetime-recent',
          width: 152,
          label: t('admin.users.col.lastSignIn', 'Last sign-in'),
        },
        cell: ({ row }) =>
          row.original.last_login_at ? (
            <RelativeTime date={row.original.last_login_at} />
          ) : (
            <span className="text-muted-foreground">{t('admin.users.never', 'Never')}</span>
          ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.users.col.created', 'Created'),
        meta: {
          kind: 'date',
          // "about 1 month ago" whole, like Last sign-in.
          width: 152,
          hideBelow: 720,
          label: t('admin.users.col.created', 'Created'),
        },
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
    ],
    [t, router]
  )

  return (
    <Main>
      <PageStack>
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
          <>
            <ListTitleRow
              title={
                state === 'all'
                  ? t('admin.users.viewAll', 'All accounts')
                  : t(`admin.users.state.${state}`, STATE_LABELS[state])
              }
              count={
                <ListCount
                  total={total}
                  loading={!data}
                  label={t(
                    'admin.users.total',
                    '{count, plural, one {# account} other {# accounts}}',
                    { count: total }
                  )}
                />
              }
            />
            <DataTable
              columns={columns}
              data={data?.data ?? []}
              caption={t('admin.nav.users', 'Users')}
              getRowId={(u) => u.id}
              error={error}
              onRetry={() => void mutate()}
              errorTitle={t('admin.users.errorTitle', 'accounts')}
              // The first read: skeleton rows under a toolbar that stays mounted.
              isLoading={isLoading && !data}
              isRefreshing={isValidating && !!data}
              refreshingLabel={t('admin.users.refreshing', 'Refreshing accounts')}
              showSearch={false}
              search={{
                value: list.q,
                onChange: list.setSearch,
                placeholder: t('admin.users.search', 'Search email, name or user id…'),
                label: t('admin.users.searchLabel', 'Search accounts'),
              }}
              toolbarStart={
                <FilterSelect<PlatformUserState>
                  label={t('admin.users.stateFilter', 'State')}
                  value={state}
                  allValue="all"
                  allLabel={t('admin.users.state.all', STATE_LABELS.all)}
                  allCount={data?.counts?.all}
                  foldLabel
                  onChange={(v) => list.setFilter('state', v || 'all')}
                  options={PLATFORM_USER_STATES.filter((x) => x !== 'all').map((x) => ({
                    value: x,
                    label: t(`admin.users.state.${x}`, STATE_LABELS[x]),
                    count: data?.counts?.[x],
                  }))}
                />
              }
              // The search needs three characters: said in the row under the
              // toolbar, and the list stays as it was.
              toolbarBelow={
                tooShort ? (
                  <p role="status" className="text-sm text-muted-foreground">
                    {t('admin.users.tooShort', 'Type at least 3 characters to search.')}
                  </p>
                ) : undefined
              }
              showSelectionCount={false}
              mobileCards
              onRowClick={(u) => router.push(platformUserHref(u.id))}
              isFiltered={narrowed}
              onClearFilters={list.reset}
              emptyState={{
                nothingYet: (
                  <EmptyState icon={UserRound} title={t('admin.users.empty', 'No accounts yet')} />
                ),
                noMatch: {
                  title: q
                    ? t('admin.users.noMatch', 'No account matches this search')
                    : t('admin.users.noneInState', 'No account in this state'),
                },
              }}
              manualPagination
              pageCount={data?.total_pages ?? 1}
              rowCount={total}
              pagination={list.pagination}
              onPaginationChange={list.setPagination}
              paginationNoun={t('admin.users.noun', 'accounts')}
            />
          </>
        )}
      </PageStack>
    </Main>
  )
}
