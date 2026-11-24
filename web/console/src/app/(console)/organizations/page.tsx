'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Building2 } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import {
  DataTable,
  EmptyState,
  FilterSelect,
  PageHeader,
  PageStack,
  RelativeTime,
} from '@/features/shared'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
import { toDisplayText } from '@/lib/untrusted-text'
import { useOrganizations } from '@console/features/admin-console/api/use-admin-organizations'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { CreateOrganizationDialog } from '@console/features/admin-console/components/create-organization-dialog'
import { SSOPostureBadges } from '@console/features/admin-console/components/sso-posture-badges'
import { OwnerInvitationBadge } from '@console/features/admin-console/components/owner-invitation'
import {
  ORG_STATUSES,
  OrganizationStatePill,
  type OrgStatus,
} from '@console/features/admin-console/components/organization-state-pill'
import { organizationHref } from '@console/features/admin-console/lib/console-links'
import { type AdminOrganization, adminHas } from '@console/features/admin-console/types'

export default function AdminOrganizationsPage() {
  const admin = useAdmin()
  const router = useRouter()
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page, per_page, q and
  // the filters, so the overview can link to "organizations without an owner".
  const list = useListParams({ defaultPageSize: 25, filters: { owner: '', status: '' } })
  const debounced = list.searchTerm
  const owner =
    list.filters.owner === 'none' || list.filters.owner === 'present' ? list.filters.owner : ''
  const status = (ORG_STATUSES as readonly string[]).includes(list.filters.status)
    ? (list.filters.status as OrgStatus)
    : ''
  const filtered = Boolean(debounced || owner || status)
  const { data, error, isLoading, isValidating, mutate } = useOrganizations({
    search: debounced.trim(),
    owner,
    status,
    page: list.page,
    perPage: list.perPage,
  })
  const total = data?.total ?? 0

  const columns = useMemo<ColumnDef<AdminOrganization>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.org.col.organization', 'Organization'),
        // The organization is the row's name: it stays in view while the
        // table scrolls sideways and links to the organization's page.
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: 200,
          label: t('admin.org.col.organization', 'Organization'),
        },
        cell: ({ row }) => {
          const href = organizationHref(row.original.id)
          return (
            // The name keeps its room (up to 70 % of the cell); the slug is the
            // one that gives way.
            <span className="flex min-w-0 items-baseline gap-2">
              <span className="flex max-w-[70%] min-w-0 shrink-0">
                <RowNameLink
                  href={href}
                  onOpen={() => router.push(href)}
                  title={toDisplayText(row.original.name)}
                >
                  {toDisplayText(row.original.name)}
                </RowNameLink>
              </span>
              <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
                {row.original.slug}
              </span>
            </span>
          )
        },
      },
      {
        accessorKey: 'owner_domains',
        header: t('admin.org.col.owner', 'Owner'),
        meta: { kind: 'text', width: 160, label: t('admin.org.col.owner', 'Owner') },
        cell: ({ row }) => {
          // The list carries the owners' domains, never their addresses.
          const owners = row.original.owner_domains
          if (owners.length === 0 && row.original.owner_count > 0)
            return (
              <span className="text-muted-foreground">
                {t('admin.org.ownerCount', '{count, plural, one {# owner} other {# owners}}', {
                  count: row.original.owner_count,
                })}
              </span>
            )
          if (owners.length === 0 && row.original.owner_invitation)
            return <OwnerInvitationBadge invitation={row.original.owner_invitation} />
          if (owners.length === 0)
            return (
              <Badge variant="outline" className="border-warning/50 text-warning">
                {t('admin.org.noOwner', 'No owner')}
              </Badge>
            )
          return (
            <span className="flex min-w-0 gap-1" title={owners.join(', ')}>
              <span className="truncate">{owners[0]}</span>
              {owners.length > 1 && (
                <span className="shrink-0 text-muted-foreground">+{owners.length - 1}</span>
              )}
            </span>
          )
        },
      },
      {
        accessorKey: 'limits_apply',
        header: t('admin.org.col.limits', 'Limits'),
        meta: {
          kind: 'text',
          width: 104,
          hideBelow: 1040,
          label: t('admin.org.col.limits', 'Limits'),
        },
        cell: ({ row }) =>
          row.original.limits_apply ? (
            <Badge variant="secondary" data-testid="org-limits-apply">
              {t('admin.org.limitsSet', 'Limited')}
            </Badge>
          ) : (
            <span className="text-muted-foreground">{t('admin.org.noLimits', 'None')}</span>
          ),
      },
      {
        id: 'status',
        header: t('admin.org.col.status', 'Status'),
        meta: { kind: 'status', width: 152, label: t('admin.org.col.status', 'Status') },
        cell: ({ row }) => <OrganizationStatePill status={row.original.status} />,
      },
      {
        accessorKey: 'active_members',
        header: t('admin.org.col.members', 'Members'),
        meta: {
          kind: 'number',
          width: 88,
          hideBelow: 760,
          label: t('admin.org.col.members', 'Members'),
        },
        cell: ({ row }) => <span className="tabular-nums">{row.original.active_members}</span>,
      },
      {
        id: 'last_sign_in',
        header: t('admin.org.col.lastSignIn', 'Last member sign-in'),
        // On the organization's page too: it gives way on a tablet frame, so
        // the list never scrolls sideways there.
        meta: {
          kind: 'datetime-recent',
          width: 160,
          hideBelow: 800,
          label: t('admin.org.col.lastSignIn', 'Last member sign-in'),
        },
        cell: ({ row }) =>
          row.original.last_member_sign_in_at ? (
            <RelativeTime date={row.original.last_member_sign_in_at} />
          ) : (
            <span className="text-muted-foreground">
              {t('admin.org.neverSignedIn', 'Nobody yet')}
            </span>
          ),
      },
      {
        id: 'sso',
        header: t('admin.org.col.sso', 'Single sign-on'),
        meta: {
          kind: 'tags',
          width: 184,
          hideBelow: 900,
          label: t('admin.org.col.sso', 'Single sign-on'),
        },
        cell: ({ row }) => (
          <span className="flex min-w-0 overflow-hidden ps-3 whitespace-nowrap *:flex-nowrap">
            <SSOPostureBadges org={row.original} />
          </span>
        ),
      },
      {
        accessorKey: 'created_at',
        header: t('admin.org.col.created', 'Created'),
        meta: {
          kind: 'date',
          width: 152,
          hideBelow: 1560,
          label: t('admin.org.col.created', 'Created'),
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
          title={t('admin.nav.organizations', 'Organizations')}
          description={t(
            'admin.org.listDescription',
            'Every organization on this installation, with its owner, limits and single sign-on setup.'
          )}
        >
          {adminHas(admin, 'platform.tenants.create') && (
            <CreateOrganizationDialog onCreated={(org) => router.push(organizationHref(org.id))} />
          )}
        </PageHeader>
        <ListTitleRow
          title={t('admin.org.viewAll', 'All organizations')}
          count={
            <ListCount
              total={total}
              loading={!data}
              label={t(
                'admin.org.total',
                '{count, plural, one {# organization} other {# organizations}}',
                { count: total }
              )}
            />
          }
        />
        <DataTable
          columns={columns}
          data={data?.data ?? []}
          caption={t('admin.nav.organizations', 'Organizations')}
          getRowId={(o) => o.id}
          error={error}
          onRetry={() => void mutate()}
          errorTitle={t('admin.organizationsPage.organizations', 'organizations')}
          // The first read: skeleton rows under a toolbar that stays mounted.
          isLoading={isLoading && !data}
          isRefreshing={isValidating && !!data}
          refreshingLabel={t('admin.org.refreshing', 'Refreshing organizations')}
          showSearch={false}
          showSelectionCount={false}
          mobileCards
          onRowClick={(o) => router.push(organizationHref(o.id))}
          isFiltered={filtered}
          onClearFilters={list.reset}
          emptyState={{
            nothingYet: (
              <EmptyState icon={Building2} title={t('admin.org.empty', 'No organizations yet')} />
            ),
            noMatch: {
              title: t('admin.org.emptyFiltered', 'No organization matches these filters'),
            },
          }}
          manualPagination
          pageCount={data?.total_pages ?? 1}
          rowCount={total}
          pagination={list.pagination}
          onPaginationChange={list.setPagination}
          paginationNoun={t('admin.org.noun', 'organizations')}
          search={{
            value: list.q,
            onChange: list.setSearch,
            placeholder: t('admin.org.search', 'Search name or slug…'),
            label: t('admin.org.searchLabel', 'Search organizations'),
          }}
          toolbarStart={
            <>
              <FilterSelect<OrgStatus>
                label={t('admin.org.col.status', 'Status')}
                value={status}
                foldLabel
                onChange={(v) => list.setFilter('status', v)}
                options={[
                  { value: 'active', label: t('admin.org.status.active', 'Active') },
                  { value: 'suspended', label: t('admin.org.suspension.badge', 'Suspended') },
                  {
                    value: 'pending_deletion',
                    label: t('admin.org.deletion.badge', 'Deletion scheduled'),
                  },
                ]}
              />
              <FilterSelect<'none' | 'present'>
                label={t('admin.org.col.owner', 'Owner')}
                value={owner}
                foldLabel
                onChange={(v) => list.setFilter('owner', v)}
                allLabel={t('admin.org.ownerAny', 'Any owner')}
                options={[
                  { value: 'none', label: t('admin.org.ownerNone', 'Without an owner') },
                  { value: 'present', label: t('admin.org.ownerPresent', 'With an owner') },
                ]}
              />
            </>
          }
        />
      </PageStack>
    </Main>
  )
}
