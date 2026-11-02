'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DataTable,
  ErrorState,
  FilterSelect,
  PageHeader,
  PageStack,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useListParams } from '@/hooks/use-list-params'
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
import { type AdminOrganization, adminHas } from '@console/features/admin-console/types'

const ANY = 'any'

export default function AdminOrganizationsPage() {
  const admin = useAdmin()
  const router = useRouter()
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page, per_page, q and
  // the filters, so the overview can link to "organizations without an owner".
  const list = useListParams({ defaultPageSize: 20, filters: { owner: '', status: '' } })
  const debounced = list.searchTerm
  const owner =
    list.filters.owner === 'none' || list.filters.owner === 'present' ? list.filters.owner : ''
  const status = (ORG_STATUSES as readonly string[]).includes(list.filters.status)
    ? (list.filters.status as OrgStatus)
    : ''
  const filtered = Boolean(debounced || owner || status)
  const { data, error, isLoading, mutate } = useOrganizations({
    search: debounced.trim(),
    owner,
    status,
    page: list.page,
    perPage: list.perPage,
  })

  const columns = useMemo<ColumnDef<AdminOrganization>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.org.col.organization', 'Organization'),
        cell: ({ row }) => (
          <StackedCell primary={row.original.name} secondary={row.original.slug} />
        ),
      },
      {
        accessorKey: 'owner_domains',
        header: t('admin.org.col.owner', 'Owner'),
        cell: ({ row }) => {
          // The list carries the owners' domains, never their addresses.
          const owners = row.original.owner_domains
          if (owners.length === 0 && row.original.owner_count > 0)
            return (
              <span className="text-sm text-muted-foreground">
                {t('admin.org.ownerCount', '{count} owner(s)', { count: row.original.owner_count })}
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
            <span className="text-sm">
              {owners[0]}
              {owners.length > 1 && (
                <span className="text-muted-foreground"> +{owners.length - 1}</span>
              )}
            </span>
          )
        },
      },
      {
        accessorKey: 'limits_apply',
        header: t('admin.org.col.limits', 'Limits'),
        cell: ({ row }) =>
          row.original.limits_apply ? (
            <Badge variant="secondary" data-testid="org-limits-apply">
              {t('admin.org.limitsSet', 'Limited')}
            </Badge>
          ) : (
            <span className="text-sm text-muted-foreground">{t('admin.org.noLimits', 'None')}</span>
          ),
      },
      {
        id: 'status',
        header: t('admin.org.col.status', 'Status'),
        cell: ({ row }) => <OrganizationStatePill status={row.original.status} />,
      },
      {
        accessorKey: 'active_members',
        header: t('admin.org.col.members', 'Members'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.active_members}</span>,
      },
      {
        id: 'last_sign_in',
        header: t('admin.org.col.lastSignIn', 'Last member sign-in'),
        cell: ({ row }) =>
          row.original.last_member_sign_in_at ? (
            <RelativeTime date={row.original.last_member_sign_in_at} className="text-sm" />
          ) : (
            <span className="text-sm text-muted-foreground">
              {t('admin.org.neverSignedIn', 'Nobody yet')}
            </span>
          ),
      },
      {
        id: 'sso',
        header: t('admin.org.col.sso', 'Single sign-on'),
        cell: ({ row }) => <SSOPostureBadges org={row.original} />,
      },
      {
        accessorKey: 'created_at',
        header: t('admin.org.col.created', 'Created'),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} className="text-sm" />,
      },
    ],
    [t]
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
            <CreateOrganizationDialog
              onCreated={(org) => router.push(`/organizations/${org.id}`)}
            />
          )}
        </PageHeader>
        {error ? (
          <ErrorState
            title={t('admin.organizationsPage.organizations', 'organizations')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data ?? []}
            getRowId={(o) => o.id}
            isLoading={isLoading}
            showSearch={false}
            showColumnToggle={false}
            showSelectionCount={false}
            mobileCards
            onRowClick={(o) => router.push(`/organizations/${o.id}`)}
            emptyMessage={
              filtered
                ? t('admin.org.emptyFiltered', 'No organization matches these filters')
                : t('admin.org.empty', 'No organizations yet')
            }
            manualPagination
            pageCount={data?.total_pages ?? 1}
            rowCount={data?.total ?? 0}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
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
                <Select
                  value={owner || ANY}
                  onValueChange={(v) => list.setFilter('owner', v === ANY ? '' : v)}
                >
                  <SelectTrigger
                    className="sm:w-44"
                    aria-label={t('admin.org.ownerFilter', 'Filter by owner')}
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ANY}>{t('admin.org.ownerAny', 'Any owner')}</SelectItem>
                    <SelectItem value="none">
                      {t('admin.org.ownerNone', 'Without an owner')}
                    </SelectItem>
                    <SelectItem value="present">
                      {t('admin.org.ownerPresent', 'With an owner')}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </>
            }
          />
        )}
      </PageStack>
    </Main>
  )
}
