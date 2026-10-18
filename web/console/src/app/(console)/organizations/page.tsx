'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Search } from 'lucide-react'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DataTable, ErrorState, PageHeader, RelativeTime, StackedCell } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDebounce } from '@/hooks/use-debounce'
import { useListParams } from '@/hooks/use-list-params'
import { useOrganizations } from '@console/features/admin-console/api/use-admin-organizations'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { CreateOrganizationDialog } from '@console/features/admin-console/components/create-organization-dialog'
import { SSOPostureBadges } from '@console/features/admin-console/components/sso-posture-badges'
import { OrganizationStatusBadge } from '@console/features/admin-console/components/organization-suspension'
import { adminCan, type AdminOrganization } from '@console/features/admin-console/types'

const ANY = 'any'

export default function AdminOrganizationsPage() {
  const admin = useAdmin()
  const router = useRouter()
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page, per_page, q and
  // the filters, so the overview can link to "organizations without an owner".
  const list = useListParams({ defaultPageSize: 20, filters: { owner: '' } })
  const debounced = useDebounce(list.q, 300)
  const owner =
    list.filters.owner === 'none' || list.filters.owner === 'present' ? list.filters.owner : ''
  const filtered = Boolean(debounced || owner)
  const { data, error, isLoading, mutate } = useOrganizations({
    search: debounced.trim(),
    owner,
    page: list.page,
    perPage: list.perPage,
  })

  const columns = useMemo<ColumnDef<AdminOrganization>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('admin.org.col.organization', 'Organization'),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <StackedCell primary={row.original.name} secondary={row.original.slug} />
            <OrganizationStatusBadge org={row.original} />
          </div>
        ),
      },
      {
        accessorKey: 'owner_emails',
        header: t('admin.org.col.owner', 'Owner'),
        cell: ({ row }) => {
          const owners = row.original.owner_emails
          if (owners.length === 0 && row.original.owner_count > 0)
            return (
              <span className="text-sm text-muted-foreground">
                {t('admin.org.ownerCount', '{count} owner(s)', { count: row.original.owner_count })}
              </span>
            )
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
        accessorKey: 'active_members',
        header: t('admin.org.col.members', 'Members'),
        cell: ({ row }) => <span className="tabular-nums">{row.original.active_members}</span>,
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
      <PageHeader
        title={t('admin.nav.organizations', 'Organizations')}
        description={t(
          'admin.org.listDescription',
          'Every organization on this installation, with its owner, limits and single sign-on setup.'
        )}
      >
        {adminCan(admin.role, 'ops_admin') && (
          <CreateOrganizationDialog onCreated={(org) => router.push(`/organizations/${org.id}`)} />
        )}
      </PageHeader>
      <div className="mt-5">
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
            toolbarStart={
              <div className="flex w-full flex-col gap-2 sm:flex-row">
                <div className="relative w-full sm:max-w-xs">
                  <Search className="absolute start-2.5 top-2.5 size-4 text-muted-foreground" />
                  <Input
                    placeholder={t('admin.org.search', 'Search name or slug...')}
                    value={list.q}
                    onChange={(e) => list.setSearch(e.target.value)}
                    className="ps-8"
                    aria-label={t('admin.org.searchLabel', 'Search organizations')}
                  />
                </div>
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
              </div>
            }
          />
        )}
      </div>
    </Main>
  )
}
