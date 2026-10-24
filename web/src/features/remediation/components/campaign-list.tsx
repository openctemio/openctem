'use client'

/**
 * The campaign list (/remediation/campaigns): each campaign with its owner,
 * due date, status, tasks and findings closed. Pages, filters and the status
 * counts come from the server.
 */

import { useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Flag, Plus } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { DataTable, FilterSelect, ListToolbar, PageStack } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { StatusChip } from '@/features/shared/components/status-chip'
import { HubPage } from '@/features/remediation-hub/components/hub-page'
import {
  CAMPAIGN_STATUSES,
  type CampaignStatus,
  type RemediationCampaign,
  campaignApi,
  useCampaignStatusCounts,
  useRemediationCampaigns,
  useRevalidateCampaigns,
} from '../api/use-remediation-campaigns'
import { CampaignDue, CampaignTasksCell, FindingsProgress, useCampaignOwner } from './campaign-bits'
import { CampaignFormDialog } from './campaign-form-dialog'
import { useSearchQuery } from '@/hooks/use-search-query'

type StatusFilter = CampaignStatus | 'all'

export function CampaignList() {
  const { t } = useTranslation()
  const router = useRouter()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  const ownerOf = useCampaignOwner()
  const revalidate = useRevalidateCampaigns()
  // The status is a filter of the rows, kept in the URL so a view can be linked.
  const [statusParam, setStatusParam] = useUrlFilter('status', '')
  const status: StatusFilter = (CAMPAIGN_STATUSES as readonly string[]).includes(statusParam)
    ? (statusParam as StatusFilter)
    : 'all'
  const [search, setSearch] = useState('')
  const searchTerm = useSearchQuery(search).term
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })
  const [createOpen, setCreateOpen] = useState(false)

  const { data, error, isLoading, mutate } = useRemediationCampaigns({
    status: status === 'all' ? undefined : status,
    search: searchTerm,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const counts = useCampaignStatusCounts(data)
  const rows = useMemo(() => data?.data ?? [], [data])

  const columns = useMemo<ColumnDef<RemediationCampaign>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('remediationCampaigns.columns.campaign'),
        cell: ({ row }) => (
          <div className="min-w-0 max-w-xs">
            <Link
              href={`/remediation/campaigns/${row.original.id}`}
              className="font-medium hover:underline"
            >
              {row.original.name}
            </Link>
            {row.original.description && (
              <div className="text-muted-foreground truncate text-xs">
                {row.original.description}
              </div>
            )}
          </div>
        ),
      },
      {
        id: 'owner',
        header: t('remediationCampaigns.columns.owner'),
        cell: ({ row }) => <span className="block min-w-28 text-sm">{ownerOf(row.original)}</span>,
      },
      {
        accessorKey: 'due_date',
        header: t('remediationCampaigns.columns.due'),
        cell: ({ row }) => (
          <span className="text-sm">
            <CampaignDue campaign={row.original} />
          </span>
        ),
      },
      {
        accessorKey: 'status',
        header: t('remediationCampaigns.columns.status'),
        cell: ({ row }) => <StatusChip domain="remediationCampaign" value={row.original.status} />,
      },
      {
        id: 'tasks',
        header: t('remediationCampaigns.columns.tasks'),
        cell: ({ row }) => <CampaignTasksCell summary={row.original.summary} />,
      },
      {
        id: 'progress',
        header: t('remediationCampaigns.columns.progress'),
        cell: ({ row }) => <FindingsProgress summary={row.original.summary} />,
      },
    ],
    [ownerOf, t]
  )

  const filtered = status !== 'all' || search.trim() !== ''

  return (
    <HubPage
      title={t('remediationCampaigns.title')}
      description={t('remediationCampaigns.description')}
      actions={
        canWrite && (
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" aria-hidden />
            {t('remediationCampaigns.actions.new')}
          </Button>
        )
      }
    >
      <PageStack>
        <ListToolbar
          start={
            <>
              <FilterSelect<Exclude<StatusFilter, 'all'>>
                label={t('remediationCampaigns.statusLabel', 'Status')}
                value={status === 'all' ? '' : status}
                allCount={counts?.all}
                options={CAMPAIGN_STATUSES.map((s) => ({
                  value: s,
                  label: t(`remediationCampaigns.filter.${s}`),
                  count: counts?.[s],
                }))}
                onChange={(next) => {
                  setStatusParam(next)
                  setPagination((p) => ({ ...p, pageIndex: 0 }))
                }}
              />
              <Input
                className="h-9 w-full sm:w-64"
                placeholder={t('remediationCampaigns.search')}
                aria-label={t('remediationCampaigns.search')}
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value)
                  setPagination((p) => ({ ...p, pageIndex: 0 }))
                }}
              />
            </>
          }
        />

        {error ? (
          <ErrorState
            title={t('remediationCampaigns.loadError')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : !isLoading && rows.length === 0 && !filtered ? (
          <EmptyState
            icon={Flag}
            title={t('remediationCampaigns.empty.title')}
            description={t('remediationCampaigns.empty.description')}
            action={
              canWrite ? (
                <Button onClick={() => setCreateOpen(true)}>
                  <Plus className="size-4" aria-hidden />
                  {t('remediationCampaigns.actions.new')}
                </Button>
              ) : undefined
            }
            card
          />
        ) : (
          <DataTable
            columns={columns}
            data={rows}
            showSearch={false}
            isLoading={isLoading}
            manualPagination
            rowCount={data?.total ?? 0}
            pageCount={data ? Math.max(1, Math.ceil(data.total / pagination.pageSize)) : 1}
            pagination={pagination}
            onPaginationChange={setPagination}
            getRowId={(r) => r.id}
            onRowClick={(r) => router.push(`/remediation/campaigns/${r.id}`)}
            emptyMessage={t('remediationCampaigns.empty.filtered')}
            mobileRow={(c) => (
              <div className="bg-card space-y-2 rounded-md border p-3 text-sm">
                <div className="flex items-start justify-between gap-2">
                  <Link
                    href={`/remediation/campaigns/${c.id}`}
                    className="font-medium hover:underline"
                  >
                    {c.name}
                  </Link>
                  <StatusChip domain="remediationCampaign" value={c.status} />
                </div>
                <div className="text-muted-foreground text-xs">
                  {ownerOf(c)} · <CampaignDue campaign={c} />
                </div>
                <div>
                  <CampaignTasksCell summary={c.summary} />
                </div>
                <FindingsProgress summary={c.summary} />
              </div>
            )}
          />
        )}
      </PageStack>

      <CampaignFormDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSubmit={async (fields) => {
          const created = await campaignApi.create(fields)
          toast.success(t('remediationCampaigns.toast.created', undefined, { name: created.name }))
          void revalidate()
          router.push(`/remediation/campaigns/${created.id}`)
        }}
      />
    </HubPage>
  )
}
