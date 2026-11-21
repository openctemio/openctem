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
import { DataTable, FilterSelect, PageStack, ToolbarAction } from '@/features/shared'
import { useUrlFilter } from '@/hooks/use-url-param'
import { EmptyState } from '@/features/shared/components/empty-state'
import { MetaLine } from '@/features/shared/components/text-layout'
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

/** Table frame widths (px) under which a column folds away; the name and the status stay. */
export const CAMPAIGN_HIDE_BELOW = { owner: 560, tasks: 700, progress: 840 } as const

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

  // Board order: the campaign, its status, who owns it, its tasks, the
  // findings it closed, then the due date. Widths come from the column kinds.
  const columns = useMemo<ColumnDef<RemediationCampaign>[]>(
    () => [
      {
        accessorKey: 'name',
        header: t('remediationCampaigns.columns.campaign'),
        meta: { kind: 'name', label: t('remediationCampaigns.columns.campaign') },
        cell: ({ row }) => (
          <div className="min-w-0">
            <Link
              href={`/remediation/campaigns/${row.original.id}`}
              className="block truncate font-medium hover:underline"
              title={row.original.name}
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
        accessorKey: 'status',
        header: t('remediationCampaigns.columns.status'),
        meta: { kind: 'status', label: t('remediationCampaigns.columns.status') },
        cell: ({ row }) => <StatusChip domain="remediationCampaign" value={row.original.status} />,
      },
      {
        id: 'owner',
        header: t('remediationCampaigns.columns.owner'),
        meta: {
          kind: 'owner',
          label: t('remediationCampaigns.columns.owner'),
          hideBelow: CAMPAIGN_HIDE_BELOW.owner,
        },
        cell: ({ row }) => (
          <span className="block truncate text-sm" title={ownerOf(row.original)}>
            {ownerOf(row.original)}
          </span>
        ),
      },
      {
        id: 'tasks',
        header: t('remediationCampaigns.columns.tasks'),
        meta: {
          kind: 'text',
          label: t('remediationCampaigns.columns.tasks'),
          width: 128,
          hideBelow: CAMPAIGN_HIDE_BELOW.tasks,
        },
        cell: ({ row }) => <CampaignTasksCell summary={row.original.summary} />,
      },
      {
        id: 'progress',
        header: t('remediationCampaigns.columns.progress'),
        meta: {
          kind: 'text',
          label: t('remediationCampaigns.columns.progress'),
          width: 176,
          hideBelow: CAMPAIGN_HIDE_BELOW.progress,
        },
        cell: ({ row }) => <FindingsProgress summary={row.original.summary} />,
      },
      {
        accessorKey: 'due_date',
        header: t('remediationCampaigns.columns.due'),
        meta: { kind: 'due', label: t('remediationCampaigns.columns.due') },
        cell: ({ row }) => (
          <span className="text-sm">
            <CampaignDue campaign={row.original} />
          </span>
        ),
      },
    ],
    [ownerOf, t]
  )

  const filtered = status !== 'all' || search.trim() !== ''

  const clearFilters = () => {
    setSearch('')
    setStatusParam('')
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }
  const newCampaign = canWrite ? (
    <Button onClick={() => setCreateOpen(true)}>
      <Plus aria-hidden />
      {t('remediationCampaigns.actions.new')}
    </Button>
  ) : undefined

  return (
    <HubPage
      title={t('remediationCampaigns.title')}
      description={t('remediationCampaigns.description')}
    >
      <PageStack>
        <DataTable
          columns={columns}
          data={rows}
          search={{
            value: search,
            onChange: (v) => {
              setSearch(v)
              setPagination((p) => ({ ...p, pageIndex: 0 }))
            },
            placeholder: t('remediationCampaigns.search'),
          }}
          toolbarStart={
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
          }
          toolbarEnd={
            canWrite && (
              <ToolbarAction
                icon={Plus}
                label={t('remediationCampaigns.actions.new')}
                onClick={() => setCreateOpen(true)}
              />
            )
          }
          isLoading={isLoading}
          error={error && !data ? error : undefined}
          errorTitle={t('remediationCampaigns.loadError')}
          onRetry={() => void mutate()}
          isFiltered={filtered}
          onClearFilters={clearFilters}
          emptyState={{
            nothingYet: (
              <EmptyState
                icon={Flag}
                title={t('remediationCampaigns.empty.title')}
                description={t('remediationCampaigns.empty.description')}
                action={newCampaign}
                card
              />
            ),
            noMatch: {
              title: t('remediationCampaigns.empty.filtered'),
              hint: t('remediationCampaigns.empty.filteredHint'),
            },
          }}
          manualPagination
          rowCount={data?.total ?? 0}
          pageCount={data ? Math.max(1, Math.ceil(data.total / pagination.pageSize)) : 1}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.id}
          onRowClick={(r) => router.push(`/remediation/campaigns/${r.id}`)}
          paginationNoun={t('remediationCampaigns.noun')}
          mobileRow={(c) => (
            <div data-slot="campaign-card" className="flex min-w-0 flex-col gap-1 px-3 py-3">
              <div className="flex min-w-0 items-center justify-between gap-3">
                <Link
                  href={`/remediation/campaigns/${c.id}`}
                  className="min-w-0 truncate font-medium hover:underline"
                  title={c.name}
                >
                  {c.name}
                </Link>
                <StatusChip domain="remediationCampaign" value={c.status} className="shrink-0" />
              </div>
              <p className="text-meta truncate">{ownerOf(c)}</p>
              <MetaLine
                items={[
                  <CampaignTasksCell key="tasks" summary={c.summary} />,
                  <CampaignDue key="due" campaign={c} />,
                ]}
              />
              <FindingsProgress summary={c.summary} />
            </div>
          )}
        />
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
