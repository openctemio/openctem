'use client'

import { HealthStatus } from '@/components/ui/health-status'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { OUTBOX_HEALTH } from '@/features/notifications/lib/outbox-health'
import { useState } from 'react'
import { useListParams } from '@/hooks/use-list-params'
import type { ColumnDef } from '@tanstack/react-table'
import { MoreHorizontal, Loader2, RotateCcw, Trash2, ExternalLink, AlertCircle } from 'lucide-react'
import { toast } from 'sonner'

import { Main } from '@/components/layout'
import { ErrorState, DataTable, PageStack } from '@/features/shared'
import { RefreshButton } from '@/components/list-page-parts'
import { NotificationSectionHeader } from '@/features/integrations/components/notification-sections'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'

import {
  useNotificationOutboxApi,
  useNotificationOutboxStatsApi,
  useRetryOutboxEntryApi,
  useDeleteOutboxEntryApi,
  invalidateNotificationOutboxCache,
  invalidateNotificationOutboxStatsCache,
} from '@/features/notifications/api/use-notification-outbox-api'
import {
  type OutboxEntry,
  type OutboxStatus,
} from '@/features/notifications/types/notification-outbox.types'
import { safeHref } from '@/lib/safe-href'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime } from '@/features/shared/components/relative-time'

// Queue Health Status component
function QueueHealthStatus({
  stats,
  isLoading,
  onViewFailed,
}: {
  stats: { pending: number; processing: number; failed: number; dead: number }
  isLoading: boolean
  onViewFailed: () => void
}) {
  const { t } = useTranslation()
  if (isLoading) {
    return <Skeleton className="h-16 w-full rounded-lg" />
  }

  const hasIssues = stats.failed > 0 || stats.dead > 0
  // Only a problem earns a banner above the list: a healthy or busy queue is
  // read from the table itself (its rows carry their status), so a box of its
  // own there was a wasted row.
  if (!hasIssues) return null

  // Build status parts
  const parts: string[] = []
  if (stats.pending > 0)
    parts.push(
      t('notificationChannels.outbox.count.pending', '{count} pending', { count: stats.pending })
    )
  if (stats.processing > 0)
    parts.push(
      t('notificationChannels.outbox.count.processing', '{count} processing', {
        count: stats.processing,
      })
    )
  if (stats.failed > 0)
    parts.push(
      t('notificationChannels.outbox.count.failed', '{count} failed', { count: stats.failed })
    )
  if (stats.dead > 0)
    parts.push(t('notificationChannels.outbox.count.dead', '{count} dead', { count: stats.dead }))

  return (
    <Alert variant="destructive">
      <AlertCircle className="h-4 w-4" />
      <AlertTitle>{parts.join(', ')}</AlertTitle>
      <AlertDescription>
        {t('notificationChannels.outbox.needAttention', 'Some notifications need attention')}
        <div className="mt-2">
          <Button variant="outline" size="sm" onClick={onViewFailed}>
            {t('notificationChannels.outbox.viewIssues', 'View Issues')}
          </Button>
        </div>
      </AlertDescription>
    </Alert>
  )
}

export default function NotificationOutboxPage() {
  const { t, locale } = useTranslation()
  const statusLabel = (s: string) =>
    t(`notificationChannels.outbox.status.${s}`, OUTBOX_HEALTH[s as OutboxStatus]?.label ?? s)
  // State
  // The list lives in the URL (one list convention): page, per_page, status.
  const list = useListParams({ filters: { status: 'all' } })
  const statusFilter = list.filters.status as OutboxStatus | 'all'
  const setStatusFilter = (value: OutboxStatus | 'all') => list.setFilter('status', value)
  const { pagination, setPagination, setPage } = list
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [selectedEntry, setSelectedEntry] = useState<OutboxEntry | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)

  // Fetch data
  const {
    data: statsData,
    error: statsError,
    isLoading: statsLoading,
    mutate: mutateStats,
  } = useNotificationOutboxStatsApi()
  const {
    data: entriesData,
    error: entriesError,
    isLoading: entriesLoading,
    mutate: mutateEntries,
  } = useNotificationOutboxApi({
    status: statusFilter === 'all' ? undefined : statusFilter,
    page: pagination.pageIndex + 1,
    per_page: pagination.pageSize,
  })

  // Mutations
  const mayRetryRoute = useCanMutate('POST /api/v1/notification-outbox/{id}/retry')
  const mayDeleteRoute = useCanMutate('DELETE /api/v1/notification-outbox/{id}')
  const { trigger: retryEntry, isMutating: isRetrying } = useRetryOutboxEntryApi()
  const { trigger: deleteEntry, isMutating: isDeleting } = useDeleteOutboxEntryApi(
    selectedEntry?.id || ''
  )

  const entries = entriesData?.data ?? []
  const stats = statsData ?? {
    pending: 0,
    processing: 0,
    completed: 0,
    failed: 0,
    dead: 0,
    total: 0,
  }

  // Handlers
  const handleRefresh = async () => {
    await Promise.all([mutateStats(), mutateEntries()])
    toast.success(t('notificationChannels.outbox.toast.refreshed', 'Data refreshed'))
  }

  const handleViewFailed = () => {
    setStatusFilter('failed')
    setPage(1)
  }

  const handleRetry = async (entry: OutboxEntry) => {
    if (actionInProgress) return
    setActionInProgress(entry.id)

    try {
      await retryEntry(entry.id)
      await invalidateNotificationOutboxCache()
      await invalidateNotificationOutboxStatsCache()
      await Promise.all([mutateStats(), mutateEntries()])
      toast.success(t('notificationChannels.outbox.toast.retried', 'Entry scheduled for retry'))
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('notificationChannels.outbox.toast.retryFailed', 'Failed to retry entry')
        )
      )
    } finally {
      setActionInProgress(null)
    }
  }

  const handleDeleteClick = (entry: OutboxEntry) => {
    setSelectedEntry(entry)
    setDeleteDialogOpen(true)
  }

  const handleDeleteConfirm = async () => {
    if (!selectedEntry || actionInProgress) return
    setActionInProgress(selectedEntry.id)

    try {
      await deleteEntry()
      await invalidateNotificationOutboxCache()
      await invalidateNotificationOutboxStatsCache()
      await Promise.all([mutateStats(), mutateEntries()])
      toast.success(t('notificationChannels.outbox.toast.deleted', 'Entry deleted'))
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('notificationChannels.outbox.toast.deleteFailed', 'Failed to delete entry')
        )
      )
    } finally {
      setActionInProgress(null)
      setSelectedEntry(null)
      setDeleteDialogOpen(false)
    }
  }

  // The API cannot sort the queue, so the headers are plain text. Rebuilt each
  // render: the row actions close over the latest in-flight state.
  const columns: ColumnDef<OutboxEntry>[] = [
    {
      accessorKey: 'title',
      header: t('notificationChannels.outbox.col.title', 'Title'),
      meta: { kind: 'name' },
      cell: ({ row }) => {
        const entry = row.original
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="max-w-[250px]">
                <p className="truncate font-medium">{entry.title}</p>
                {entry.body && (
                  <p className="truncate text-xs text-muted-foreground">{entry.body}</p>
                )}
              </div>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-[400px]">
              <p className="font-medium">{entry.title}</p>
              {entry.body && <p className="mt-1 text-sm">{entry.body}</p>}
            </TooltipContent>
          </Tooltip>
        )
      },
    },
    {
      accessorKey: 'event_type',
      header: t('notificationChannels.outbox.col.event', 'Event'),
      meta: { kind: 'text', hideBelow: 960 },
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.original.event_type}</span>
          <span className="text-xs text-muted-foreground">{row.original.aggregate_type}</span>
        </div>
      ),
    },
    {
      accessorKey: 'severity',
      header: t('notificationChannels.outbox.col.severity', 'Severity'),
      meta: { kind: 'severity' },
      cell: ({ row }) => {
        return (
          <SeverityBadge severity={row.original.severity}>
            {t(`notificationChannels.severity.${row.original.severity}`)}
          </SeverityBadge>
        )
      },
    },
    {
      accessorKey: 'status',
      header: t('notificationChannels.outbox.col.status', 'Status'),
      meta: { kind: 'status' },
      cell: ({ row }) => {
        const entry = row.original
        const health = OUTBOX_HEALTH[entry.status]
        return (
          <>
            <HealthStatus
              state={health.state}
              value={entry.status}
              label={statusLabel(entry.status)}
              detail={
                entry.status === 'dead'
                  ? t('notificationChannels.outbox.deadLetter', 'dead letter')
                  : undefined
              }
            />
            {entry.last_error && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="mt-1 max-w-[150px] truncate text-xs text-destructive">
                    {entry.last_error}
                  </p>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-[400px]">
                  <p className="text-sm">{entry.last_error}</p>
                </TooltipContent>
              </Tooltip>
            )}
          </>
        )
      },
    },
    {
      id: 'retries',
      header: t('notificationChannels.outbox.col.retries', 'Retries'),
      meta: { kind: 'number', hideBelow: 1100 },
      cell: ({ row }) => (
        <span className="text-sm tabular-nums">
          {row.original.retry_count} / {row.original.max_retries}
        </span>
      ),
    },
    {
      accessorKey: 'scheduled_at',
      header: t('notificationChannels.outbox.col.scheduled', 'Scheduled'),
      meta: { kind: 'datetime-recent' },
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          <RelativeTime date={row.original.scheduled_at} />
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) => {
        const entry = row.original
        const canRetry = entry.status === 'failed' || entry.status === 'dead'
        const sourceUrl = safeHref(entry.url)
        const busy = actionInProgress === entry.id
        const label = t('common.actionMenu.label', 'Actions for {name}', { name: entry.title })
        const items: ActionMenuEntry[] = [
          ...(sourceUrl
            ? [
                {
                  id: 'view-source',
                  label: t('notificationChannels.outbox.viewSource', 'View source'),
                  icon: ExternalLink,
                  onSelect: () => {
                    const u = safeHref(entry.url)
                    if (u) window.open(u, '_blank', 'noopener,noreferrer')
                  },
                },
              ]
            : []),
          ...(mayRetryRoute && canRetry
            ? [
                {
                  id: 'retry',
                  label: t('notificationChannels.outbox.retry', 'Retry'),
                  icon: RotateCcw,
                  disabledReason: isRetrying
                    ? t(
                        'notificationChannels.outbox.retryingReason',
                        'A retry is already in progress.'
                      )
                    : undefined,
                  onSelect: () => handleRetry(entry),
                },
              ]
            : []),
          ...(mayDeleteRoute
            ? [
                {
                  id: 'delete',
                  label: t('notificationChannels.outbox.delete', 'Delete'),
                  icon: Trash2,
                  destructive: true,
                  disabledReason: isDeleting
                    ? t(
                        'notificationChannels.outbox.deletingReason',
                        'A delete is already in progress.'
                      )
                    : undefined,
                  onSelect: () => handleDeleteClick(entry),
                },
              ]
            : []),
        ]
        return (
          <ActionMenu
            title={entry.title}
            label={label}
            items={items}
            trigger={
              <Button
                variant="ghost"
                size="icon-sm"
                className="p-0"
                aria-label={label}
                disabled={busy}
              >
                {busy ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                ) : (
                  <MoreHorizontal className="h-4 w-4" aria-hidden />
                )}
              </Button>
            }
          />
        )
      },
    },
  ]

  // A failed read would otherwise render an all-zero (i.e. healthy, empty) queue
  // while the real queue may be backed up with dead entries.
  const loadError = statsError ?? entriesError
  if (loadError) {
    return (
      <Main>
        <ErrorState
          title={t('notificationChannels.outbox.errorTitle', 'notification queue')}
          error={loadError}
          onRetry={() => {
            void mutateStats()
            void mutateEntries()
          }}
        />
      </Main>
    )
  }

  return (
    <>
      <Main>
        <PageStack>
          {/* The section's header stays as on Channels; the tabs show this
              sub-page and lead back (no back-link row). */}
          <NotificationSectionHeader />

          {/* Queue Health Status */}
          <QueueHealthStatus
            stats={stats}
            isLoading={statsLoading}
            onViewFailed={handleViewFailed}
          />

          {/* The entries table is always there, with the queue's filter and
              refresh in its toolbar, as on the other notification tabs. */}
          <div>
            <DataTable
              columns={columns}
              data={entries}
              getRowId={(e) => e.id}
              isLoading={entriesLoading}
              pinActions
              showSearch={false}
              toolbarEnd={
                <RefreshButton
                  onClick={() => void handleRefresh()}
                  loading={statsLoading || entriesLoading}
                />
              }
              toolbarStart={
                <Select
                  value={statusFilter}
                  onValueChange={(value) => {
                    setStatusFilter(value as OutboxStatus | 'all')
                    setPage(1)
                  }}
                >
                  <SelectTrigger
                    className="w-[160px]"
                    aria-label={t('notificationChannels.outbox.filterByStatus', 'Filter by status')}
                  >
                    <SelectValue
                      placeholder={t('notificationChannels.outbox.allStatuses', 'All statuses')}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">
                      {t('notificationChannels.outbox.allStatuses', 'All statuses')}
                    </SelectItem>
                    <SelectItem value="pending">{statusLabel('pending')}</SelectItem>
                    <SelectItem value="processing">{statusLabel('processing')}</SelectItem>
                    <SelectItem value="failed">{statusLabel('failed')}</SelectItem>
                    <SelectItem value="dead">{statusLabel('dead')}</SelectItem>
                  </SelectContent>
                </Select>
              }
              manualPagination
              rowCount={entriesData?.total ?? 0}
              pagination={pagination}
              onPaginationChange={setPagination}
              pageSize={pagination.pageSize}
              emptyMessage={t('notificationChannels.outbox.emptyMessage', 'No entries found')}
              emptyDescription={
                statusFilter !== 'all'
                  ? t(
                      'notificationChannels.outbox.emptyFiltered',
                      'No {status} entries in the queue',
                      {
                        status: statusLabel(statusFilter).toLocaleLowerCase(locale),
                      }
                    )
                  : t('notificationChannels.outbox.emptyQueue', 'The notification queue is empty')
              }
            />
          </div>

          {/* Delete Confirmation Dialog */}
          <ConfirmDialog
            open={deleteDialogOpen}
            onOpenChange={setDeleteDialogOpen}
            title={t('confirm.outbox.deleteTitle', 'Delete this notification entry?')}
            desc={
              <>
                {t(
                  'confirm.outbox.deleteDesc',
                  'The entry leaves the outbox and is not sent or retried. This cannot be undone.'
                )}
                {selectedEntry && (
                  <span className="mt-2 block font-medium">{selectedEntry.title}</span>
                )}
              </>
            }
            confirmText={
              isDeleting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {t('confirm.deleting', 'Deleting…')}
                </>
              ) : (
                t('confirm.delete', 'Delete')
              )
            }
            destructive
            isLoading={isDeleting}
            handleConfirm={() => void handleDeleteConfirm()}
          />
        </PageStack>
      </Main>
    </>
  )
}
