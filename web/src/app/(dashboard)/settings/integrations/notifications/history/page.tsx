'use client'

import { useState, useCallback, useEffect, useMemo, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { useUrlParam } from '@/hooks/use-url-param'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from 'sonner'
import { Bell, ExternalLink } from 'lucide-react'
import {
  DataTable,
  EmptyState,
  ErrorState,
  PageStack,
  RunStatusBadge,
  SeverityBadge,
} from '@/features/shared'
import type { Severity } from '@/features/shared/types'
import { RefreshButton } from '@/components/list-page-parts'
import {
  NOTIFICATION_PROVIDER_LABELS,
  NotificationSectionHeader,
} from '@/features/integrations/components/notification-sections'
import { Can } from '@/lib/permissions'
import {
  useNotificationIntegrationsApi,
  useNotificationEventsApi,
  invalidateNotificationEventsCache,
  integrationIdFromParam,
} from '@/features/integrations/api/use-integrations-api'
import type { NotificationEventEntry } from '@/features/integrations/types/integration.types'
import { safeHref } from '@/lib/safe-href'
import { useTranslation } from '@/context/i18n-provider'
import { SafeExternalLink } from '@/components/safe-external-link'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { DEFAULT_TABLE_PAGE_SIZE } from '@/lib/page-size-options'
import { formatDateTime } from '@/lib/app-locale'

/** The channel's own delivery result wins over the event-wide status. */
function deliveryStatus(entry: NotificationEventEntry): string {
  const sendResult = entry.send_results?.[0]
  if (sendResult?.status === 'success') return 'completed'
  if (sendResult?.status === 'failed') return 'failed'
  return entry.status
}

type Translate = ReturnType<typeof useTranslation>['t']

function buildColumns(t: Translate): ColumnDef<NotificationEventEntry>[] {
  return [
    {
      accessorKey: 'title',
      header: t('notificationChannels.history.col.title', 'Title'),
      cell: ({ row }) => {
        const entry = row.original
        const sendResult = entry.send_results?.[0]
        return (
          <div className="min-w-0 max-w-md space-y-0.5">
            <p className="font-medium">{entry.title}</p>
            {entry.body && (
              <p className="line-clamp-2 text-xs text-muted-foreground">{entry.body}</p>
            )}
            {sendResult?.status === 'failed' && sendResult.error && (
              <p className="text-xs text-destructive">
                {t('notificationChannels.history.errorPrefix', 'Error: {error}', {
                  error: sendResult.error,
                })}
              </p>
            )}
            {sendResult?.message_id && (
              <p className="text-xs text-muted-foreground">
                {t('notificationChannels.history.messageId', 'Message ID')}{' '}
                <span className="font-mono">{sendResult.message_id}</span>
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: 'integration',
      header: t('notificationChannels.history.col.integration', 'Integration'),
      cell: ({ row }) => {
        const sendResult = row.original.send_results?.[0]
        if (!sendResult) return <span className="text-muted-foreground">-</span>
        return (
          <div className="flex flex-col">
            <span>{sendResult.name}</span>
            <span className="text-xs capitalize text-muted-foreground">{sendResult.provider}</span>
          </div>
        )
      },
    },
    {
      accessorKey: 'severity',
      header: t('notificationChannels.history.col.severity', 'Severity'),
      cell: ({ row }) => <SeverityBadge severity={row.original.severity as Severity} />,
    },
    {
      id: 'status',
      header: t('notificationChannels.history.col.status', 'Status'),
      cell: ({ row }) => <RunStatusBadge status={deliveryStatus(row.original)} />,
    },
    {
      accessorKey: 'processed_at',
      header: t('notificationChannels.history.col.time', 'Time'),
      cell: ({ row }) => (
        <span
          className="whitespace-nowrap text-sm text-muted-foreground"
          title={formatDateTime(new Date(row.original.processed_at))}
        >
          <RelativeTime date={row.original.processed_at} />
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) =>
        safeHref(row.original.url) ? (
          <Button variant="ghost" size="icon-sm" asChild>
            <SafeExternalLink
              href={row.original.url}
              aria-label={t(
                'notificationChannels.history.openSource',
                'Open the source of {title}',
                {
                  title: row.original.title,
                }
              )}
            >
              <ExternalLink className="h-4 w-4" />
            </SafeExternalLink>
          </Button>
        ) : null,
    },
  ]
}

function HistoryList({
  integrationId,
  picker,
}: {
  integrationId: string
  /** The channel picker, at the start of the table's toolbar. */
  picker: ReactNode
}) {
  const { t } = useTranslation()
  const columns = useMemo(() => buildColumns(t), [t])
  // Server pagination over the channel's events (page / per_page).
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: DEFAULT_TABLE_PAGE_SIZE })
  useEffect(() => {
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }, [integrationId])

  const { data, error, isLoading, mutate } = useNotificationEventsApi(integrationId, {
    limit: pagination.pageSize,
    offset: pagination.pageIndex * pagination.pageSize,
  })
  const entries = useMemo(() => data?.data ?? [], [data?.data])
  const total = data?.total ?? 0

  const handleRefresh = useCallback(async () => {
    await invalidateNotificationEventsCache(integrationId)
    await mutate()
    toast.success(t('notificationChannels.history.refreshed', 'Notifications refreshed'))
  }, [integrationId, mutate, t])

  if (error && !data) {
    return (
      <ErrorState
        title={t('notificationChannels.history.errorTitle', 'notification events')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  return (
    <>
      <DataTable
        columns={columns}
        data={entries}
        getRowId={(e) => e.id}
        isLoading={isLoading}
        showSearch={false}
        toolbarStart={picker}
        toolbarEnd={<RefreshButton onClick={() => void handleRefresh()} loading={isLoading} />}
        manualPagination
        rowCount={total}
        pagination={pagination}
        onPaginationChange={setPagination}
        pageSize={pagination.pageSize}
        emptyMessage={t('notificationChannels.history.emptyMessage', 'No notifications sent yet')}
        emptyDescription={t(
          'notificationChannels.history.emptyDescription',
          'Send a test notification to see it here'
        )}
      />
    </>
  )
}

function HistoryContent() {
  const { t } = useTranslation()
  const router = useRouter()
  // Read on every render, not once: after an in-app navigation (a channel's
  // "View events") the first render still sees the previous page's URL.
  // Only a channel id is used from the link; anything else is ignored.
  const urlId = integrationIdFromParam(useUrlParam('integration'))
  const [pickedId, setPickedId] = useState('')

  const { data: integrationsData, isLoading: loadingIntegrations } =
    useNotificationIntegrationsApi()
  const integrations = useMemo(() => integrationsData?.data ?? [], [integrationsData?.data])

  // The channel picked here, else the one in the link, else the first.
  const selectedId = pickedId || urlId || integrations[0]?.id || ''

  const picker = (
    <Select value={selectedId} onValueChange={setPickedId}>
      <SelectTrigger
        className="w-[16rem] max-w-full"
        aria-label={t('notificationChannels.history.channel', 'Channel')}
      >
        <SelectValue
          placeholder={t('notificationChannels.history.selectChannel', 'Select channel…')}
        />
      </SelectTrigger>
      <SelectContent>
        {integrations.map((i) => (
          <SelectItem key={i.id} value={i.id}>
            {/* A long channel name ends in an ellipsis in the trigger;
                the full name is in the list and the title. */}
            <div className="flex min-w-0 items-center gap-2">
              <span data-slot="select-text" title={i.name}>
                {i.name}
              </span>
              <Badge variant="outline" className="shrink-0">
                {NOTIFICATION_PROVIDER_LABELS[i.provider] ?? i.provider}
              </Badge>
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )

  // The section's header stays as on Channels; the tabs show this sub-page,
  // and the breadcrumb and the Channels tab lead back (no back-link row).
  return (
    <PageStack>
      <NotificationSectionHeader />
      {loadingIntegrations ? (
        <Skeleton className="h-64 w-full" />
      ) : integrations.length === 0 ? (
        <EmptyState
          icon={Bell}
          title={t('notificationChannels.history.noChannels', 'No channels yet')}
          description={t(
            'notificationChannels.history.noChannelsDescription',
            'Add a channel; the events it sends are listed here.'
          )}
          action={
            <Can route="POST /api/v1/integrations/notifications">
              <Button onClick={() => router.push('/settings/integrations/notifications')}>
                {t('notificationChannels.history.addChannel', 'Add channel')}
              </Button>
            </Can>
          }
        />
      ) : (
        <HistoryList integrationId={selectedId} picker={picker} />
      )}
    </PageStack>
  )
}

export default function NotificationHistoryPage() {
  return (
    <Main>
      <HistoryContent />
    </Main>
  )
}
