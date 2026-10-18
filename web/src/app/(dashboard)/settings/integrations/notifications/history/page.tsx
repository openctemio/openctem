'use client'

import { useState, useCallback, useEffect, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { useUrlParam } from '@/hooks/use-url-param'
import { formatDistanceToNow } from 'date-fns'
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
import { ArrowLeft, Bell, ExternalLink } from 'lucide-react'
import {
  DataTable,
  EmptyState,
  ErrorState,
  PageHeader,
  RunStatusBadge,
  SeverityBadge,
  MetricStrip,
} from '@/features/shared'
import type { Severity } from '@/features/shared/types'
import { RefreshButton } from '@/components/list-page-parts'
import { Can } from '@/lib/permissions'
import {
  useNotificationIntegrationsApi,
  useNotificationEventsApi,
  invalidateNotificationEventsCache,
} from '@/features/integrations/api/use-integrations-api'
import type { NotificationEventEntry } from '@/features/integrations/types/integration.types'
import { safeHref } from '@/lib/safe-href'
import { useTranslation } from '@/context/i18n-provider'
import { SafeExternalLink } from '@/components/safe-external-link'

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
          title={new Date(row.original.processed_at).toLocaleString()}
        >
          {formatDistanceToNow(new Date(row.original.processed_at), { addSuffix: true })}
        </span>
      ),
    },
    {
      id: 'actions',
      enableHiding: false,
      cell: ({ row }) =>
        safeHref(row.original.url) ? (
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0" asChild>
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

function HistoryList({ integrationId }: { integrationId: string }) {
  const { t } = useTranslation()
  const columns = useMemo(() => buildColumns(t), [t])
  // Server pagination over the channel's events (page / per_page).
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 10 })
  useEffect(() => {
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }, [integrationId])

  const { data, error, isLoading, mutate } = useNotificationEventsApi(integrationId, {
    limit: pagination.pageSize,
    offset: pagination.pageIndex * pagination.pageSize,
  })
  const entries = useMemo(() => data?.data ?? [], [data?.data])
  const total = data?.total ?? 0

  // Delivery outcome of the events on this page (the API has no per-channel totals).
  const pageStats = useMemo(() => {
    const success = entries.filter((e) => e.send_results?.[0]?.status === 'success').length
    const failed = entries.filter((e) => e.send_results?.[0]?.status === 'failed').length
    return {
      success,
      failed,
      rate: entries.length ? Math.round((success / entries.length) * 100) : 0,
    }
  }, [entries])

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
    <div className="space-y-5">
      {/* Success rate and failures cover the events on this page; the API has
          no per-channel delivery totals. */}
      <MetricStrip
        loading={isLoading && !data}
        items={[
          {
            key: 'total',
            label: t('notificationChannels.history.metric.sent', 'Sent'),
            value: total,
          },
          {
            key: 'rate',
            label: t('notificationChannels.history.metric.successRate', 'Success rate'),
            value: `${pageStats.rate}%`,
            hint: t('notificationChannels.history.metric.pageHint', 'Events on this page'),
          },
          {
            key: 'failed',
            label: t('notificationChannels.history.metric.failed', 'Failed'),
            value: pageStats.failed,
            tone: 'danger',
            hint: t('notificationChannels.history.metric.pageHint', 'Events on this page'),
          },
        ]}
      />

      <DataTable
        columns={columns}
        data={entries}
        getRowId={(e) => e.id}
        isLoading={isLoading}
        showSearch={false}
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
    </div>
  )
}

function HistoryContent() {
  const { t } = useTranslation()
  const router = useRouter()
  // Read on every render, not once: after an in-app navigation (a channel's
  // "View events") the first render still sees the previous page's URL.
  const urlId = useUrlParam('integration') || ''
  const [pickedId, setPickedId] = useState('')

  const { data: integrationsData, isLoading: loadingIntegrations } =
    useNotificationIntegrationsApi()
  const integrations = useMemo(() => integrationsData?.data ?? [], [integrationsData?.data])

  // The channel picked here, else the one in the link, else the first.
  const selectedId = pickedId || urlId || integrations[0]?.id || ''

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="-ms-2 mb-2"
        onClick={() => router.push('/settings/integrations/notifications')}
      >
        <ArrowLeft className="me-2 h-4 w-4" />
        {t('notificationChannels.history.back', 'Back to channels')}
      </Button>
      <PageHeader
        title={t('notificationChannels.history.title', 'Notification events')}
        description={t(
          'notificationChannels.history.description',
          'What each notification channel sent, and whether delivery succeeded.'
        )}
        className="mb-6"
      >
        {loadingIntegrations ? (
          <Skeleton className="h-9 w-[220px]" />
        ) : integrations.length === 0 ? (
          <Can route="POST /api/v1/integrations/notifications">
            <Button
              variant="outline"
              size="sm"
              onClick={() => router.push('/settings/integrations/notifications')}
            >
              {t('notificationChannels.history.addChannel', 'Add channel')}
            </Button>
          </Can>
        ) : (
          <Select value={selectedId} onValueChange={setPickedId}>
            <SelectTrigger
              className="w-[220px] max-w-full"
              aria-label={t('notificationChannels.history.channel', 'Channel')}
            >
              <SelectValue
                placeholder={t('notificationChannels.history.selectChannel', 'Select channel…')}
              />
            </SelectTrigger>
            <SelectContent>
              {integrations.map((i) => (
                <SelectItem key={i.id} value={i.id}>
                  <div className="flex items-center gap-2">
                    <span>{i.name}</span>
                    <Badge variant="outline" className="text-xs">
                      {i.provider}
                    </Badge>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </PageHeader>

      {selectedId ? (
        <HistoryList integrationId={selectedId} />
      ) : (
        <EmptyState
          icon={Bell}
          title={t(
            'notificationChannels.history.selectPrompt',
            'Select a channel to view its notification events'
          )}
        />
      )}
    </>
  )
}

export default function NotificationHistoryPage() {
  return (
    <Main>
      <HistoryContent />
    </Main>
  )
}
