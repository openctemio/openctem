'use client'

import { IntegrationHealth } from '@/features/integrations/components/integration-health'
import { ConnectionNote } from '@/features/integrations/components/connection-note'
import { useState, useMemo, useCallback } from 'react'
import { csrfFetch, del } from '@/lib/api/client'
import { useRouter } from 'next/navigation'
import { Main } from '@/components/layout'
import { RefreshButton } from '@/components/list-page-parts'
import { toDisplayText } from '@/lib/untrusted-text'
import { PersonPhoneCard } from '@/features/organization/components/person-phone-card'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  RelativeTime,
  StackedCell,
  type RowAction,
  PageStack,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { ColumnDef } from '@tanstack/react-table'
import { confirmName } from '@/lib/confirm-name'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { toast } from 'sonner'
import { Can } from '@/lib/permissions'
import { Plus, Bell, Send, Pencil, Trash2, MessageSquare, History } from 'lucide-react'
import {
  useNotificationIntegrationsApi,
  invalidateNotificationIntegrationsCache,
} from '@/features/integrations'
import type { Integration } from '@/features/integrations'
import { getErrorMessage } from '@/lib/api/error-handler'
import { ALL_NOTIFICATION_SEVERITIES } from '@/features/integrations/types/integration.types'
import { coversAllSeverities } from '@/features/notifications/lib/notification-filters'
import { notificationChannelsOnly } from '@/features/integrations/lib/integration-routing'
import {
  useTenantEventTypes,
  labelEventTypes,
  type NotificationEventTypeInfo,
  type NotificationEventCategoryInfo,
} from '@/features/integrations/api/use-event-types'
import { cn } from '@/lib/utils'
import { SEVERITY_BADGE_SOFT, type SeverityLevel } from '@/lib/severity-colors'
import { AddNotificationDialog } from '@/features/notifications/components/add-notification-dialog'
import { EditNotificationDialog } from '@/features/notifications/components/edit-notification-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  IntegrationList,
  integrationStatusGroup,
} from '@/features/integrations/components/integration-list'
import {
  NOTIFICATION_PROVIDER_LABELS,
  NotificationSectionHeader,
} from '@/features/integrations/components/notification-sections'

const PROVIDER_LABELS = NOTIFICATION_PROVIDER_LABELS

function ProviderIcon({ provider, className }: { provider: string; className?: string }) {
  switch (provider) {
    case 'slack':
      return <MessageSquare className={cn('text-[#4A154B]', className)} />
    case 'teams':
      return <MessageSquare className={cn('text-[#6264A7]', className)} />
    case 'telegram':
      return <Send className={cn('text-[#0088cc]', className)} />
    case 'webhook':
    case 'email':
      return <Bell className={cn('text-muted-foreground', className)} />
    default:
      return <Bell className={className} />
  }
}

/**
 * Group a channel's enabled event type identifiers into labelled category
 * buckets, using the catalog the API returned.
 *
 * Identifiers with no catalog entry are kept under an "Other" bucket rather
 * than dropped. The previous implementation did a `.find()` against a
 * hardcoded array and skipped anything it did not recognise, so a channel
 * routing `sla_breach` displayed as though it routed nothing — the display
 * silently disagreed with what the backend would deliver.
 */
function summarizeEventTypes(
  enabled: string[],
  catalog: NotificationEventTypeInfo[],
  categories: NotificationEventCategoryInfo[],
  otherLabel: string
): { category: string; label: string; labels: string[] }[] {
  const labelled = labelEventTypes(enabled, catalog)
  const byCategory = new Map<string, string[]>()
  for (const { label, category } of labelled) {
    const bucket = byCategory.get(category)
    if (bucket) {
      bucket.push(label)
    } else {
      byCategory.set(category, [label])
    }
  }

  const categoryLabels = new Map(categories.map((c) => [c.category, c.label]))
  return Array.from(byCategory.entries()).map(([category, labels]) => ({
    category,
    label: categoryLabels.get(category) ?? (category === 'unknown' ? otherLabel : category),
    labels,
  }))
}

/** Table frame widths (px) under which a column folds away; the channel, its status and the actions stay. */
const CHANNEL_HIDE_BELOW = { provider: 760, lastUsed: 900, severities: 1100, events: 1240 } as const

export default function NotificationIntegrationsPage() {
  const { t } = useTranslation()
  const router = useRouter()
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [editDialogOpen, setEditDialogOpen] = useState(false)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)

  const { data: integrationsData, error, isLoading, mutate } = useNotificationIntegrationsApi()

  // The event-type catalog is served by the API from the same registry the
  // notification outbox routes on. Nothing about it is hardcoded here — see
  // use-event-types.ts for why.
  const {
    eventTypes: eventTypeCatalog,
    categories: eventCategories,
    defaultEnabled: defaultEventTypes,
    totalCount: eventTypeCount,
  } = useTenantEventTypes()

  // Handle the API response format
  const integrations = useMemo(() => {
    if (!integrationsData) return []
    // SIEM destinations (Splunk) are managed on the SIEM page; this page's
    // edit dialog would overwrite their HEC token with a webhook URL.
    return notificationChannelsOnly(integrationsData.data ?? [])
  }, [integrationsData])

  const handleRefresh = useCallback(async () => {
    setActionInProgress('refresh')
    try {
      await invalidateNotificationIntegrationsCache()
      await mutate()
      toast.success(t('notificationChannels.toast.refreshed', 'Integrations refreshed'))
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('notificationChannels.toast.refreshFailed', 'Failed to refresh integrations')
        )
      )
    } finally {
      setActionInProgress(null)
    }
  }, [mutate, t])

  const handleTestNotification = useCallback(
    async (integration: Integration) => {
      setActionInProgress(integration.id)
      try {
        const response = await csrfFetch(
          `/api/v1/integrations/${integration.id}/test-notification`,
          {
            method: 'POST',
          }
        )

        // Handle rate limit (429)
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After')
          const seconds = retryAfter ? parseInt(retryAfter, 10) : 60
          toast.error(
            t(
              'notificationChannels.toast.rateLimited',
              'Rate limit exceeded. Please wait {seconds} seconds before trying again.',
              { seconds }
            )
          )
          return
        }

        if (!response.ok) throw new Error('Test failed')
        const result = await response.json()
        if (result.success) {
          toast.success(
            t('notificationChannels.toast.testSent', 'Test notification sent to "{name}"', {
              name: integration.name,
            })
          )
        } else {
          toast.error(
            result.error || t('notificationChannels.toast.testFailed', 'Test notification failed')
          )
        }
      } catch (err) {
        toast.error(
          getErrorMessage(
            err,
            t('notificationChannels.toast.testError', 'Failed to send test notification')
          )
        )
      } finally {
        setActionInProgress(null)
      }
    },
    [t]
  )

  const handleDelete = useCallback(async () => {
    if (!selectedIntegration) return
    setActionInProgress(selectedIntegration.id)
    try {
      // apiClient path: a STEP_UP_REQUIRED answer opens the re-authentication dialog and retries.
      await del(`/api/v1/integrations/${selectedIntegration.id}`)
      toast.success(
        t('notificationChannels.toast.deleted', 'Integration "{name}" deleted', {
          name: selectedIntegration.name,
        })
      )
      await invalidateNotificationIntegrationsCache()
      await mutate()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('notificationChannels.toast.deleteFailed', 'Failed to delete integration')
        )
      )
    } finally {
      setDeleteDialogOpen(false)
      setSelectedIntegration(null)
      setActionInProgress(null)
    }
  }, [selectedIntegration, mutate, t])

  const handleDeleteClick = useCallback((integration: Integration) => {
    setSelectedIntegration(integration)
    setDeleteDialogOpen(true)
  }, [])

  const handleEditClick = useCallback((integration: Integration) => {
    setSelectedIntegration(integration)
    setEditDialogOpen(true)
  }, [])

  // One row menu for the table row and the phone card.
  const rowActions = useCallback(
    (integration: Integration) => {
      const actions: RowAction[] = [
        {
          label: t('notificationChannels.actions.sendTest', 'Send test'),
          icon: Send,
          onClick: () => void handleTestNotification(integration),
          route: 'POST /api/v1/integrations/{id}/test-notification',
        },
        {
          label: t('notificationChannels.actions.edit', 'Edit'),
          icon: Pencil,
          onClick: () => handleEditClick(integration),
          route: 'PUT /api/v1/integrations/{id}/notification',
        },
        {
          label: t('notificationChannels.actions.viewEvents', 'View events'),
          icon: History,
          onClick: () =>
            router.push(
              `/settings/integrations/notifications/history?integration=${integration.id}`
            ),
          route: 'PUT /api/v1/integrations/{id}',
        },
        {
          label: t('notificationChannels.actions.delete', 'Delete'),
          icon: Trash2,
          onClick: () => handleDeleteClick(integration),
          destructive: true,
          separatorBefore: true,
          route: 'DELETE /api/v1/integrations/{id}',
        },
      ]
      return (
        <DataTableRowActions
          title={integration.name}
          label={t('common.rowActions.actionsFor', 'Actions for {name}', {
            name: integration.name,
          })}
          actions={actions}
        />
      )
    },
    [t, router, handleTestNotification, handleEditClick, handleDeleteClick]
  )

  const columns = useMemo<ColumnDef<Integration>[]>(
    () => [
      {
        accessorKey: 'name',
        meta: { kind: 'name', minWidth: 200 },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('notificationChannels.col.channel', 'Channel')}
          />
        ),
        cell: ({ row }) => {
          const integration = row.original
          // Channel name / chat id live in integration.metadata now — the
          // notification_extension.channel_name getter is hardcoded to "" on
          // the API, so the old read here always rendered nothing.
          const meta = integration.metadata as Record<string, unknown> | undefined
          const channelName = (meta?.channel_name as string) || (meta?.chat_id as string) || ''
          return (
            <div className="flex items-center gap-3">
              <ProviderIcon provider={integration.provider} className="h-5 w-5 shrink-0" />
              <StackedCell
                primary={integration.name}
                secondary={channelName ? `#${channelName}` : undefined}
              />
            </div>
          )
        },
      },
      {
        accessorKey: 'provider',
        meta: { hideBelow: CHANNEL_HIDE_BELOW.provider },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('notificationChannels.col.provider', 'Provider')}
          />
        ),
        cell: ({ row }) => (
          <Badge variant="outline" className="text-xs">
            {PROVIDER_LABELS[row.original.provider] || row.original.provider}
          </Badge>
        ),
      },
      {
        accessorKey: 'status',
        // The row's state: a phone card shows it on its title line. The cell
        // also says why a connection failed, so it keeps room for that reason.
        meta: { kind: 'status', width: 280 },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('notificationChannels.col.status', 'Status')}
          />
        ),
        cell: ({ row }) => {
          const integration = row.original
          return (
            <div className="space-y-1">
              <IntegrationHealth status={integration.status} />
              <ConnectionNote integration={integration} className="max-w-[250px]" />
            </div>
          )
        },
      },
      {
        id: 'severity_filters',
        meta: { hideBelow: CHANNEL_HIDE_BELOW.severities },
        header: t('notificationChannels.col.severityFilters', 'Severity filters'),
        enableSorting: false,
        cell: ({ row }) => {
          const ext = row.original.notification_extension
          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex gap-1 flex-wrap cursor-default">
                    {(() => {
                      // "All" only when every real severity is enabled.
                      const severities = ext?.enabled_severities ?? []
                      const isAllSeverities = coversAllSeverities(severities)
                      if (isAllSeverities) {
                        return (
                          <span className="text-xs text-muted-foreground">
                            {t('notificationChannels.severity.all', 'All severities')}
                          </span>
                        )
                      }
                      // Show max 3 severity badges, then "+N more"
                      const maxShow = 3
                      const shown = severities.slice(0, maxShow)
                      const remaining = severities.length - maxShow
                      return (
                        <>
                          {shown.map((sev) => {
                            const colorClass =
                              SEVERITY_BADGE_SOFT[
                                (sev === 'none' ? 'info' : sev) as SeverityLevel
                              ] || ''
                            const config = ALL_NOTIFICATION_SEVERITIES.find((s) => s.value === sev)
                            return (
                              <Badge
                                key={sev}
                                variant="outline"
                                className={cn('text-xs', colorClass)}
                              >
                                {t(`notificationChannels.severity.${sev}`, config?.label || sev)}
                              </Badge>
                            )
                          })}
                          {remaining > 0 && (
                            <Badge variant="secondary" className="text-xs">
                              +{remaining}
                            </Badge>
                          )}
                        </>
                      )
                    })()}
                  </div>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[200px]">
                  <p className="text-xs font-medium mb-1">
                    {t('notificationChannels.severity.tooltipTitle', 'Severity filters:')}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {(() => {
                      const severities = ext?.enabled_severities ?? []
                      const isAllSeverities = coversAllSeverities(severities)
                      if (isAllSeverities) {
                        // Show actual list of all severities
                        return ALL_NOTIFICATION_SEVERITIES.map((s) =>
                          t(`notificationChannels.severity.${s.value}`, s.label)
                        ).join(', ')
                      }
                      return severities
                        .map((sev) => {
                          const config = ALL_NOTIFICATION_SEVERITIES.find((s) => s.value === sev)
                          return t(`notificationChannels.severity.${sev}`, config?.label || sev)
                        })
                        .join(', ')
                    })()}
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )
        },
      },
      {
        id: 'event_types',
        meta: { hideBelow: CHANNEL_HIDE_BELOW.events },
        header: t('notificationChannels.col.eventTypes', 'Event types'),
        enableSorting: false,
        cell: ({ row }) => {
          const ext = row.original.notification_extension
          const enabled = ext?.enabled_event_types ?? defaultEventTypes
          // "All events" only when the catalog has actually loaded — otherwise
          // eventTypeCount is 0 and every channel would claim to route
          // everything.
          const isAll =
            enabled.length === 0 || (eventTypeCount > 0 && enabled.length === eventTypeCount)
          const groups = summarizeEventTypes(
            enabled,
            eventTypeCatalog,
            eventCategories,
            t('notificationChannels.events.other', 'Other')
          )

          return (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className="flex gap-1 flex-wrap cursor-default">
                    {isAll ? (
                      <span className="text-xs text-muted-foreground">
                        {t('notificationChannels.events.all', 'All events')}
                      </span>
                    ) : groups.length > 0 && groups.length <= 2 ? (
                      groups.map((g) => (
                        <Badge
                          key={g.category}
                          variant="outline"
                          className="text-xs bg-primary/10 text-primary border-primary/20"
                        >
                          {g.label.replace(' Events', '')} ({g.labels.length})
                        </Badge>
                      ))
                    ) : (
                      <Badge
                        variant="outline"
                        className="text-xs bg-primary/10 text-primary border-primary/20"
                      >
                        {t('notificationChannels.events.count', '{count} event types', {
                          count: enabled.length,
                        })}
                      </Badge>
                    )}
                  </div>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-[280px]">
                  <p className="text-xs font-medium mb-1">
                    {t('notificationChannels.events.tooltipTitle', 'Event types:')}
                  </p>
                  {isAll ? (
                    <p className="text-xs text-muted-foreground">
                      {t('notificationChannels.events.allEnabled', 'All event types enabled')}
                    </p>
                  ) : (
                    groups.map((g) => (
                      <div key={g.category} className="mb-1 last:mb-0">
                        <span className="text-xs font-medium">{g.label}:</span>
                        <span className="text-xs text-muted-foreground ms-1">
                          {g.labels.join(', ')}
                        </span>
                      </div>
                    ))
                  )}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )
        },
      },
      {
        accessorKey: 'last_sync_at',
        meta: { hideBelow: CHANNEL_HIDE_BELOW.lastUsed },
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('notificationChannels.col.lastUsed', 'Last used')}
          />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.last_sync_at} />,
      },
      {
        id: 'actions',
        meta: { kind: 'actions' },
        header: '',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => rowActions(row.original),
      },
    ],
    [t, rowActions, eventTypeCatalog, eventCategories, defaultEventTypes, eventTypeCount]
  )

  return (
    <>
      <Main>
        <PageStack>
          {/* The create button stays in the header; the empty state only explains. */}
          <NotificationSectionHeader>
            <Can route="POST /api/v1/integrations/notifications">
              <Button onClick={() => setAddDialogOpen(true)}>
                <Plus aria-hidden />
                {t('notificationChannels.page.addChannel', 'Add channel')}
              </Button>
            </Can>
          </NotificationSectionHeader>

          <IntegrationList
            rows={integrations}
            isLoading={isLoading}
            error={error}
            onRetry={() => void mutate()}
            errorTitle={t('notificationChannels.page.errorTitle', 'notification channels')}
            groupOf={(i) => integrationStatusGroup(i.status)}
            empty={{
              icon: Bell,
              title: t('notificationChannels.page.emptyTitle', 'No notification channels'),
              description: t(
                'notificationChannels.page.emptyDescription',
                'Add Slack, Microsoft Teams, Telegram, or webhook integrations to receive security alerts.'
              ),
            }}
          >
            {(visible) => (
              <DataTable
                columns={columns}
                data={visible}
                getRowId={(i) => i.id}
                searchPlaceholder={t(
                  'notificationChannels.page.searchPlaceholder',
                  'Search channels…'
                )}
                showSelectionCount={false}
                pinActions
                mobileRow={(integration) => (
                  <PersonPhoneCard
                    title={toDisplayText(integration.name, 200)}
                    address={PROVIDER_LABELS[integration.provider] || integration.provider}
                    menu={rowActions(integration)}
                    facts={
                      <>
                        <IntegrationHealth status={integration.status} />
                        <ConnectionNote integration={integration} className="basis-full" />
                      </>
                    }
                  />
                )}
                toolbarEnd={
                  <RefreshButton
                    onClick={() => void handleRefresh()}
                    loading={actionInProgress === 'refresh'}
                    label={t('notificationChannels.page.refresh', 'Refresh')}
                  />
                }
                emptyMessage={t(
                  'notificationChannels.page.noMatch',
                  'No channels match your search'
                )}
              />
            )}
          </IntegrationList>
        </PageStack>
      </Main>

      {/* Dialogs */}
      <AddNotificationDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={async () => {
          await invalidateNotificationIntegrationsCache()
          await mutate()
        }}
      />

      {selectedIntegration && (
        <EditNotificationDialog
          open={editDialogOpen}
          onOpenChange={setEditDialogOpen}
          integration={selectedIntegration}
          onSuccess={async () => {
            await invalidateNotificationIntegrationsCache()
            await mutate()
          }}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        title={t(
          'confirm.notificationChannel.deleteTitle',
          'Delete the notification channel "{name}"?',
          {
            name: selectedIntegration?.name ?? '',
          }
        )}
        desc={t(
          'confirm.notificationChannel.deleteDesc',
          'Notifications stop going to this channel at once, and rules that send to it lose this destination. This cannot be undone.'
        )}
        confirmText={t('confirm.notificationChannel.deleteBtn')}
        destructive
        typeToConfirm={
          selectedIntegration
            ? confirmName(selectedIntegration.name, selectedIntegration.id)
            : undefined
        }
        handleConfirm={() => void handleDelete()}
      />
    </>
  )
}
