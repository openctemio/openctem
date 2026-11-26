'use client'

import type { ReactNode } from 'react'
import { Bell, History, Inbox } from 'lucide-react'
import { PageHeader, SectionTabs } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'

export const NOTIFICATION_CHANNELS_PATH = '/settings/integrations/notifications'

/**
 * Settings > Integrations > Notification channels: the channels, the events
 * they sent and the delivery queue. One section: the title and description
 * stay the same on all three pages, and the tab row under them shows the
 * sub-page, so nothing above the tabs moves when the reader switches tabs
 * and no page needs its own "Back to channels" link (the breadcrumb and the
 * Channels tab do that).
 *
 * Events and Queue show every event of the organization and need
 * integrations:manage (route-permissions.ts and the API): a reader without it
 * gets no tab row at all, rather than tabs that lead to a refusal or a row
 * holding the one Channels tab.
 */
export function NotificationSectionHeader({ children }: { children?: ReactNode }) {
  const { t } = useTranslation()
  const canManage = useHasPermission(Permission.IntegrationsManage)
  return (
    <>
      {/* anatomy-ok: inside a PageStack (each notification page renders this first in its own) */}
      <PageHeader
        title={t('notificationChannels.page.title', 'Notification channels')}
        description={t(
          'notificationChannels.page.description',
          'Send security alerts to Slack, Microsoft Teams, Telegram and custom webhooks.'
        )}
      >
        {children}
      </PageHeader>
      {canManage && (
        <SectionTabs
          label={t('notificationChannels.tabs.label', 'Notification channel sections')}
          tabs={[
            {
              label: t('notificationChannels.tabs.channels', 'Channels'),
              href: NOTIFICATION_CHANNELS_PATH,
              icon: Bell,
            },
            {
              label: t('notificationChannels.tabs.events', 'Events'),
              href: `${NOTIFICATION_CHANNELS_PATH}/history`,
              icon: History,
            },
            {
              label: t('notificationChannels.tabs.queue', 'Queue'),
              href: `${NOTIFICATION_CHANNELS_PATH}/outbox`,
              icon: Inbox,
            },
          ]}
        />
      )}
    </>
  )
}

/** A notification channel's provider by its product name (never the raw "slack"). */
export const NOTIFICATION_PROVIDER_LABELS: Readonly<Record<string, string>> = {
  slack: 'Slack',
  teams: 'Microsoft Teams',
  telegram: 'Telegram',
  webhook: 'Webhook',
  email: 'Email',
}
