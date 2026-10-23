'use client'

import Link from '@/components/link'
import { Info } from 'lucide-react'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared/types'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelativeTime } from '@/lib/format-metric'
import { safeInternalHref } from '@/lib/safe-href'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import type { UserNotification } from '../api/use-notification-api'
import { NOTIFICATION_TYPE_ICONS, NOTIFICATION_TYPE_LABELS } from '../lib/notification-types'

interface NotificationRowProps {
  notification: UserNotification
  /** Called (not awaited) the first time an unread row is activated. */
  onMarkAsRead: (id: string) => void
  /** Called when the row is activated, e.g. to close the bell popover. */
  onNavigate?: () => void
  /** The smaller layout used inside the bell popover. */
  compact?: boolean
}

/**
 * One notification, on the page and in the bell. With a same-origin target the
 * row is a link and the first click navigates (marking read happens in the
 * background). Without one, or with an external or unsafe one, it is a button
 * that only marks the row read: the target comes from integration payloads, so
 * it is never followed off-site.
 */
export function NotificationRow({
  notification,
  onMarkAsRead,
  onNavigate,
  compact = false,
}: NotificationRowProps) {
  const { t, locale } = useTranslation()
  const Icon = NOTIFICATION_TYPE_ICONS[notification.notification_type] || Info
  const typeLabel = t(
    `notificationTypes.${notification.notification_type}.name`,
    NOTIFICATION_TYPE_LABELS[notification.notification_type] || notification.notification_type
  )
  const title = toDisplayText(notification.title)
  const body = notification.body ? toDisplayText(notification.body) : ''
  const unread = !notification.is_read
  const severity = (notification.severity || '').toLowerCase()
  const severityLabel = t(`severity.${severity}`, notification.severity)

  const ariaLabel = t(
    unread ? 'notifications.row.labelUnread' : 'notifications.row.label',
    unread ? 'Unread: {title}, {type}, {severity}' : '{title}, {type}, {severity}',
    { title, type: typeLabel, severity: severityLabel }
  )

  const activate = () => {
    if (unread) onMarkAsRead(notification.id)
    onNavigate?.()
  }

  const content = (
    <>
      <Icon
        className={cn(
          'mt-0.5 flex-shrink-0 text-muted-foreground',
          compact ? 'h-4 w-4' : 'h-5 w-5'
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex items-start justify-between gap-2">
          <p
            dir="auto"
            className={cn(
              'break-words text-sm leading-snug [unicode-bidi:isolate]',
              compact && 'line-clamp-2',
              unread && 'font-medium'
            )}
          >
            {title}
          </p>
          <SeverityBadge severity={severity as Severity} className="flex-shrink-0" />
        </div>
        {body && (
          <p
            dir="auto"
            className="line-clamp-2 break-words text-xs text-muted-foreground [unicode-bidi:isolate]"
          >
            {body}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          {typeLabel} · {formatRelativeTime(notification.created_at, locale)}
        </p>
      </div>
      {unread && (
        <span className="mt-1.5 flex-shrink-0">
          <span className="block h-2 w-2 rounded-full bg-primary" aria-hidden />
          <span className="sr-only">{t('notifications.unread', 'Unread')}</span>
        </span>
      )}
    </>
  )

  const rowClassName = cn(
    'flex items-start gap-3 transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none',
    compact ? 'p-3' : 'p-4',
    unread && 'bg-primary/5'
  )

  const href = safeInternalHref(notification.url)
  if (href) {
    return (
      <Link href={href} className={rowClassName} onClick={activate} aria-label={ariaLabel}>
        {content}
      </Link>
    )
  }

  return (
    <div
      className={cn(rowClassName, 'cursor-pointer')}
      role="button"
      tabIndex={0}
      aria-label={ariaLabel}
      onClick={activate}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          activate()
        }
      }}
    >
      {content}
    </div>
  )
}
