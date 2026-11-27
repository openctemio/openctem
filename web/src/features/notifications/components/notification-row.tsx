'use client'

import Link from '@/components/link'
import { Info } from 'lucide-react'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared/types'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelativeTime } from '@/lib/format-metric'
import { safeInternalHref } from '@/lib/safe-href'
import { hasServerText, messageOf, serverText } from '@/lib/server-text'
import { toDisplayBlock, toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import type { UserNotification } from '../api/use-notification-api'
import { legacyCoverageMessage } from '../lib/legacy-message'
import { NOTIFICATION_TYPE_ICONS, NOTIFICATION_TYPE_LABELS } from '../lib/notification-types'

/** The fixed titles the server writes (in English), by catalog key. */
const SERVER_TITLE_KEYS: Record<string, string> = {
  'API key expires soon': 'notifications.serverTitle.apiKeyExpiresSoon',
  'Scan paused: no active owner': 'notifications.serverTitle.scanPausedNoOwner',
  'An SSO change is waiting for your approval': 'notifications.serverTitle.ssoChangeWaiting',
  'Content install approval is being switched off': 'notifications.serverTitle.contentApprovalOff',
}

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
    NOTIFICATION_TYPE_LABELS[notification.notification_type] ||
      t('notificationTypes.other.name', 'Notification')
  )
  // A notice with a message code is worded from the serverText catalog in the
  // reader's language (src/lib/server-text.ts). Older notices, and a code
  // this build does not know, show the English text the server stored: a
  // fixed title in the reader's language, any other title and the body as
  // stored text.
  const storedBody = notification.body ? toDisplayBlock(notification.body, 4000) : ''
  const titleKey = Object.hasOwn(SERVER_TITLE_KEYS, notification.title)
    ? SERVER_TITLE_KEYS[notification.title]
    : undefined
  const storedTitle = titleKey ? t(titleKey, notification.title) : toDisplayText(notification.title)
  // Title and body come from the catalog together or not at all, so one
  // notice never mixes two languages.
  const raw =
    messageOf(notification.message_code, notification.message_params) ??
    legacyCoverageMessage(notification.notification_type, notification.title, notification.body)
  const coded =
    raw !== undefined &&
    hasServerText(t, locale, raw, 'title') &&
    (!storedBody || hasServerText(t, locale, raw, 'body'))
  const title = coded ? serverText(t, locale, raw, storedTitle, 'title') : storedTitle
  // The body keeps its line breaks (a list of changes reads as lines, never
  // as one paragraph strung with return marks).
  const body = coded && storedBody ? serverText(t, locale, raw, storedBody, 'body') : storedBody
  const titleTranslated = coded || Boolean(titleKey)
  const bodyTranslated = coded
  const unread = !notification.is_read
  const severity = (notification.severity || '').toLowerCase()

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
      <div className={cn('min-w-0 flex-1', compact ? 'space-y-0.5' : 'space-y-1')}>
        <div className="flex items-start justify-between gap-2">
          <p
            dir="auto"
            translate={titleTranslated ? undefined : 'no'}
            data-cut-tooltip={compact ? '' : undefined}
            title={compact ? title : undefined}
            className={cn(
              'break-words [unicode-bidi:isolate]',
              compact ? 'text-dense line-clamp-2 font-medium' : 'text-sm leading-snug',
              !compact && unread && 'font-medium'
            )}
          >
            {title}
          </p>
          <SeverityBadge severity={severity as Severity} className="flex-shrink-0" />
        </div>
        {/* The list shows the whole message; the bell's compact row keeps
            two lines, the rest in its title. */}
        {body && (
          <p
            dir="auto"
            translate={bodyTranslated ? undefined : 'no'}
            data-cut-tooltip={compact ? '' : undefined}
            title={compact ? body : undefined}
            className={cn(
              'break-words whitespace-pre-line text-muted-foreground [unicode-bidi:isolate]',
              compact ? 'text-cap line-clamp-2' : 'text-xs'
            )}
          >
            {body}
          </p>
        )}
        <p className={cn(compact ? 'text-cap text-fg-dim' : 'text-xs text-muted-foreground')}>
          {typeLabel}, {formatRelativeTime(notification.created_at, locale)}
        </p>
      </div>
      {/* One unread dot in a fixed end column, so read and unread rows keep
          the same text width and nothing wraps differently. */}
      <span className="mt-1.5 w-2 flex-none" data-slot="notification-unread">
        {unread && (
          <>
            <span className="bg-signal block size-2 rounded-full" aria-hidden />
            <span className="sr-only">{t('notifications.unread', 'Unread')}</span>
          </>
        )}
      </span>
    </>
  )

  const rowClassName = cn(
    'flex items-start gap-3 transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none',
    compact ? 'px-4 py-3' : 'p-4',
    !compact && unread && 'bg-primary/5'
  )

  const href = safeInternalHref(notification.url)
  if (href) {
    return (
      <Link href={href} className={rowClassName} onClick={activate}>
        {content}
      </Link>
    )
  }

  return (
    <div
      className={cn(rowClassName, 'cursor-pointer')}
      role="button"
      tabIndex={0}
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
