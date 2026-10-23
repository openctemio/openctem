import { useCallback, useState } from 'react'
import Link from '@/components/link'
import { AlertCircle, Bell, CheckCheck, Loader2, RotateCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import {
  useNotificationsApi,
  useUnreadCountApi,
} from '@/features/notifications/api/use-notification-api'
import { useMarkNotifications } from '@/features/notifications/api/use-mark-notifications'
import { NotificationRow } from '@/features/notifications/components/notification-row'
import { useUserNotificationChannel } from '@/hooks/use-websocket'
import { useTenant } from '@/context/tenant-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { useTranslation } from '@/context/i18n-provider'

/** The bell shows the latest few; the page has the full list. */
const BELL_PER_PAGE = 10

export function NotificationBell() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const { currentTenant } = useTenant()
  // The profile API is the reliable source of the user id: the auth store is
  // only filled by a client-side login or token refresh, not on a fresh tab.
  const user = useDisplayUser()

  // Fetch notifications and unread count from API
  const {
    data: notificationsData,
    isLoading,
    error,
    mutate: mutateNotifications,
  } = useNotificationsApi(1, BELL_PER_PAGE, undefined, { enabled: open })
  const { data: unreadData, mutate: mutateUnreadCount } = useUnreadCountApi()

  const notifications = notificationsData?.data ?? []
  const unreadCount = unreadData?.count ?? 0

  // Real-time updates arrive on the user's own channel (user:{tenant}:{user}).
  // The server pushes every notification there that this user's inbox would
  // show (addressed to them, their groups, or everyone, minus what their
  // preferences filter out) and nothing addressed to anyone else.
  useUserNotificationChannel(currentTenant?.id, user?.id, {
    onData: useCallback(
      (data: Record<string, unknown>) => {
        // Only revalidate when the WebSocket event is a notification
        if (data?.type === 'notification') {
          mutateUnreadCount()
          // The list is only fetched while the popover is open.
          if (open) mutateNotifications()
        }
      },
      [open, mutateNotifications, mutateUnreadCount]
    ),
  })

  const { markRead, markAllRead } = useMarkNotifications()

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="relative"
          aria-label={
            unreadCount > 0
              ? t('notifications.bell.label', 'Notifications, {n} unread', { n: unreadCount })
              : t('notifications.bell.labelNone', 'Notifications')
          }
        >
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge
              variant="destructive"
              className="absolute -top-1 -right-1 h-5 min-w-5 rounded-full px-1 text-xs flex items-center justify-center"
              aria-hidden
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>

      <PopoverContent
        // Mobile: take nearly the full viewport width (minus 1rem on
        // each side) so collision detection produces symmetric margins
        // regardless of where the bell sits in the header. The previous
        // fixed `w-[340px]` was anchored to the bell trigger via
        // `align="end"`, but the bell isn't the last button in the
        // header (theme toggle + avatar come after it), so the popover
        // landed visually off-center.
        //
        // Tablet+: revert to the fixed 380px right-anchored to the
        // bell, which is the desktop pattern users expect.
        //
        // overflow-x-hidden + the break-words on inner text prevent
        // long titles/bodies from rendering past the popover edge on
        // narrow viewports.
        className="w-[calc(100vw-1rem)] max-w-[380px] p-0 sm:w-[380px] overflow-x-hidden"
        align="end"
        sideOffset={8}
        collisionPadding={8}
      >
        <div className="flex items-center justify-between px-3 py-3 sm:px-4">
          <h4 className="text-sm font-semibold sm:text-base">
            {t('notifications.bell.labelNone', 'Notifications')}
          </h4>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-auto px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
              onClick={() => void markAllRead()}
            >
              <CheckCheck className="h-3 w-3 me-1 sm:me-1" />
              <span className="hidden sm:inline">
                {t('notifications.markAllRead', 'Mark all as read')}
              </span>
              <span className="sm:hidden">{t('notifications.bell.markAllShort', 'Mark read')}</span>
            </Button>
          )}
        </div>

        <Separator />

        <ScrollArea className="h-[320px] sm:h-[400px]">
          {isLoading ? (
            <div
              role="status"
              className="flex flex-col items-center justify-center py-10 text-muted-foreground sm:py-12"
            >
              <Loader2
                className="h-8 w-8 mb-2 animate-spin opacity-30 sm:h-10 sm:w-10 sm:mb-3"
                aria-hidden
              />
              <p className="text-xs font-medium sm:text-sm">
                {t('notifications.list.loading', 'Loading notifications')}
              </p>
            </div>
          ) : error && !notificationsData ? (
            <div
              role="alert"
              className="flex flex-col items-center justify-center gap-2 py-10 text-muted-foreground sm:py-12"
            >
              <AlertCircle className="h-5 w-5 text-destructive" aria-hidden />
              <p className="text-xs font-medium sm:text-sm">
                {t('notifications.list.loadFailed', "Couldn't load notifications")}
              </p>
              <Button variant="outline" size="sm" onClick={() => void mutateNotifications()}>
                <RotateCw className="me-1.5 h-3 w-3" aria-hidden />
                {t('notifications.list.retry', 'Retry')}
              </Button>
            </div>
          ) : notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground sm:py-12">
              <Bell className="h-8 w-8 mb-2 opacity-30 sm:h-10 sm:w-10 sm:mb-3" aria-hidden />
              <p className="text-xs font-medium sm:text-sm">
                {t('notifications.bell.empty', 'No notifications')}
              </p>
              <p className="text-xs">{t('notifications.bell.caughtUp', 'You are all caught up')}</p>
            </div>
          ) : (
            <div className="divide-y">
              {notifications.map((notification) => (
                <NotificationRow
                  key={notification.id}
                  notification={notification}
                  onMarkAsRead={markRead}
                  onNavigate={() => setOpen(false)}
                  compact
                />
              ))}
            </div>
          )}
        </ScrollArea>

        <Separator />

        <div className="p-1.5 sm:p-2">
          <Button
            variant="ghost"
            className="w-full justify-center text-xs text-muted-foreground hover:text-foreground sm:text-sm"
            size="sm"
            asChild
          >
            <Link href="/notifications" onClick={() => setOpen(false)}>
              {t('notifications.bell.viewAll', 'View all notifications')}
            </Link>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  )
}
