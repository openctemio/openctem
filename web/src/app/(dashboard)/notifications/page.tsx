import { useCallback, useMemo } from 'react'
import { useListParams } from '@/hooks/use-list-params'
import Link from '@/components/link'
import {
  AlertTriangle,
  Bell,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Settings,
} from 'lucide-react'
import { Main } from '@/components/layout'
import { useWebSocket } from '@/context/websocket-provider'
import { useTenant } from '@/context/tenant-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { useUserNotificationChannel } from '@/hooks/use-websocket'
import { PageHeader } from '@/features/shared'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  useNotificationsApi,
  useUnreadCountApi,
  type NotificationListFilters,
} from '@/features/notifications/api/use-notification-api'
import { useMarkNotifications } from '@/features/notifications/api/use-mark-notifications'
import { NotificationRow } from '@/features/notifications/components/notification-row'
import { SEVERITY_LABELS, SEVERITY_LEVELS } from '@/lib/severity'
import { useTranslation } from '@/context/i18n-provider'

const PER_PAGE = 20

export default function NotificationsPage() {
  const { t } = useTranslation()
  // The list lives in the URL (one list convention): page, severity, read.
  const list = useListParams({
    defaultPageSize: PER_PAGE,
    filters: { severity: 'all', read: 'all' },
  })
  const { page, setPage } = list
  const severityFilter = list.filters.severity
  const readFilter = list.filters.read

  // Build server-side filters
  const filters = useMemo<NotificationListFilters>(() => {
    const f: NotificationListFilters = {}
    if (severityFilter !== 'all') f.severity = severityFilter
    if (readFilter === 'unread') f.is_read = false
    if (readFilter === 'read') f.is_read = true
    return f
  }, [severityFilter, readFilter])

  // The full list is on screen here, so keep it fresh while the page is open:
  // refetch on each notification pushed over the WebSocket, and poll only while
  // the socket is down.
  const { isConnected } = useWebSocket()
  const { currentTenant } = useTenant()
  const user = useDisplayUser()
  const { data, isLoading, error, mutate } = useNotificationsApi(page, PER_PAGE, filters, {
    refreshInterval: isConnected ? 0 : 60000,
  })
  useUserNotificationChannel(currentTenant?.id, user?.id, {
    onData: useCallback(
      (event: Record<string, unknown>) => {
        if (event?.type === 'notification') void mutate()
      },
      [mutate]
    ),
  })
  const { data: unreadData } = useUnreadCountApi()

  const notifications = data?.data ?? []
  const totalPages = data?.total_pages ?? 0
  const total = data?.total ?? 0
  const unreadCount = unreadData?.count ?? 0

  const { markRead, markAllRead } = useMarkNotifications()

  // Reset page when filters change
  const handleSeverityChange = (value: string) => list.setFilter('severity', value)

  const handleReadFilterChange = (value: string) => list.setFilter('read', value)

  const filtered = severityFilter !== 'all' || readFilter !== 'all'

  return (
    <Main>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader title={t('settings.notifications.title', 'Notifications')} />
        <div className="flex items-center gap-2">
          {unreadCount > 0 && (
            <>
              <span className="text-sm text-muted-foreground">
                {t('notifications.unreadCount', '{n} unread', { n: unreadCount })}
              </span>
              <Button variant="outline" size="sm" onClick={() => void markAllRead()}>
                <CheckCheck className="h-4 w-4 me-1.5" />
                {t('notifications.markAllRead', 'Mark all as read')}
              </Button>
            </>
          )}
          <Button variant="outline" size="sm" asChild>
            <Link href="/account/notifications">
              <Settings className="h-4 w-4 me-1.5" />
              {t('notifications.settings', 'Settings')}
            </Link>
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Select value={severityFilter} onValueChange={handleSeverityChange}>
          <SelectTrigger
            className="h-8 w-auto min-w-[8rem] text-xs"
            aria-label={t('notifications.filters.severity', 'Filter by severity')}
          >
            <SelectValue placeholder={t('notifications.filters.severityPlaceholder', 'Severity')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">
              {t('notifications.filters.severityAll', 'All severities')}
            </SelectItem>
            {SEVERITY_LEVELS.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`severity.${s}`, SEVERITY_LABELS[s])}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={readFilter} onValueChange={handleReadFilterChange}>
          <SelectTrigger
            className="h-8 w-auto min-w-[8rem] text-xs"
            aria-label={t('notifications.filters.status', 'Filter by read status')}
          >
            <SelectValue placeholder={t('notifications.filters.statusPlaceholder', 'Status')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('notifications.filters.statusAll', 'All')}</SelectItem>
            <SelectItem value="unread">
              {t('notifications.filters.statusUnread', 'Unread')}
            </SelectItem>
            <SelectItem value="read">{t('notifications.filters.statusRead', 'Read')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Notification List */}
      <div className="mt-4">
        {isLoading ? (
          <div
            role="status"
            className="flex flex-col items-center justify-center py-16 text-muted-foreground"
          >
            <Loader2 className="h-8 w-8 mb-3 animate-spin opacity-30" aria-hidden />
            <p className="text-sm">{t('notifications.list.loading', 'Loading notifications')}</p>
          </div>
        ) : error && !data ? (
          <div
            role="alert"
            className="flex flex-col items-center justify-center gap-3 py-16 text-muted-foreground"
          >
            <AlertTriangle className="h-8 w-8 opacity-30" aria-hidden />
            <p className="text-sm font-medium">
              {t('notifications.list.loadFailed', "Couldn't load notifications")}
            </p>
            <Button variant="outline" size="sm" onClick={() => void mutate()}>
              {t('notifications.list.retry', 'Retry')}
            </Button>
          </div>
        ) : notifications.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <Bell className="h-10 w-10 mb-3 opacity-30" aria-hidden />
            <p className="text-sm font-medium">
              {filtered
                ? t('notifications.list.emptyFilteredTitle', 'No matching notifications')
                : t('notifications.list.emptyTitle', 'No notifications yet')}
            </p>
            <p className="text-xs mt-1">
              {filtered
                ? t('notifications.list.emptyFilteredHint', 'Try adjusting your filters')
                : t(
                    'notifications.list.emptyHint',
                    'Notifications will appear here when events occur'
                  )}
            </p>
          </div>
        ) : (
          <div className="divide-y border-y">
            {notifications.map((notification) => (
              <NotificationRow
                key={notification.id}
                notification={notification}
                onMarkAsRead={markRead}
              />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {t('notifications.pagination.page', 'Page {page} of {pages} ({total} total)', {
              page,
              pages: totalPages,
              total,
            })}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page <= 1}
            >
              <ChevronLeft className="h-4 w-4 me-1" />
              {t('notifications.pagination.previous', 'Previous')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page >= totalPages}
            >
              {t('notifications.pagination.next', 'Next')}
              <ChevronRight className="h-4 w-4 ms-1" />
            </Button>
          </div>
        </div>
      )}
    </Main>
  )
}
