'use client'

import { useCallback, useRef } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import {
  invalidateNotificationsCache,
  markAllNotificationsAsRead,
  markNotificationAsRead,
} from './use-notification-api'

/**
 * Mark-as-read actions shared by the notifications page and the top-bar bell.
 * A failed call tells the user (the row stays unread, so a silent failure
 * would look like a click that did nothing) instead of being swallowed.
 */
export function useMarkNotifications() {
  const { t } = useTranslation()
  const inFlight = useRef<Set<string>>(new Set())

  /** Fire and forget: callers never wait on it, so navigation is not delayed. */
  const markRead = useCallback(
    (id: string): void => {
      if (inFlight.current.has(id)) return
      inFlight.current.add(id)
      void (async () => {
        try {
          await markNotificationAsRead(id)
          await invalidateNotificationsCache()
        } catch {
          toast.error(t('notifications.markFailed', "Couldn't mark the notification as read."))
        } finally {
          inFlight.current.delete(id)
        }
      })()
    },
    [t]
  )

  const markAllRead = useCallback(async (): Promise<void> => {
    try {
      await markAllNotificationsAsRead()
      await invalidateNotificationsCache()
    } catch {
      toast.error(t('notifications.markAllFailed', "Couldn't mark the notifications as read."))
    }
  }, [t])

  return { markRead, markAllRead }
}
