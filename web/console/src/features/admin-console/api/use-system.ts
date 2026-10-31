'use client'

import { useCallback } from 'react'
import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type { AdminAnnouncement, ThreatIntelFeed } from '../types'

/** Platform announcements, newest first (any admin). */
export function useAdminAnnouncements() {
  return useSWR<{ data: AdminAnnouncement[] }>('/announcements', adminFetcher)
}

export interface PublishAnnouncementInput {
  message: string
  severity: AdminAnnouncement['severity']
  starts_at?: string
  ends_at: string
  reason: string
}

/** Publishes an announcement (ops admin and up; reason audited). */
export function publishAnnouncement(input: PublishAnnouncementInput) {
  return adminFetch<AdminAnnouncement>('/announcements', { method: 'POST', body: input })
}

/** Ends an announcement now (ops admin and up; reason audited). */
export function cancelAnnouncement(id: string, reason: string) {
  return adminFetch<void>(`/announcements/${encodeURIComponent(id)}/cancel`, {
    method: 'POST',
    body: { reason },
  })
}

/**
 * The platform-wide feed states (any admin). While a feed runs, or right after
 * a sync was requested (`fast`), the list refreshes every 2 seconds.
 */
export function useThreatIntelFeeds(fast = false) {
  // Memoized: SWR restarts its polling timer when the interval changes identity.
  const refreshInterval = useCallback(
    (latest?: ThreatIntelFeed[]) =>
      fast || latest?.some((f) => f.state === 'running') ? 2000 : 60000,
    [fast]
  )
  return useSWR<ThreatIntelFeed[]>('/threat-intel/sync', adminFetcher, { refreshInterval })
}

/** What a sync request did for one feed. */
export interface ThreatIntelTriggerResult {
  source: string
  status: 'queued' | 'already_running' | 'skipped'
  /** Why a feed was skipped: disabled, not_configured or rate_limited. */
  reason?: string
}

/**
 * Asks for a sync of one feed (or all) now (ops admin and up; audited). The
 * server queues the work and answers 202 at once; the outcome shows in the
 * feed's state.
 */
export function syncThreatIntel(source: string) {
  return adminFetch<{ results?: ThreatIntelTriggerResult[] }>('/threat-intel/sync', {
    method: 'POST',
    body: { source },
  })
}

/** Turns a feed's scheduled sync on or off (ops admin and up; audited). */
export function setThreatIntelEnabled(source: string, enabled: boolean) {
  return adminFetch<ThreatIntelFeed>(`/threat-intel/sync/${encodeURIComponent(source)}`, {
    method: 'PATCH',
    body: { enabled },
  })
}
