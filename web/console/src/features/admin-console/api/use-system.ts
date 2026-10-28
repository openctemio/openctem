'use client'

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

/** The EPSS and CISA KEV feed sync states (any admin). */
export function useThreatIntelFeeds() {
  return useSWR<ThreatIntelFeed[]>('/threat-intel/sync', adminFetcher)
}

/** One feed's outcome in a sync response. */
export interface ThreatIntelSyncResult {
  source: string
  records_synced: number
  duration_ms: number
  success: boolean
  error?: string
}

/** Syncs one feed (or all) now (ops admin and up; audited). The response is
 * 200 even when a feed failed: read `results[].success`. */
export function syncThreatIntel(source: string) {
  return adminFetch<{ results?: ThreatIntelSyncResult[] }>('/threat-intel/sync', {
    method: 'POST',
    body: { source },
  })
}

/** The feeds a sync response reports as failed. */
export function failedSyncResults(res: { results?: ThreatIntelSyncResult[] } | undefined) {
  return (res?.results ?? []).filter((r) => !r.success)
}

/** Turns a feed's scheduled sync on or off (ops admin and up; audited). */
export function setThreatIntelEnabled(source: string, enabled: boolean) {
  return adminFetch<ThreatIntelFeed>(`/threat-intel/sync/${encodeURIComponent(source)}`, {
    method: 'PATCH',
    body: { enabled },
  })
}
