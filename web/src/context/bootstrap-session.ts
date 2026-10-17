/**
 * The session parts of GET /me/bootstrap, written into the SWR cache under the
 * keys of the endpoints they replace.
 *
 * Every page of the app shell used to ask, on each load, for the caller's
 * profile (/users/me), their organizations (/users/me/tenants), the unread
 * notification count, the review-queue and approvals badges, the organization policy
 * (/auth/providers) and the platform announcements. The bootstrap now returns all of them in one response
 * (research/81). Seeding the cache keeps every existing consumer (`useProfile`,
 * `useMyTenants`, the bell, the sidebar badge) working unchanged: they read
 * the seeded value, and those hooks do not revalidate a cached value on mount
 * (`revalidateIfStale: false`), so nothing is fetched twice. Mutations still
 * refresh them with `mutate(key)`, and the WebSocket keeps the unread count live.
 *
 * A field the API left out (an older API, a count the caller may not read, a
 * source that failed) is not seeded, and its hook fetches as before.
 */
import { mutate } from 'swr'

import { notificationEndpoints, userEndpoints } from '@/lib/api/endpoints'
import type { TenantMembership } from '@/lib/api/user-tenant-types'
import type { UserProfile } from '@/features/account/types/account.types'

export interface BootstrapBadges {
  unread_notifications?: number
  easm_review?: number
  pending_approvals?: number
}

/** One platform announcement (GET /api/v1/announcements). */
export interface PlatformAnnouncement {
  id: string
  message: string
  severity: 'info' | 'warning' | 'maintenance'
  starts_at: string
  ends_at?: string
}

export interface BootstrapSessionData {
  user?: UserProfile
  tenants?: TenantMembership[]
  tenant_creation_mode?: string
  badges?: BootstrapBadges
  announcements?: PlatformAnnouncement[]
  /** A limit or module deny applies to the organization (owners and admins). */
  limits_apply?: boolean
}

/**
 * SWR key of the bootstrap's limits_apply: read from the cache only (no
 * request), so the settings rail decides whether to list Usage & limits
 * without a call on every page.
 */
export const LIMITS_APPLY_KEY = 'bootstrap:limits_apply'

/** The platform notices the announcement banner reads. */
export const ANNOUNCEMENTS_URL = '/api/v1/announcements'

/**
 * The attack surface decision count the sidebar badge and the Suggestions
 * tab read: `total` of the suggestion cards (one per card, not per row).
 */
export const EASM_SUGGESTIONS_COUNT_URL = '/api/v1/easm/suggestions?view=count'

/**
 * The finding approvals waiting for a decision (the Approvals sidebar badge):
 * `status_counts.pending` of the approvals list, under the caller's data scope.
 */
export const PENDING_APPROVALS_COUNT_URL = '/api/v1/approvals?status=pending&page=1&per_page=1'

/** Writes the session parts into the SWR cache, without revalidating them. */
export async function seedSessionCache(data: BootstrapSessionData): Promise<void> {
  const writes: Promise<unknown>[] = []
  const seed = (key: string, value: unknown) =>
    writes.push(mutate(key, value, { revalidate: false }))

  if (data.user) seed(userEndpoints.me(), data.user)
  if (data.tenants) seed(userEndpoints.myTenants(), data.tenants)
  if (typeof data.badges?.unread_notifications === 'number')
    seed(notificationEndpoints.unreadCount(), { count: data.badges.unread_notifications })
  if (typeof data.badges?.easm_review === 'number')
    seed(EASM_SUGGESTIONS_COUNT_URL, { cards: [], total: data.badges.easm_review, can_add: false })
  if (typeof data.badges?.pending_approvals === 'number')
    seed(PENDING_APPROVALS_COUNT_URL, {
      data: [],
      total: data.badges.pending_approvals,
      page: 1,
      per_page: 1,
      status_counts: { pending: data.badges.pending_approvals },
    })
  if (Array.isArray(data.announcements)) seed(ANNOUNCEMENTS_URL, { data: data.announcements })
  seed(LIMITS_APPLY_KEY, data.limits_apply === true)

  await Promise.all(writes)
}
