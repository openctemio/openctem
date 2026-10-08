/**
 * The session parts of GET /me/bootstrap, written into the SWR cache under the
 * keys of the endpoints they replace.
 *
 * Every page of the app shell used to ask, on each load, for the caller's
 * profile (/users/me), their organizations (/users/me/tenants), the unread
 * notification count, the review-queue badge and the organization policy
 * (/auth/providers). The bootstrap now returns all of them in one response
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
}

export interface BootstrapSessionData {
  user?: UserProfile
  tenants?: TenantMembership[]
  tenant_creation_mode?: string
  badges?: BootstrapBadges
}

/** The review-queue count the sidebar badge reads (one row, `total` only). */
export const EASM_REVIEW_COUNT_URL =
  '/api/v1/easm/candidates?states=needs_review%2Ccandidate&page=1&per_page=1'

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
    seed(EASM_REVIEW_COUNT_URL, { data: [], total: data.badges.easm_review })

  await Promise.all(writes)
}
