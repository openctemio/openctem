'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type {
  PlatformUserAction,
  PlatformUserDetail,
  PlatformUserList,
  PlatformUserState,
} from '../types'

/** The API refuses shorter searches; an empty search browses. */
export const PLATFORM_USER_SEARCH_MIN = 3

/**
 * Accounts newest first in one state, optionally narrowed to those whose
 * email or name contains q (or whose id is q). Every view is audited.
 */
export function usePlatformUsers(q: string, state: PlatformUserState, page = 1, perPage = 25) {
  const term = q.trim()
  const params = new URLSearchParams({ state, page: String(page), per_page: String(perPage) })
  if (term.length >= PLATFORM_USER_SEARCH_MIN) params.set('q', term)
  const key =
    term.length === 0 || term.length >= PLATFORM_USER_SEARCH_MIN
      ? `/platform-users?${params}`
      : null
  return useSWR<PlatformUserList>(key, adminFetcher, { keepPreviousData: true })
}

/** One account with memberships, identities and active sessions (viewing is audited). */
export function usePlatformUser(id: string | null) {
  return useSWR<PlatformUserDetail>(
    id ? `/platform-users/${encodeURIComponent(id)}` : null,
    adminFetcher
  )
}

/** Runs a support action (ops admin and up; the reason goes to the audit log). */
export function runPlatformUserAction(id: string, action: PlatformUserAction, reason: string) {
  return adminFetch<{ status: string }>(`/platform-users/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    body: { reason },
  })
}
