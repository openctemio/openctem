'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'
import type { Paged, PlatformUser, PlatformUserAction, PlatformUserDetail } from '../types'

/** The API refuses shorter searches (the directory is looked up, not browsed). */
export const PLATFORM_USER_SEARCH_MIN = 3

/** Accounts whose email or name contains q, or whose id is q. */
export function usePlatformUsers(q: string, page = 1, perPage = 25) {
  const term = q.trim()
  const key =
    term.length >= PLATFORM_USER_SEARCH_MIN
      ? `/platform-users?${new URLSearchParams({ q: term, page: String(page), per_page: String(perPage) })}`
      : null
  return useSWR<Paged<PlatformUser>>(key, adminFetcher, { keepPreviousData: true })
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
