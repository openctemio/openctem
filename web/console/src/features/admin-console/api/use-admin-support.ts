'use client'

/**
 * Support sessions (api RFC-063), the console's side. An organization owner
 * granted the caller read-only access to chosen data for a few hours; the
 * caller opens a session (route-level console step-up: adminFetch prompts and
 * retries) and reads through a narrow read model. Every read is checked and
 * audited on the server: the grant must be live, the session the caller's and
 * bound to this console session, the scope granted.
 */

import useSWR from 'swr'

import type {
  AdminSupportAssetList,
  AdminSupportFindingList,
  AdminSupportGrantList,
  AdminSupportSession,
  SupportAssetView,
  SupportFindingView,
  SupportOverview,
} from '@/lib/api/generated'

import { AdminApiError, adminFetch, adminFetcher } from '@console/lib/admin-api/client'

/** The grant behind the session ended (revoked, expired, ended, or another console session). */
export const SUPPORT_GRANT_REQUIRED = 'SUPPORT_GRANT_REQUIRED'

export function isSupportAccessEnded(err: unknown): boolean {
  return err instanceof AdminApiError && err.code === SUPPORT_GRANT_REQUIRED
}

export const SUPPORT_PAGE_SIZE = 25

const s = (id: string) => `/support/sessions/${encodeURIComponent(id)}`

/** The live grants naming the caller. */
export function useAdminSupportGrants() {
  return useSWR<AdminSupportGrantList>('/support/grants', adminFetcher, {
    revalidateOnFocus: true,
  })
}

export function openSupportSession(grantId: string, reason?: string) {
  return adminFetch<AdminSupportSession>(
    `/support/grants/${encodeURIComponent(grantId)}/sessions`,
    { method: 'POST', body: reason ? { reason } : {} }
  )
}

export function endSupportSession(sessionId: string) {
  return adminFetch<unknown>(s(sessionId), { method: 'DELETE' })
}

/** Reads never retry: a refused read means the access ended or was not granted. */
const READ_OPTS = { revalidateOnFocus: false, shouldRetryOnError: false } as const

export function useSupportOverview(sessionId: string) {
  return useSWR<SupportOverview>(`${s(sessionId)}/overview`, adminFetcher, READ_OPTS)
}

export interface SupportListParams {
  search: string
  severity?: string
  status: string
  page: number
}

function qs(p: SupportListParams): string {
  const q = new URLSearchParams()
  if (p.search.trim()) q.set('search', p.search.trim())
  if (p.severity) q.set('severity', p.severity)
  if (p.status) q.set('status', p.status)
  q.set('page', String(p.page))
  q.set('per_page', String(SUPPORT_PAGE_SIZE))
  return q.toString()
}

export function useSupportFindings(sessionId: string, p: SupportListParams) {
  return useSWR<AdminSupportFindingList>(`${s(sessionId)}/findings?${qs(p)}`, adminFetcher, {
    ...READ_OPTS,
    keepPreviousData: true,
  })
}

export function useSupportAssets(sessionId: string, p: SupportListParams) {
  return useSWR<AdminSupportAssetList>(`${s(sessionId)}/assets?${qs(p)}`, adminFetcher, {
    ...READ_OPTS,
    keepPreviousData: true,
  })
}

export function useSupportFinding(sessionId: string, id: string | null) {
  return useSWR<SupportFindingView>(
    id ? `${s(sessionId)}/findings/${encodeURIComponent(id)}` : null,
    adminFetcher,
    READ_OPTS
  )
}

export function useSupportAsset(sessionId: string, id: string | null) {
  return useSWR<SupportAssetView>(
    id ? `${s(sessionId)}/assets/${encodeURIComponent(id)}` : null,
    adminFetcher,
    READ_OPTS
  )
}
