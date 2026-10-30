'use client'

import useSWR, { mutate as globalMutate, type SWRConfiguration } from 'swr'
import { get, post } from '@/lib/api/client'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { READY_TO_CLOSE_COUNT_URL } from '@/context/bootstrap-session'
import { useTenant } from '@/context/tenant-provider'
import type {
  AutoClosedFinding,
  ClosureProposal,
  DecideResult,
  DismissReason,
  PagedList,
} from './types'

const BASE = '/api/v1/findings/closure'

// The Ready to close count: the bootstrap seeds this key from
// badges.ready_to_close, so no page asks for it on load.
export { READY_TO_CLOSE_COUNT_URL }

export function proposalsUrl(page: number, perPage: number): string {
  return `${BASE}/proposals?page=${page}&per_page=${perPage}`
}

export function autoClosedUrl(page: number, perPage: number): string {
  return `${BASE}/auto-closed?page=${page}&per_page=${perPage}`
}

const listConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

export function useClosureProposals(page: number, perPage: number, enabled = true) {
  return useSWR<PagedList<ClosureProposal>>(
    enabled ? proposalsUrl(page, perPage) : null,
    (url: string) => get<PagedList<ClosureProposal>>(url),
    listConfig
  )
}

export function useRecentlyAutoClosed(page: number, perPage: number, enabled = true) {
  return useSWR<PagedList<AutoClosedFinding>>(
    enabled ? autoClosedUrl(page, perPage) : null,
    (url: string) => get<PagedList<AutoClosedFinding>>(url),
    listConfig
  )
}

/** The Ready to close count for verifiers, from the seeded bootstrap value. */
export function useReadyToCloseCount(shouldFetch: boolean): number | undefined {
  const { currentTenant } = useTenant()
  const bootstrapPending = useBootstrapPending()
  const key =
    currentTenant?.id && shouldFetch && !bootstrapPending ? READY_TO_CLOSE_COUNT_URL : null
  const { data } = useSWR<{ total?: number }>(key, (url: string) => get<{ total?: number }>(url), {
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
    revalidateIfStale: false,
  })
  return data?.total
}

/** Re-reads the lists and the count after a decision. */
export function refreshClosureReview() {
  return globalMutate((key) => typeof key === 'string' && key.startsWith(BASE))
}

/** Confirms (closes as fixed) or dismisses (keeps open) proposals. */
export function decideClosureProposals(body: {
  proposal_ids: string[]
  decision: 'confirm' | 'dismiss'
  reason?: DismissReason
  note?: string
}): Promise<DecideResult> {
  return post<DecideResult>(`${BASE}/proposals/decide`, body)
}

/** Reopens a finding the platform closed by itself: not fixed. */
export function reopenNotFixed(findingId: string, note?: string): Promise<void> {
  return post<void>(
    `/api/v1/findings/${encodeURIComponent(findingId)}/reopen-not-fixed`,
    note ? { note } : {}
  )
}
