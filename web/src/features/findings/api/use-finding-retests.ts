/**
 * Continuous retest hooks (RFC-039).
 *
 *   GET  /api/v1/findings/{id}/retests   — the finding's retests, newest first
 *   POST /api/v1/findings/{id}/retests   — "Retest now" (needs findings:verify)
 *
 * A retest re-runs the rule that produced the finding against its own target,
 * on a sensor that reports it can re-check findings of that tool. Its result
 * arrives asynchronously, so the list polls while the newest retest is still
 * pending. The list says whether a retest would be accepted now (can_retest).
 */

'use client'

import useSWR, { useSWRConfig } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { FindingRetestListResponse, FindingRetestResponse } from '@/lib/api/generated'

export type FindingRetest = FindingRetestResponse

/** Poll every 5 s while a retest is running. */
export const RETEST_POLL_MS = 5000

/** Statuses a retest may run on (the API refuses the others). */
const RETESTABLE_STATUSES = new Set(['new', 'confirmed', 'in_progress', 'fix_applied', 'resolved'])

/**
 * Whether a finding may have a deterministic re-check: a rule of a tool, in an
 * open or resolved status. Which tools can be re-checked is decided by the API
 * from what the organization's sensors report (`can_retest` on the retest
 * list); this only keeps the button and the history request off findings the
 * API would always refuse.
 */
export function isRetestable(finding: {
  toolName?: string
  ruleId?: string
  status?: string
}): boolean {
  return (
    !!finding.toolName?.trim() &&
    !!finding.ruleId?.trim() &&
    RETESTABLE_STATUSES.has(finding.status ?? '')
  )
}

/** Whether a finding can have retest history: a rule of a tool, any status. */
export function hasRetestHistory(finding: { toolName?: string; ruleId?: string }): boolean {
  return !!finding.toolName?.trim() && !!finding.ruleId?.trim()
}

function retestsEndpoint(findingId: string): string {
  return `/api/v1/findings/${findingId}/retests`
}

/** A finding's retests, newest first. Polls while the newest is pending. */
export function useFindingRetests(findingId: string | null) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? retestsEndpoint(findingId) : null
  return useSWR<FindingRetestListResponse>(
    key,
    (url: string) => get<FindingRetestListResponse>(url),
    {
      revalidateOnFocus: false,
      refreshInterval: (latest) => (latest?.data?.[0]?.status === 'pending' ? RETEST_POLL_MS : 0),
    }
  )
}

/**
 * "Retest now". On success the retest list is revalidated, so the pending
 * retest shows (and polling starts) at once.
 */
export function useRequestRetest(findingId: string) {
  const { currentTenant } = useTenant()
  const { mutate } = useSWRConfig()
  const key = currentTenant && findingId ? retestsEndpoint(findingId) : null
  return useSWRMutation(key, async (url: string) => {
    const created = await post<FindingRetestResponse>(url, {})
    await mutate(url)
    return created
  })
}
