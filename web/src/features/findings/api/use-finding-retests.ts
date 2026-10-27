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

/**
 * A retest that ran the finding's retest check carries the check's id and the
 * digest of the template that ran (see use-finding-retest-check.ts). Declared
 * here until the generated contract includes them.
 */
export type FindingRetestWithCheck = FindingRetest & {
  retest_check_id?: string
  check_digest?: string
}

/** How a finding is re-checked (strategy on the retest list). */
export type RetestStrategyKind = 'template' | 'custom_check' | 'version_recheck' | 'none'

export interface RetestStrategy {
  kind: RetestStrategyKind
  /** The template or rule re-run, or the CVE a version re-check evaluates. */
  rule?: string
  /** The tool that re-checks (the fingerprint tool for version_recheck). */
  tool?: string
  product?: string
  version?: string
}

/** An installed template that can run as an optional active check. */
export interface RetestActiveCheck {
  template: string
  available: boolean
  reason?: string
}

/**
 * The retest list with what the server says about re-checking the finding:
 * the strategy, why a retest would be refused (reason) and the optional
 * active check. Declared here until the generated contract includes them.
 */
export type FindingRetestList = FindingRetestListResponse & {
  reason?: string
  strategy?: RetestStrategy
  active_check?: RetestActiveCheck
}

/** Request modes: the finding's strategy, or the active check. */
export type RetestMode = 'active_check'

/** Poll every 5 s while a retest is running. */
export const RETEST_POLL_MS = 5000

/** Statuses a retest may run on (the API refuses the others). */
export const RETESTABLE_STATUSES = new Set([
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
  'resolved',
])

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
  return useSWR<FindingRetestList>(key, (url: string) => get<FindingRetestList>(url), {
    revalidateOnFocus: false,
    refreshInterval: (latest) => (latest?.data?.[0]?.status === 'pending' ? RETEST_POLL_MS : 0),
  })
}

/**
 * "Retest now" (or, with mode active_check, the optional active check of a
 * version-based finding). On success the retest list is revalidated, so the
 * pending retest shows (and polling starts) at once.
 */
export function useRequestRetest(findingId: string) {
  const { currentTenant } = useTenant()
  const { mutate } = useSWRConfig()
  const key = currentTenant && findingId ? retestsEndpoint(findingId) : null
  return useSWRMutation(key, async (url: string, { arg }: { arg?: RetestMode }) => {
    const created = await post<FindingRetestResponse>(url, arg ? { mode: arg } : {})
    await mutate(url)
    return created
  })
}
