/**
 * The server's allowed status moves of a finding (GET
 * /api/v1/findings/{id}/transitions) and the bulk dry run (POST
 * /api/v1/findings/transitions/preview). The API's transition engine is
 * the only copy of the lifecycle rules; the console renders its decisions.
 */

import useSWR, { type SWRConfiguration } from 'swr'
import { get, post } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { FindingStatus } from '../types'

export interface TransitionBlock {
  code: string
  params?: Record<string, string>
}

export interface TransitionDecision {
  to: FindingStatus
  allowed: boolean
  mode?: 'direct' | 'request' | 'duplicate_picker'
  requires?: string[]
  blocked?: TransitionBlock[]
  /** The organization sub-status the move lands on; absent: the target's default label. */
  to_sub_status_id?: string
  /** The organization's listed move that matched, and its name. */
  transition?: string
  name?: string
  /** The shortest note the move accepts (0 or absent: the platform rule). */
  note_min_len?: number
  /** Inputs the move requires (ticket_link, fix_reference, ...). */
  fields?: string[]
  /** The closure reason a closed sub-status binds; the move sets it. */
  closure_reason?: string
}

export interface FindingTransitions {
  status: FindingStatus
  transitions: TransitionDecision[]
}

export interface EvaluatedTransition {
  finding_id: string
  not_found?: boolean
  decision?: TransitionDecision
}

export function findingTransitionsKey(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/transitions`
}

/** The caller's moves of one finding; null id disables the request. */
export function useFindingTransitions(findingId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? findingTransitionsKey(findingId) : null
  return useSWR<FindingTransitions>(key, (url: string) => get<FindingTransitions>(url), {
    revalidateOnFocus: false,
    ...config,
  })
}

/** Dry run: whether each finding may move to `to`, and why not. */
export async function evaluateFindingTransitions(
  findingIds: string[],
  to: string,
  subStatusId?: string
): Promise<EvaluatedTransition[]> {
  const res = await post<{ to: string; results: EvaluatedTransition[] }>(
    '/api/v1/findings/transitions/preview',
    { finding_ids: findingIds, to, ...(subStatusId ? { sub_status_id: subStatusId } : {}) }
  )
  return res?.results ?? []
}
