/**
 * The server's allowed status moves of a finding (GET
 * /api/v1/findings/{id}/transitions) and the bulk dry run (POST
 * /api/v1/findings/transitions:evaluate). The API's transition engine is
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
  to: string
): Promise<EvaluatedTransition[]> {
  const res = await post<{ to: string; results: EvaluatedTransition[] }>(
    '/api/v1/findings/transitions:evaluate',
    { finding_ids: findingIds, to }
  )
  return res?.results ?? []
}
