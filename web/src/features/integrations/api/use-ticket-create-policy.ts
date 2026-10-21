/**
 * Ticket create policy of a Jira integration: which findings the automatic
 * path files as issues, its preview, and a finding's holds
 * (api/docs/architecture/ticket-create-policy.md).
 */
import useSWR, { mutate } from 'swr'
import { get, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'

export type TicketHoldReason = 'below_threshold' | 'daily_cap' | 'create_failed'

export interface TicketCreatePolicy {
  min_severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  /** '' when the priority-class floor is not used. */
  min_priority_class: '' | 'P0' | 'P1' | 'P2' | 'P3'
  always_kev: boolean
  /** 0 = no cap. */
  daily_cap: number
  updated_at?: string
}

export interface TicketCreatePolicyResponse {
  policy: TicketCreatePolicy
  defaults: TicketCreatePolicy
  stored: boolean
  stats: { held_by_reason: Partial<Record<TicketHoldReason, number>>; created_today: number }
}

export interface TicketCreatePolicyPreview {
  last_30_days_total: number
  last_30_days_pass: number
  held_now: number
  held_would_pass: number
}

export interface TicketHold {
  integration_id: string
  finding_id: string
  reason: TicketHoldReason
  detail?: string
  held_at: string
  checked_at: string
}

export const MAX_DAILY_CAP = 10000

const policyPath = (integrationId: string) =>
  `/api/v1/integrations/${integrationId}/ticket-create-policy`

function body(p: TicketCreatePolicy) {
  return {
    min_severity: p.min_severity,
    min_priority_class: p.min_priority_class,
    always_kev: p.always_kev,
    daily_cap: p.daily_cap,
  }
}

export function useTicketCreatePolicy(integrationId: string, enabled = true) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? policyPath(integrationId) : null
  return useSWR<TicketCreatePolicyResponse>(
    key,
    (u: string) => get<TicketCreatePolicyResponse>(u),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    }
  )
}

export async function saveTicketCreatePolicy(integrationId: string, p: TicketCreatePolicy) {
  const res = await put<TicketCreatePolicyResponse>(policyPath(integrationId), body(p))
  await mutate(policyPath(integrationId), res, { revalidate: false })
  return res
}

export function previewTicketCreatePolicy(integrationId: string, p: TicketCreatePolicy) {
  return post<TicketCreatePolicyPreview>(`${policyPath(integrationId)}/preview`, body(p))
}

export function useFindingTicketHolds(findingId: string) {
  const { currentTenant } = useTenant()
  const key = currentTenant && findingId ? `/api/v1/findings/${findingId}/ticket-holds` : null
  return useSWR<{ holds: TicketHold[] }>(key, (u: string) => get<{ holds: TicketHold[] }>(u), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}
