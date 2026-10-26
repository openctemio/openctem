/**
 * Organization enrollment tokens and the sensors waiting for approval
 * (api docs/architecture/sensor-pairing.md, "Enrollment tokens").
 *
 * A token is shown once, in the answer to its creation; the list never
 * carries it. Creating one needs a recent re-authentication: the shared
 * client opens the step-up dialog when the API asks for it. Every route is
 * tenant-scoped by the session.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { get, post } from './client'
import type { SensorPairingView } from './sensor-pairing-hooks'

export const ENROLLMENT_TOKENS_PATH = '/api/v1/sensor-pairings/enrollment-tokens'
export const PENDING_PAIRINGS_PATH = '/api/v1/sensor-pairings/pending'

export type EnrollmentTokenState = 'active' | 'expired' | 'exhausted' | 'revoked'

export interface EnrollmentToken {
  id: string
  name: string
  /** Only in the answer to the creation. */
  token?: string
  token_hint: string
  state: EnrollmentTokenState
  max_uses: number
  use_count: number
  require_approval: boolean
  sensor_type: string
  grant_profile?: string
  zone_ids: string[]
  labels: Record<string, string>
  allowed_cidrs: string[]
  created_by?: string
  created_at: string
  expires_at: string
  last_used_at?: string
  last_used_from?: string
  revoked_at?: string
}

export interface CreateEnrollmentTokenRequest {
  name: string
  ttl_hours: number
  max_uses: number
  require_approval: boolean
  sensor_type?: string
  grant_profile?: string
  zone_ids?: string[]
  labels?: Record<string, string>
  allowed_cidrs?: string[]
}

export function useEnrollmentTokens(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ items: EnrollmentToken[] }>(
    currentTenant && enabled ? ENROLLMENT_TOKENS_PATH : null,
    (url: string) => get<{ items: EnrollmentToken[] }>(url),
    { revalidateOnFocus: false }
  )
}

export async function createEnrollmentToken(
  body: CreateEnrollmentTokenRequest
): Promise<EnrollmentToken> {
  const out = await post<EnrollmentToken>(ENROLLMENT_TOKENS_PATH, body)
  await globalMutate(ENROLLMENT_TOKENS_PATH)
  return out
}

export async function revokeEnrollmentToken(id: string): Promise<EnrollmentToken> {
  const out = await post<EnrollmentToken>(
    `${ENROLLMENT_TOKENS_PATH}/${encodeURIComponent(id)}/revoke`,
    {}
  )
  await globalMutate(ENROLLMENT_TOKENS_PATH)
  return out
}

/** Poll interval of the waiting-for-approval list while it is on screen. */
export const PENDING_POLL_MS = 10_000

export function usePendingPairings(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ items: SensorPairingView[] }>(
    currentTenant && enabled ? PENDING_PAIRINGS_PATH : null,
    (url: string) => get<{ items: SensorPairingView[] }>(url),
    { revalidateOnFocus: true, refreshInterval: PENDING_POLL_MS }
  )
}

export function refreshPendingPairings() {
  return globalMutate(PENDING_PAIRINGS_PATH)
}
