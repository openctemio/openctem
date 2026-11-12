'use client'

import useSWR from 'swr'
import { del, get, post } from '@/lib/api/client'
import { useRegisterPages } from '@/lib/api/use-register-pages'
import type { CtemCycle } from './types'

/**
 * Reads and writes of one CTEM cycle. Lifecycle transitions have their own
 * endpoints (activate snapshots the scope, close evaluates the charter); a
 * plain update never changes the status.
 */

export const cycleKey = (id: string) => `/api/v1/ctem-cycles/${id}`

export function useCycle(id: string | null) {
  return useSWR<CtemCycle>(id ? cycleKey(id) : null, (url: string) => get<CtemCycle>(url), {
    revalidateOnFocus: false,
  })
}

/**
 * One asset frozen into the cycle's scope on Activate. The asset fields are
 * joined by the API (empty when the asset was deleted since).
 */
export interface CycleScopeItem {
  id: string
  asset_id: string
  scope_target_id?: string
  included_at: string
  asset_name?: string
  asset_type?: string
  asset_criticality?: string
}

/** The scope snapshot (empty until the cycle is activated). */
export function useCycleScope(id: string | null) {
  return useSWR<CycleScopeItem[]>(
    id ? `${cycleKey(id)}/scope` : null,
    (url: string) => get<CycleScopeItem[]>(url),
    { revalidateOnFocus: false }
  )
}

export interface AttackerProfile {
  id: string
  name: string
  description?: string
  profile_type: string
  is_default?: boolean
}

export const PROFILE_TYPE_LABELS: Record<string, string> = {
  external_unauth: 'External, unauthenticated',
  external_stolen_creds: 'External, stolen credentials',
  malicious_insider: 'Malicious insider',
  supplier_compromise: 'Supplier compromise',
  custom: 'Custom',
}

/**
 * The attacker-profile type in words. With `t` it comes from the catalog
 * (attackerProfiles.type.<type>); the English map is the fallback.
 */
export const profileTypeLabel = (type: string, t?: (key: string, fallback?: string) => string) => {
  const fallback =
    PROFILE_TYPE_LABELS[type] ?? type.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
  return t ? t(`attackerProfiles.type.${type}`, fallback) : fallback
}

/** The attacker profiles the cycle assumes (GET /ctem-cycles/{id}/profiles). */
export function useCycleProfiles(id: string | null) {
  return useSWR<{ data: AttackerProfile[] }>(
    id ? `${cycleKey(id)}/profiles` : null,
    (url: string) => get<{ data: AttackerProfile[] }>(url),
    { revalidateOnFocus: false }
  )
}

/** Every attacker profile of the tenant, for pickers. */
export function useAttackerProfiles(enabled = true) {
  return useRegisterPages<AttackerProfile>(
    enabled ? '/api/v1/attacker-profiles?per_page=100' : null
  )
}

export function linkCycleProfiles(cycleId: string, profileIds: string[]): Promise<unknown> {
  return post(`${cycleKey(cycleId)}/profiles`, { profile_ids: profileIds })
}

export function unlinkCycleProfile(cycleId: string, profileId: string): Promise<unknown> {
  return del(`${cycleKey(cycleId)}/profiles/${profileId}`)
}

/**
 * Apply a new selection of profiles: link the added ones in one call, unlink
 * the removed ones. Throws on the first failure.
 */
export async function syncCycleProfiles(
  cycleId: string,
  before: readonly string[],
  after: readonly string[]
): Promise<void> {
  const added = after.filter((id) => !before.includes(id))
  const removed = before.filter((id) => !after.includes(id))
  if (added.length) await linkCycleProfiles(cycleId, added)
  await Promise.all(removed.map((id) => unlinkCycleProfile(cycleId, id)))
}

export type CycleTransition = 'activate' | 'review' | 'close'

const TRANSITION_ENDPOINT: Record<CycleTransition, string> = {
  activate: 'activate',
  review: 'start-review',
  close: 'close',
}

/**
 * The body of a close that overrides a validation coverage check that could
 * not run (the API refuses the close with COVERAGE_CHECK_FAILED otherwise).
 * The reason is audited. It never lifts an enforced coverage SLO.
 */
export interface CloseOverride {
  override_coverage_check: true
  override_reason: string
}

/** The API's code when a close was refused because the coverage check failed. */
export const COVERAGE_CHECK_FAILED = 'COVERAGE_CHECK_FAILED'

/** Shortest override reason the API accepts. */
export const MIN_OVERRIDE_REASON = 10

export function transitionCycle(
  id: string,
  action: CycleTransition,
  override?: CloseOverride
): Promise<CtemCycle> {
  const url = `${cycleKey(id)}/${TRANSITION_ENDPOINT[action]}`
  return override ? post<CtemCycle>(url, override) : post<CtemCycle>(url)
}

export function saveScopeRefinement(id: string, notes: string): Promise<unknown> {
  return post(`${cycleKey(id)}/scope-refinement`, { scope_refinement_notes: notes })
}
