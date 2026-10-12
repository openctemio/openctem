'use client'

import useSWR from 'swr'
import { get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

export const CYCLE_POLICY_ENDPOINT = '/api/v1/organization/settings/cycles'

/** The organization's CTEM cycle policy. */
export interface CyclePolicy {
  /** Closing a cycle needs its validation coverage to meet the coverage SLO. */
  enforce_coverage_slo: boolean
}

/** The cycle policy, read by owners and admins only (the API answers 403 otherwise). */
export function useCyclePolicy() {
  const { can } = usePermissions()
  const key = can(Permission.TeamUpdate) ? CYCLE_POLICY_ENDPOINT : null
  return useSWR<CyclePolicy>(key, (url: string) => get<CyclePolicy>(url), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

export async function updateCyclePolicy(policy: CyclePolicy): Promise<CyclePolicy> {
  return put<CyclePolicy>(CYCLE_POLICY_ENDPOINT, policy)
}
