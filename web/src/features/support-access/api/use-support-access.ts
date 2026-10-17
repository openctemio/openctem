/**
 * Support access (api RFC-063), the organization's side.
 *
 * - `GET …/active` (every member): who from platform support can read the
 *   organization's data right now; drives the banner.
 * - `GET …/grants` (owners and admins): every grant, history included.
 * - `POST …/grants` (owner + recent re-authentication: the shared client
 *   answers STEP_UP_REQUIRED with the re-auth dialog and retries).
 * - `DELETE …/grants/{id}` (owners and admins): revoke now.
 *
 * The UI hides actions by role for clarity only; the API is the authority.
 */

import useSWR from 'swr'

import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'
import type {
  SupportActiveList,
  SupportGrant,
  SupportGrantInput,
  SupportGrantList,
} from '@/lib/api/generated'

export type SupportScope = 'findings' | 'assets'
export const SUPPORT_SCOPES: SupportScope[] = ['findings', 'assets']
export const SUPPORT_DURATIONS = [1, 4, 8, 24, 72] as const
export const SUPPORT_DEFAULT_DURATION = 4
export const SUPPORT_REASON_MIN = 10
export const SUPPORT_REASON_MAX = 500

/** The banner polls once a minute and on focus: one small, indexed read. */
const ACTIVE_REFRESH_MS = 60_000

export function useActiveSupportAccess(enabled = true) {
  const { data } = useSWR<SupportActiveList>(
    enabled ? tenantEndpoints.supportAccessActive() : null,
    fetcher,
    {
      refreshInterval: ACTIVE_REFRESH_MS,
      revalidateOnFocus: true,
      shouldRetryOnError: false,
      dedupingInterval: 10_000,
    }
  )
  return data?.data ?? []
}

export function useSupportGrants(enabled: boolean) {
  const { data, error, isLoading, mutate } = useSWR<SupportGrantList>(
    enabled ? tenantEndpoints.supportAccessGrants() : null,
    fetcher,
    { revalidateOnFocus: true }
  )
  return { grants: data?.data ?? [], error, isLoading: enabled && isLoading, mutate }
}

export function createSupportGrant(input: SupportGrantInput) {
  return fetcherWithOptions<SupportGrant>(tenantEndpoints.supportAccessGrants(), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function revokeSupportGrant(grantId: string) {
  return fetcherWithOptions<SupportGrant>(tenantEndpoints.supportAccessGrant(grantId), {
    method: 'DELETE',
  })
}
