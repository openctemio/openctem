'use client'

import useSWR from 'swr'

import { fetcher } from '@/lib/api/client'
import type { SecurityOverview } from '@/lib/api/generated'

/** GET /api/v1/organization/security-overview: the organization of the credential. */
export const SECURITY_OVERVIEW_URL = '/api/v1/organization/security-overview'

/**
 * The security overview (Settings > Security overview; owners and admins).
 * The server computes it per request; `mutate()` is the Re-check button.
 */
export function useSecurityOverview(enabled = true) {
  return useSWR<SecurityOverview>(enabled ? SECURITY_OVERVIEW_URL : null, fetcher, {
    shouldRetryOnError: false,
    revalidateOnFocus: false,
  })
}
