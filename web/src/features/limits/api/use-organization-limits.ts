'use client'

import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import type { OrganizationLimitsResponse } from '@/lib/api/generated'

/** GET /api/v1/organization/limits: the caller's organization (from the credential). */
export const ORGANIZATION_LIMITS_URL = '/api/v1/organization/limits'

/**
 * The limits and unavailable modules that apply to the organization
 * (Settings > Usage & limits; owners and admins). `enabled: false` skips the
 * request (a member may not read it).
 */
export function useOrganizationLimits(enabled = true) {
  return useSWR<OrganizationLimitsResponse>(enabled ? ORGANIZATION_LIMITS_URL : null, fetcher, {
    shouldRetryOnError: false,
  })
}
