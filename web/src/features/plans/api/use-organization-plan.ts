'use client'

import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import type { PlanSummaryResponse } from '@/lib/api/generated'

/** GET /api/v1/organization/plan: the caller's organization (from the credential). */
export const ORGANIZATION_PLAN_URL = '/api/v1/organization/plan'

/** The organization's plan, limits and usage (Settings > Plan & usage; owners and admins). */
export function useOrganizationPlan() {
  return useSWR<PlanSummaryResponse>(ORGANIZATION_PLAN_URL, fetcher)
}
