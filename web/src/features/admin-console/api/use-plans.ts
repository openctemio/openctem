'use client'

import useSWR from 'swr'
import type {
  PlanDefaultsResponse,
  PlanSummaryResponse,
  SetPlanOverrideRequest,
  UpdatePlanDefaultsRequest,
} from '@/lib/api/generated'
import { adminFetch, adminFetcher } from './admin-client'

const DEFAULTS_KEY = '/settings/plans'
const tenantPlanKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/plan`

/** The plan defaults (System > Plans). Any administrator reads them. */
export function usePlanDefaults() {
  return useSWR<PlanDefaultsResponse>(DEFAULTS_KEY, adminFetcher)
}

/**
 * Saves the plan defaults (super admin). `version` is the version that was
 * read (409 when someone else saved since); `totp_code` is a fresh code from
 * the console authenticator.
 */
export function savePlanDefaults(input: UpdatePlanDefaultsRequest) {
  return adminFetch<PlanDefaultsResponse>(DEFAULTS_KEY, { method: 'PUT', body: input })
}

/** One organization's plan, limits, usage and over-limit flag. */
export function useTenantPlan(tenantId: string) {
  return useSWR<PlanSummaryResponse>(tenantId ? tenantPlanKey(tenantId) : null, adminFetcher)
}

/** Changes the organization's plan (ops admin and up). Nothing is removed. */
export function setTenantPlan(tenantId: string, plan: string) {
  return adminFetch<PlanSummaryResponse>(tenantPlanKey(tenantId), {
    method: 'PUT',
    body: { plan },
  })
}

/** Sets one limit for this organization (ops admin and up; reason required). */
export function putPlanOverride(tenantId: string, key: string, input: SetPlanOverrideRequest) {
  return adminFetch<PlanSummaryResponse>(
    `${tenantPlanKey(tenantId)}/overrides/${encodeURIComponent(key)}`,
    { method: 'PUT', body: input }
  )
}

/** Removes one per-organization limit; the plan default applies again. */
export function deletePlanOverride(tenantId: string, key: string) {
  return adminFetch<PlanSummaryResponse>(
    `${tenantPlanKey(tenantId)}/overrides/${encodeURIComponent(key)}`,
    { method: 'DELETE' }
  )
}
