'use client'

import useSWR from 'swr'
import type {
  AdminTenantModulesResponse,
  DeleteModuleGrantRequest,
  PlanModulesResponse,
  SetModuleGrantRequest,
  UpdatePlanModulesRequest,
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

// ---------------------------------------------------------------------------
// Module entitlements (RFC-064)
// ---------------------------------------------------------------------------

const PLAN_MODULES_KEY = '/settings/plan-modules'
const tenantModulesKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/modules`

/** The modules of each plan (System > Plans). Any administrator reads them. */
export function usePlanModules() {
  return useSWR<PlanModulesResponse>(PLAN_MODULES_KEY, adminFetcher)
}

/** Saves the modules of each plan (super admin, fresh authenticator code). */
export function savePlanModules(input: UpdatePlanModulesRequest) {
  return adminFetch<PlanModulesResponse>(PLAN_MODULES_KEY, { method: 'PUT', body: input })
}

/** One organization's module entitlements: plan, grants and denies. */
export function useTenantModuleEntitlements(tenantId: string) {
  return useSWR<AdminTenantModulesResponse>(
    tenantId ? tenantModulesKey(tenantId) : null,
    adminFetcher
  )
}

/** Grants a module beyond the plan, or denies one (ops admin and up; reason required). */
export function putModuleGrant(tenantId: string, moduleId: string, input: SetModuleGrantRequest) {
  return adminFetch<AdminTenantModulesResponse>(
    `${tenantModulesKey(tenantId)}/${encodeURIComponent(moduleId)}/grant`,
    { method: 'PUT', body: input }
  )
}

/**
 * Removes an organization's grant or deny: the plan decides again. Needs a
 * reason (admin audit log) and a fresh authenticator code.
 */
export function deleteModuleGrant(
  tenantId: string,
  moduleId: string,
  proof: DeleteModuleGrantRequest
) {
  return adminFetch<AdminTenantModulesResponse>(
    `${tenantModulesKey(tenantId)}/${encodeURIComponent(moduleId)}/grant`,
    { method: 'DELETE', body: proof }
  )
}
