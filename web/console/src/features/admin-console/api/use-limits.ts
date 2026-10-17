'use client'

import useSWR from 'swr'
import type {
  AdminLimitsResponse,
  AdminTenantModulesResponse,
  DeleteFeatureDenyRequest,
  SelfServiceLimitsResponse,
  SetFeatureDenyRequest,
  SetLimitRequest,
  UpdateSelfServiceLimitsRequest,
} from '@/lib/api/generated'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

const SELF_SERVICE_KEY = '/settings/limits'
const tenantLimitsKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/limits`
const tenantModulesKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/modules`

/**
 * The limits a self-service organization starts with, and the configured
 * sources (System > Limits). Any administrator reads them.
 */
export function useSelfServiceLimits() {
  return useSWR<SelfServiceLimitsResponse>(SELF_SERVICE_KEY, adminFetcher)
}

/**
 * Saves the self-service defaults (super admin). `version` is the version
 * that was read (409 when someone else saved since); `totp_code` is a fresh
 * code from the console authenticator.
 */
export function saveSelfServiceLimits(input: UpdateSelfServiceLimitsRequest) {
  return adminFetch<SelfServiceLimitsResponse>(SELF_SERVICE_KEY, { method: 'PUT', body: input })
}

/** One organization's limits with origin and reason, usage and denies. */
export function useTenantLimits(tenantId: string) {
  return useSWR<AdminLimitsResponse>(tenantId ? tenantLimitsKey(tenantId) : null, adminFetcher)
}

/** Sets one limit for this organization (ops admin and up; reason required). */
export function putTenantLimit(tenantId: string, key: string, input: SetLimitRequest) {
  return adminFetch<AdminLimitsResponse>(
    `${tenantLimitsKey(tenantId)}/${encodeURIComponent(key)}`,
    {
      method: 'PUT',
      body: input,
    }
  )
}

/** Removes one limit an administrator set for this organization. */
export function deleteTenantLimit(tenantId: string, key: string) {
  return adminFetch<AdminLimitsResponse>(
    `${tenantLimitsKey(tenantId)}/${encodeURIComponent(key)}`,
    {
      method: 'DELETE',
    }
  )
}

/** One organization's modules: available, denied, or read-only after a deny. */
export function useTenantModuleEntitlements(tenantId: string) {
  return useSWR<AdminTenantModulesResponse>(
    tenantId ? tenantModulesKey(tenantId) : null,
    adminFetcher
  )
}

/** Denies a module to the organization (ops admin and up; reason and code required). */
export function putModuleDeny(tenantId: string, moduleId: string, input: SetFeatureDenyRequest) {
  return adminFetch<AdminTenantModulesResponse>(
    `${tenantModulesKey(tenantId)}/${encodeURIComponent(moduleId)}/deny`,
    { method: 'PUT', body: input }
  )
}

/** Allows a denied module again (reason and a fresh authenticator code). */
export function deleteModuleDeny(
  tenantId: string,
  moduleId: string,
  proof: DeleteFeatureDenyRequest
) {
  return adminFetch<AdminTenantModulesResponse>(
    `${tenantModulesKey(tenantId)}/${encodeURIComponent(moduleId)}/deny`,
    { method: 'DELETE', body: proof }
  )
}
