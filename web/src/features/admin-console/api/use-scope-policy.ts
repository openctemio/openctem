'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

/** How scope-widening approvals work (RFC-054 §12.6). */
export type ScopeApprovalMode = 'required' | 'tenant_controlled' | 'disabled'

export interface ScopePolicyDefault {
  mode: ScopeApprovalMode
  version: number
}

export interface ScopePolicyOrganization {
  /** The organization's own mode; null follows the platform default. */
  override: ScopeApprovalMode | null
  effective: ScopeApprovalMode
  source: 'platform_default' | 'organization_override'
  platform_default: ScopeApprovalMode
}

const DEFAULT_KEY = '/settings/scope-policy'
const orgKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/scope-policy`

/** The platform default (any administrator reads it). */
export function useScopePolicyDefault() {
  return useSWR<ScopePolicyDefault>(DEFAULT_KEY, adminFetcher)
}

/** One organization's policy (any administrator reads it). */
export function useScopePolicyOrganization(tenantId: string | undefined) {
  return useSWR<ScopePolicyOrganization>(tenantId ? orgKey(tenantId) : null, adminFetcher)
}

/** Super admin, a fresh authenticator code and a reason. */
export function saveScopePolicyDefault(input: {
  mode: ScopeApprovalMode
  version: number
  reason: string
  totp_code: string
}) {
  return adminFetch<ScopePolicyDefault>(DEFAULT_KEY, { method: 'PUT', body: input })
}

/** Super admin; mode null follows the platform default. */
export function saveScopePolicyOrganization(
  tenantId: string,
  input: { mode: ScopeApprovalMode | null; reason: string; totp_code: string }
) {
  return adminFetch<ScopePolicyOrganization>(orgKey(tenantId), { method: 'PUT', body: input })
}
