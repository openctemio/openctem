'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

/**
 * The platform policy for scan approval (RFC-072 §5): let the organization
 * choose, or force off, on (at least) or strict.
 */
export type ScanApprovalPolicy = 'tenant_controlled' | 'off' | 'on' | 'strict'

/** An organization's scan approval in force. */
export type ScanApprovalMode = 'off' | 'on' | 'strict'

export interface ScanPolicyDefault {
  policy: ScanApprovalPolicy
  version: number
}

export interface ScanPolicyOrganization {
  /** The organization's own policy; null follows the platform default. */
  override: ScanApprovalPolicy | null
  policy: ScanApprovalPolicy
  source: 'platform_default' | 'organization_override'
  platform_default: ScanApprovalPolicy
  /** The organization's scan approval in force (its owner's choice under the policy). */
  effective_mode: ScanApprovalMode
}

const DEFAULT_KEY = '/settings/scan-approval-policy'
const orgKey = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/scan-approval-policy`

/** The platform default (any administrator reads it). */
export function useScanPolicyDefault() {
  return useSWR<ScanPolicyDefault>(DEFAULT_KEY, adminFetcher)
}

/** One organization's policy (any administrator reads it). */
export function useScanPolicyOrganization(tenantId: string | undefined) {
  return useSWR<ScanPolicyOrganization>(tenantId ? orgKey(tenantId) : null, adminFetcher)
}

/** Super admin, a fresh authenticator code and a reason. */
export function saveScanPolicyDefault(input: {
  policy: ScanApprovalPolicy
  version: number
  reason: string
  totp_code: string
}) {
  return adminFetch<ScanPolicyDefault>(DEFAULT_KEY, { method: 'PUT', body: input })
}

/** Super admin; policy null follows the platform default. */
export function saveScanPolicyOrganization(
  tenantId: string,
  input: { policy: ScanApprovalPolicy | null; reason: string; totp_code: string }
) {
  return adminFetch<ScanPolicyOrganization>(orgKey(tenantId), { method: 'PUT', body: input })
}
