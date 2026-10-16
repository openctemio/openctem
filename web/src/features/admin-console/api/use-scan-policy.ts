'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'

/**
 * The platform policy for scan approval (RFC-073 §5): let the organization
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

/**
 * "Require a verified domain before platform sensors scan a target"
 * (RFC-054 §8.1). Default off; a public multi-tenant cloud turns it on.
 */
export interface PlatformSensorProof {
  required: boolean
  version: number
}

const PROOF_KEY = '/settings/platform-sensor-proof'

/** The setting (any administrator reads it). */
export function usePlatformSensorProof() {
  return useSWR<PlatformSensorProof>(PROOF_KEY, adminFetcher)
}

/** Super admin, a fresh authenticator code and a reason. */
export function savePlatformSensorProof(input: {
  required: boolean
  version: number
  reason: string
  totp_code: string
}) {
  return adminFetch<PlatformSensorProof>(PROOF_KEY, { method: 'PUT', body: input })
}

/**
 * A single-use shared sensor enrollment token (RFC-100 §7). The token is
 * returned once and never shown again.
 */
export interface SharedSensorEnrollmentToken {
  id: string
  token: string
  name: string
  expires_at: string
}

/** Super admin, a fresh authenticator code and a reason. */
export function createSharedSensorEnrollmentToken(input: {
  name: string
  ttl_minutes: number
  reason: string
  totp_code: string
}) {
  return adminFetch<SharedSensorEnrollmentToken>('/shared-sensors/enrollment-tokens', {
    method: 'POST',
    body: input,
  })
}
