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
 * Shared sensors on this instance (RFC-100 §5): the instance switch (off by
 * default) and whether organizations without a decision may use them
 * (null until the administrator chooses; null refuses them; turning the
 * switch on needs the choice in the same change). `ready` is false while shared sensors cannot be used yet; the
 * API refuses to turn the switch on until then.
 */
export interface SharedSensorsSetting {
  enabled: boolean
  new_orgs: boolean | null
  ready: boolean
  version: number
}

const SHARED_KEY = '/settings/shared-sensors'

/** The setting (any administrator reads it). */
export function useSharedSensorsSetting() {
  return useSWR<SharedSensorsSetting>(SHARED_KEY, adminFetcher)
}

/** Super admin, a fresh authenticator code and a reason. */
export function saveSharedSensorsSetting(input: {
  enabled: boolean
  /** Required when enabled is true. */
  new_orgs: boolean | null
  version: number
  reason: string
  totp_code: string
}) {
  return adminFetch<SharedSensorsSetting>(SHARED_KEY, { method: 'PUT', body: input })
}
