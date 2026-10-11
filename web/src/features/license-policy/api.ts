'use client'

/**
 * The organization's license policy (api/docs/rfcs/RFC-070-software-components-inventory.md,
 * "License policy"). Reading needs settings:read, saving settings:write;
 * a save re-evaluates every package and its license findings.
 */

import useSWR from 'swr'
import { get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'

export const LICENSE_POLICY_ENDPOINT = '/api/v1/organization/settings/license-policy'

export type LicenseAction = 'allow' | 'review' | 'deny'

export const LICENSE_CATEGORIES = [
  'permissive',
  'weak_copyleft',
  'copyleft',
  'proprietary',
  'public_domain',
  'unknown',
] as const

export const DEPENDENCY_SCOPES = [
  'runtime',
  'development',
  'test',
  'optional',
  'build',
  'provided',
] as const

export const MAX_LICENSE_RULES = 200

export interface LicenseRule {
  match: string
  action: LicenseAction
  scopes?: string[]
}

export interface LicensePolicy {
  enabled: boolean
  default?: 'allow' | 'review'
  unknown?: 'review' | 'deny'
  review_findings?: boolean
  rules?: LicenseRule[]
}

export interface LicensePolicyEvaluation {
  links_updated: number
  violations: number
  findings_created: number
  findings_reopened: number
  findings_resolved: number
}

export interface LicensePolicyResponse {
  policy: LicensePolicy
  evaluation?: LicensePolicyEvaluation
  evaluation_error?: string
}

export function useLicensePolicy() {
  const { can } = usePermissions()
  return useSWR<LicensePolicyResponse>(
    can(Permission.SettingsRead) ? LICENSE_POLICY_ENDPOINT : null,
    (url: string) => get<LicensePolicyResponse>(url),
    { revalidateOnFocus: false }
  )
}

/** Saves the policy; etag (If-Match) refuses a save over someone else's change. */
export function updateLicensePolicy(
  policy: LicensePolicy,
  etag?: string
): Promise<LicensePolicyResponse> {
  return put<LicensePolicyResponse>(LICENSE_POLICY_ENDPOINT, policy, {
    headers: etag ? { 'If-Match': etag } : undefined,
  })
}

const LICENSE_ID = /^[A-Za-z0-9.+:-]{1,128}$/

/** Client-side check of a rule's match, mirroring the API (i18n key or null). */
export function validateRuleMatch(match: string): string | null {
  const m = match.trim()
  if (!m) return 'licensePolicy.error.empty'
  if (m.toLowerCase().startsWith('category:')) {
    return (LICENSE_CATEGORIES as readonly string[]).includes(m.slice(9).toLowerCase())
      ? null
      : 'licensePolicy.error.category'
  }
  const parts = m.split(/\s+/)
  if (parts.length === 1 && LICENSE_ID.test(parts[0])) return null
  if (
    parts.length === 3 &&
    parts[1].toUpperCase() === 'WITH' &&
    LICENSE_ID.test(parts[0]) &&
    LICENSE_ID.test(parts[2])
  ) {
    return null
  }
  return 'licensePolicy.error.match'
}
