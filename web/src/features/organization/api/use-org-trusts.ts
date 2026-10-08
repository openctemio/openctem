/**
 * Trusted organizations (api RFC-058): two-sided trusts between a host
 * organization and the home organization that manages its partners' email
 * domain. Reading needs an owner or admin; every change needs an owner with
 * a recent re-authentication (the shared client handles STEP_UP_REQUIRED).
 */

import useSWR from 'swr'

import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'

export type OrgTrustDirection = 'outgoing' | 'incoming'
export type OrgTrustStatus = 'requested' | 'active'
export type OrgTrustMaxRole = 'viewer' | 'member'

export interface OrgTrust {
  id: string
  /** outgoing: we trust them (we host); incoming: they trust us (our people work there). */
  direction: OrgTrustDirection
  organization: string
  status: OrgTrustStatus
  max_role: OrgTrustMaxRole
  accept_home_sso: boolean
  require_mfa_evidence: boolean
  home_attests_mfa: boolean
  allow_api_keys: boolean
  default_expiry_days?: number
  created_at: string
  accepted_at?: string
}

export interface OrgTrustSettingsInput {
  max_role: OrgTrustMaxRole
  accept_home_sso: boolean
  require_mfa_evidence: boolean
  allow_api_keys: boolean
  default_expiry_days?: number
}

export interface CreateOrgTrustInput extends OrgTrustSettingsInput {
  /** An email domain the other organization verified for SSO. */
  home_domain: string
}

export function useOrgTrusts(enabled: boolean) {
  const { data, error, isLoading, mutate } = useSWR<{ data: OrgTrust[] }>(
    enabled ? tenantEndpoints.orgTrusts() : null,
    fetcher,
    { revalidateOnFocus: false }
  )
  return { trusts: data?.data ?? [], error, isLoading: enabled && isLoading, mutate }
}

export function createOrgTrust(input: CreateOrgTrustInput) {
  return fetcherWithOptions<OrgTrust>(tenantEndpoints.orgTrusts(), {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function updateOrgTrust(trustId: string, input: OrgTrustSettingsInput) {
  return fetcherWithOptions<OrgTrust>(tenantEndpoints.orgTrust(trustId), {
    method: 'PATCH',
    body: JSON.stringify(input),
  })
}

export function approveOrgTrust(trustId: string, attestIdpMfa: boolean) {
  return fetcherWithOptions<OrgTrust>(tenantEndpoints.approveOrgTrust(trustId), {
    method: 'POST',
    body: JSON.stringify({ attest_idp_mfa: attestIdpMfa }),
  })
}

export function deleteOrgTrust(trustId: string) {
  return fetcherWithOptions<unknown>(tenantEndpoints.orgTrust(trustId), { method: 'DELETE' })
}
