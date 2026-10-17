/**
 * Settings > Domains and the join-request inbox (api RFC-104). Reading the
 * domains needs an owner or admin; changing one needs an owner with a recent
 * re-authentication (the shared client handles STEP_UP_REQUIRED). Join
 * requests: owners and admins list and decide.
 */

import useSWR from 'swr'

import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { tenantEndpoints } from '@/lib/api/endpoints'

export type JoinPolicy = 'off' | 'approval' | 'auto'
export type JoinRole = 'viewer' | 'member'

export interface DomainSignupPolicy {
  id: string
  domain: string
  status: string
  purpose: string
  /** The claim is verified, for SSO and unambiguous: the policy applies now. */
  effective: boolean
  join_policy: JoinPolicy
  join_role: JoinRole
  discoverable: boolean
  sso_required: boolean
  block_new_workspaces: boolean
  include_subdomains: boolean
}

export type DomainSignupPolicyInput = Omit<
  DomainSignupPolicy,
  'id' | 'domain' | 'status' | 'purpose' | 'effective'
>

export function useDomainSignupPolicies(enabled: boolean) {
  const { data, error, isLoading, mutate } = useSWR<DomainSignupPolicy[]>(
    enabled ? tenantEndpoints.domainSignupPolicies() : null,
    fetcher,
    { revalidateOnFocus: false }
  )
  return { domains: data ?? [], error, isLoading: enabled && isLoading, mutate }
}

export function saveDomainSignupPolicy(id: string, input: DomainSignupPolicyInput) {
  return fetcherWithOptions<DomainSignupPolicy>(tenantEndpoints.domainSignupPolicy(id), {
    method: 'PUT',
    body: JSON.stringify(input),
  })
}

export interface JoinRequest {
  id: string
  email: string
  name?: string
  email_verified: boolean
  requested_role: JoinRole
  requested_at: string
  expires_at: string
}

export function useJoinRequests(enabled: boolean) {
  const { data, error, isLoading, mutate } = useSWR<JoinRequest[]>(
    enabled ? tenantEndpoints.joinRequests() : null,
    fetcher,
    { revalidateOnFocus: false }
  )
  return { requests: data ?? [], error, isLoading: enabled && isLoading, mutate }
}

export function approveJoinRequest(id: string, role: JoinRole) {
  return fetcherWithOptions<unknown>(tenantEndpoints.approveJoinRequest(id), {
    method: 'POST',
    body: JSON.stringify({ role }),
  })
}

export function rejectJoinRequest(id: string) {
  return fetcherWithOptions<unknown>(tenantEndpoints.rejectJoinRequest(id), { method: 'POST' })
}
