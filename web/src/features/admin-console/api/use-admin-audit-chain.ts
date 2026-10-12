'use client'

import useSWR from 'swr'
import type {
  AdminAuditChainRebaselineRequest,
  AdminAuditChainRebaselineResponse,
  AdminAuditChainStatusResponse,
} from '@/lib/api/generated'
import { adminFetch, adminFetcher } from './admin-client'

/** Error codes the rebaseline endpoint refuses with. */
export const AUDIT_CHAIN_ERROR = {
  unexplained: 'AUDIT_CHAIN_UNEXPLAINED',
  changed: 'AUDIT_CHAIN_CHANGED',
  notRebaselinable: 'AUDIT_CHAIN_SOURCE_MISSING',
  stepUpRequired: 'STEP_UP_REQUIRED',
  stepUpUnavailable: 'STEP_UP_UNAVAILABLE',
} as const

/**
 * The classification of an organization's audit hash-chain. It walks the whole
 * chain on the server, so it is fetched once and re-checked on demand, not on
 * every focus.
 */
export function useAuditChainStatus(tenantId: string | null) {
  return useSWR<AdminAuditChainStatusResponse>(
    tenantId ? `/tenants/${tenantId}/audit-chain` : null,
    adminFetcher,
    { revalidateOnFocus: false, revalidateOnReconnect: false }
  )
}

/**
 * Re-signs the organization's audit chain (super admin). The server re-runs the
 * classification and refuses (409) unless every break is explained and the
 * chain is still the one behind `fingerprint`; `totp_code` is a fresh code from
 * the console authenticator.
 */
export function rebaselineAuditChain(tenantId: string, input: AdminAuditChainRebaselineRequest) {
  return adminFetch<AdminAuditChainRebaselineResponse>(
    `/tenants/${tenantId}/audit-chain/rebaseline`,
    { method: 'POST', body: input }
  )
}
