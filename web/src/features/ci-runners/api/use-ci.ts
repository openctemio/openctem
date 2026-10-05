/**
 * CI hooks: runs, trust configurations, gate policies and break-glass
 * overrides (api RFC-051). Tenant from the session; the API applies the
 * caller's data scope to runs and overrides.
 */

'use client'

import useSWR from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, patch, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  CIGateOverride,
  CIGateOverrideRequest,
  CIGatePolicy,
  CIGatePolicyList,
  CIGatePolicyRequest,
  CIRun,
  CIRunList,
  CITrustConfig,
  CITrustConfigRequest,
  CIVerdictFilter,
} from '../types'

export const CI_BASE = '/api/v1/ci'
const TRUST = `${CI_BASE}/trust-configs`
const POLICIES = `${CI_BASE}/gate-policies`
const OVERRIDES = `${CI_BASE}/gate-overrides`

export interface CIRunFilters {
  verdict?: CIVerdictFilter
  provider?: string
  repositoryAssetId?: string
  page?: number
  perPage?: number
}

/** The URL of a run listing; exported for tests. */
export function ciRunsURL(f: CIRunFilters = {}): string {
  const q = new URLSearchParams()
  if (f.verdict) q.set('verdict', f.verdict)
  if (f.provider) q.set('provider', f.provider)
  if (f.repositoryAssetId) q.set('repository_asset_id', f.repositoryAssetId)
  q.set('page', String(f.page ?? 1))
  q.set('per_page', String(f.perPage ?? 25))
  return `${CI_BASE}/runs?${q.toString()}`
}

export function useCIRuns(filters: CIRunFilters, { enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<CIRunList>(currentTenant && enabled ? ciRunsURL(filters) : null, (url: string) =>
    get<CIRunList>(url)
  )
}

export function useCIRun(id: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<CIRun>(
    currentTenant && id ? `${CI_BASE}/runs/${encodeURIComponent(id)}` : null,
    (url: string) => get<CIRun>(url)
  )
}

export function useTrustConfigs({ enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<{ data?: CITrustConfig[] }>(
    currentTenant && enabled ? TRUST : null,
    (url: string) => get<{ data?: CITrustConfig[] }>(url)
  )
}

export function useSaveTrustConfig() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? TRUST : null,
    async (_url: string, { arg }: { arg: { id?: string; body: CITrustConfigRequest } }) =>
      arg.id
        ? put<CITrustConfig>(`${TRUST}/${encodeURIComponent(arg.id)}`, arg.body)
        : post<CITrustConfig>(TRUST, arg.body)
  )
}

export function useDeleteTrustConfig() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? TRUST : null,
    async (_url: string, { arg }: { arg: string }) =>
      del<void>(`${TRUST}/${encodeURIComponent(arg)}`)
  )
}

export function useGatePolicies({ enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<CIGatePolicyList>(currentTenant && enabled ? POLICIES : null, (url: string) =>
    get<CIGatePolicyList>(url)
  )
}

export function useSaveGatePolicy() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? POLICIES : null,
    async (_url: string, { arg }: { arg: { id?: string; body: CIGatePolicyRequest } }) =>
      arg.id
        ? patch<CIGatePolicy>(`${POLICIES}/${encodeURIComponent(arg.id)}`, arg.body)
        : post<CIGatePolicy>(POLICIES, arg.body)
  )
}

export function useDeleteGatePolicy() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? POLICIES : null,
    async (_url: string, { arg }: { arg: string }) =>
      del<void>(`${POLICIES}/${encodeURIComponent(arg)}`)
  )
}

export function useGateOverrides({ enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<{ data?: CIGateOverride[] }>(
    currentTenant && enabled ? OVERRIDES : null,
    (url: string) => get<{ data?: CIGateOverride[] }>(url)
  )
}

export function useCreateGateOverride() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? OVERRIDES : null,
    async (_url: string, { arg }: { arg: CIGateOverrideRequest }) =>
      post<CIGateOverride>(OVERRIDES, arg)
  )
}

export function useRevokeGateOverride() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? OVERRIDES : null,
    async (_url: string, { arg }: { arg: string }) =>
      post<void>(`${OVERRIDES}/${encodeURIComponent(arg)}/revoke`, {})
  )
}
