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
  CIPipelineDetail,
  CIPipelineList,
  FleetList,
  CICoverage,
} from '../types'
import {
  fleetURL,
  pipelinesURL,
  type FleetListFilters,
  type PipelineListFilters,
} from '../lib/pipeline'

import { coverageExpectationURL, coverageURL, type CoverageFilters } from '../lib/coverage'

export const CI_BASE = '/api/v1/ci'
const TRUST = `${CI_BASE}/trust-configs`
const POLICIES = `${CI_BASE}/gate-policies`
const OVERRIDES = `${CI_BASE}/gate-overrides`

export interface CIRunFilters {
  verdict?: CIVerdictFilter
  provider?: string
  repositoryAssetId?: string
  pipelineId?: string
  page?: number
  perPage?: number
}

/** The URL of a run listing; exported for tests. */
export function ciRunsURL(f: CIRunFilters = {}): string {
  const q = new URLSearchParams()
  if (f.verdict) q.set('verdict', f.verdict)
  if (f.provider) q.set('provider', f.provider)
  if (f.repositoryAssetId) q.set('repository_asset_id', f.repositoryAssetId)
  if (f.pipelineId) q.set('pipeline_id', f.pipelineId)
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

/** CI pipelines (sensors in runner mode), most urgent first. */
export function useCIPipelines(
  filters: PipelineListFilters,
  { enabled = true }: { enabled?: boolean } = {}
) {
  const { currentTenant } = useTenant()
  return useSWR<CIPipelineList>(
    currentTenant && enabled ? pipelinesURL(CI_BASE, filters) : null,
    (url: string) => get<CIPipelineList>(url),
    { keepPreviousData: true, refreshInterval: 30_000 }
  )
}

/** One pipeline with its branches and default-branch gate trend. */
export function useCIPipeline(id: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<CIPipelineDetail>(
    currentTenant && id ? `${CI_BASE}/pipelines/${encodeURIComponent(id)}` : null,
    (url: string) => get<CIPipelineDetail>(url)
  )
}

/**
 * The fleet read model: sensors (daemon mode) and CI pipelines (runner mode)
 * in one list. The API filters each mode by its own permission and returns
 * the modes the caller may see with their counts.
 */
export function useFleet(
  filters: FleetListFilters,
  { enabled = true }: { enabled?: boolean } = {}
) {
  const { currentTenant } = useTenant()
  return useSWR<FleetList>(
    currentTenant && enabled ? fleetURL(filters) : null,
    (url: string) => get<FleetList>(url),
    { keepPreviousData: true, refreshInterval: 30_000 }
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

/** Repository x capability coverage within the caller's data scope. */
export function useCICoverage(
  filters: CoverageFilters,
  { enabled = true }: { enabled?: boolean } = {}
) {
  const { currentTenant } = useTenant()
  return useSWR<CICoverage>(
    currentTenant && enabled ? coverageURL(CI_BASE, filters) : null,
    (url: string) => get<CICoverage>(url),
    { keepPreviousData: true }
  )
}

/** Mark a repository as expected to be covered (capabilities empty = all), or stop. */
export function useSetCoverageExpectation() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? `${CI_BASE}/coverage/expectations` : null,
    async (
      _url: string,
      { arg }: { arg: { assetId: string; expected: boolean; capabilities?: string[] } }
    ) => {
      const url = coverageExpectationURL(CI_BASE, arg.assetId)
      return arg.expected
        ? put<unknown>(url, { capabilities: arg.capabilities ?? [] })
        : del<void>(url)
    }
  )
}

/** Retire a pipeline: the findings only it reported close as source retired. */
export function useRetirePipeline() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? `${CI_BASE}/pipelines/retire` : null,
    async (_url: string, { arg }: { arg: { id: string; reason: string } }) =>
      post<{ pipeline_id?: string; findings_closed?: number }>(
        `${CI_BASE}/pipelines/${encodeURIComponent(arg.id)}/retire`,
        { reason: arg.reason }
      )
  )
}
