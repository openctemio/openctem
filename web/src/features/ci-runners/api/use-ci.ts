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
  CITrustPreview,
  CITrustPreviewRequest,
  CIVerdictFilter,
  CIPipelineDetail,
  CIPipelineList,
  CICoverage,
  CISettings,
  SCMAppInstallation,
  SCMAppList,
  SCMCompleteGitHubRequest,
  SCMGitLabConnection,
  SCMGitLabConnectRequest,
  CITokenRefusal,
  CIRepositorySettings,
  CIGateBaseline,
} from '../types'
import { pipelinesURL, type PipelineListFilters } from '../lib/pipeline'

import { ApiClientError } from '@/lib/api/error-handler'
import { coverageExpectationURL, coverageURL, type CoverageFilters } from '../lib/coverage'

export const CI_BASE = '/api/v1/ci'
const TRUST = `${CI_BASE}/trust-configs`
const POLICIES = `${CI_BASE}/gate-policies`
const OVERRIDES = `${CI_BASE}/gate-overrides`
const SETTINGS = `${CI_BASE}/settings`

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

export function useCIRuns(
  filters: CIRunFilters,
  { enabled = true, refreshInterval = 0 }: { enabled?: boolean; refreshInterval?: number } = {}
) {
  const { currentTenant } = useTenant()
  return useSWR<CIRunList>(
    currentTenant && enabled ? ciRunsURL(filters) : null,
    (url: string) => get<CIRunList>(url),
    { refreshInterval }
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

export function useCIRun(id: string | null) {
  const { currentTenant } = useTenant()
  return useSWR<CIRun>(
    currentTenant && id ? `${CI_BASE}/runs/${encodeURIComponent(id)}` : null,
    (url: string) => get<CIRun>(url)
  )
}

export function useCISettings({ enabled = true }: { enabled?: boolean } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<CISettings>(currentTenant && enabled ? SETTINGS : null, (url: string) =>
    get<CISettings>(url)
  )
}

export function useSaveCISettings() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? SETTINGS : null,
    async (_url: string, { arg }: { arg: CISettings }) => put<CISettings>(SETTINGS, arg)
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

/** Checks a sample token against a draft trust configuration; nothing is stored. */
export function usePreviewTrustConfig() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? `${TRUST}/preview` : null,
    async (url: string, { arg }: { arg: CITrustPreviewRequest }) => post<CITrustPreview>(url, arg)
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

/** URL of a repository's effective gate settings; exported for tests. */
export function gateSettingsURL(repositoryAssetId: string): string {
  return `${CI_BASE}/gate-settings/${encodeURIComponent(repositoryAssetId)}`
}

/** URL of a repository's gate baseline; exported for tests. */
export function gateBaselineURL(repositoryAssetId: string): string {
  return `${CI_BASE}/gate-baselines/${encodeURIComponent(repositoryAssetId)}`
}

/**
 * A repository's effective gate settings: every field with its value, the
 * layer it comes from and any lock above (scans:ci:read, data-scoped).
 */
export function useRepositoryGateSettings(repositoryAssetId: string | null | undefined) {
  const { currentTenant } = useTenant()
  return useSWR<CIRepositorySettings>(
    currentTenant && repositoryAssetId ? gateSettingsURL(repositoryAssetId) : null,
    (url: string) => get<CIRepositorySettings>(url)
  )
}

/** A repository's gate baseline; null when none is recorded (the API answers 404). */
export function useGateBaseline(repositoryAssetId: string | null | undefined) {
  const { currentTenant } = useTenant()
  return useSWR<CIGateBaseline | null>(
    currentTenant && repositoryAssetId ? gateBaselineURL(repositoryAssetId) : null,
    async (url: string) => {
      try {
        return await get<CIGateBaseline>(url)
      } catch (e) {
        if (e instanceof ApiClientError && e.statusCode === 404) return null
        throw e
      }
    }
  )
}

/** Record the baseline now (scans:ci:policy; the API client asks for step-up). */
export function useRecordGateBaseline(repositoryAssetId: string | null | undefined) {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant && repositoryAssetId ? gateBaselineURL(repositoryAssetId) : null,
    async (url: string) => put<CIGateBaseline>(url, {})
  )
}

/** Remove the baseline: every finding counts as new again. */
export function useDeleteGateBaseline(repositoryAssetId: string | null | undefined) {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant && repositoryAssetId ? gateBaselineURL(repositoryAssetId) : null,
    async (url: string) => del<void>(url)
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

// ─────────────────────────── code-host apps (RFC-077) ───

const SCM_APPS = `${CI_BASE}/scm-apps`

/** The organization's GitHub App installations and GitLab connections. */
export function useSCMApps() {
  const { currentTenant } = useTenant()
  return useSWR<SCMAppList>(currentTenant ? SCM_APPS : null, (url: string) => get<SCMAppList>(url))
}

/** Starts the GitHub App install: the link carries a state bound to the caller. */
export function useGitHubInstallURL() {
  const { currentTenant } = useTenant()
  return useSWRMutation(currentTenant ? SCM_APPS : null, async () =>
    post<{ url?: string }>(`${SCM_APPS}/github/install-url`, {})
  )
}

/** Binds the installation GitHub's setup redirect names. */
export function useCompleteGitHubInstall() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? SCM_APPS : null,
    async (_url: string, { arg }: { arg: SCMCompleteGitHubRequest }) =>
      post<SCMAppInstallation>(`${SCM_APPS}/github/installations`, arg)
  )
}

export function useRemoveSCMInstallation() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? SCM_APPS : null,
    async (_url: string, { arg }: { arg: string }) =>
      del<void>(`${SCM_APPS}/installations/${encodeURIComponent(arg)}`)
  )
}

export function useConnectGitLab() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? SCM_APPS : null,
    async (_url: string, { arg }: { arg: SCMGitLabConnectRequest }) =>
      post<SCMGitLabConnection>(`${SCM_APPS}/gitlab-connections`, arg)
  )
}

export function useRemoveGitLab() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? SCM_APPS : null,
    async (_url: string, { arg }: { arg: string }) =>
      del<void>(`${SCM_APPS}/gitlab-connections/${encodeURIComponent(arg)}`)
  )
}

/** The URL of the refused-pipeline listing; exported for tests. */
export const CI_REFUSALS_URL = `${CI_BASE}/trust-refusals?limit=20`

/**
 * The latest refused CI token exchanges with their rule codes (scans:ci:write).
 * `refreshInterval` polls while a pipeline is being set up.
 */
export function useTrustRefusals({
  enabled = true,
  refreshInterval = 0,
}: { enabled?: boolean; refreshInterval?: number } = {}) {
  const { currentTenant } = useTenant()
  return useSWR<{ data?: CITokenRefusal[] }>(
    currentTenant && enabled ? CI_REFUSALS_URL : null,
    (url: string) => get<{ data?: CITokenRefusal[] }>(url),
    { refreshInterval }
  )
}
