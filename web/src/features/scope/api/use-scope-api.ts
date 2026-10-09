/**
 * Scope Configuration API Hooks
 *
 * SWR hooks for fetching and mutating scope configuration data from backend
 * Following CTEM (Continuous Threat Exposure Management) Scoping phase
 *
 * Tenant is determined from JWT token (token-based tenant)
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import type {
  ScopeT2MaxDuration,
  ApiScopeTarget,
  ApiScopeTargetListResponse,
  ApiScopeExclusion,
  ApiScopeExclusionListResponse,
  ApiScopeStats,
  ApiCheckScopeResponse,
  CheckScopeInput,
  ScopeTargetFilters,
  ScopeExclusionFilters,
  CreateScopeTargetInput,
  UpdateScopeTargetInput,
  CreateScopeExclusionInput,
  UpdateScopeExclusionInput,
  BulkDeleteTargetsInput,
  BulkDeleteExclusionsInput,
  BulkUpdateTargetsInput,
  BulkOperationResponse,
  ApiScopeSettings,
  UpdateScopeSettingsInput,
  PathExclusionFields,
  SetExclusionTestingInput,
} from './scope-api.types'

// ============================================
// SWR CONFIGURATION
// ============================================

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // Don't retry on client errors (4xx) - only retry on server/network errors
  shouldRetryOnError: (error) => {
    // Don't retry on 4xx errors (client errors like 403, 404, etc.)
    if (error?.statusCode >= 400 && error?.statusCode < 500) {
      return false
    }
    // Retry on 5xx or network errors
    return true
  },
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  dedupingInterval: 2000,
  onError: (error) => {
    handleApiError(error, {
      showToast: true,
      logError: true,
    })
  },
}

// ============================================
// ENDPOINT BUILDERS
// ============================================

const BASE_URL = '/api/v1/scope'

function buildTargetsEndpoint(filters?: ScopeTargetFilters): string {
  const url = `${BASE_URL}/targets`
  if (!filters) return url

  const params = new URLSearchParams()

  // The API reads comma-separated `types` and `statuses`.
  if (filters.target_type) params.set('types', filters.target_type)
  if (filters.status) params.set('statuses', filters.status)
  if (filters.search) params.set('search', filters.search)
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))
  if (filters.sort_by) params.set('sort_by', filters.sort_by)
  if (filters.sort_order) params.set('sort_order', filters.sort_order)

  const queryString = params.toString()
  return queryString ? `${url}?${queryString}` : url
}

function buildExclusionsEndpoint(filters?: ScopeExclusionFilters): string {
  const url = `${BASE_URL}/exclusions`
  if (!filters) return url

  const params = new URLSearchParams()

  if (filters.exclusion_type) params.set('types', filters.exclusion_type)
  if (filters.status) params.set('statuses', filters.status)
  if (filters.search) params.set('search', filters.search)
  if (filters.page) params.set('page', String(filters.page))
  if (filters.per_page) params.set('per_page', String(filters.per_page))
  if (filters.sort_by) params.set('sort_by', filters.sort_by)
  if (filters.sort_order) params.set('sort_order', filters.sort_order)

  const queryString = params.toString()
  return queryString ? `${url}?${queryString}` : url
}

// ============================================
// FETCHER FUNCTIONS
// ============================================

async function fetchTargets(url: string): Promise<ApiScopeTargetListResponse> {
  return get<ApiScopeTargetListResponse>(url)
}

async function fetchTarget(url: string): Promise<ApiScopeTarget> {
  return get<ApiScopeTarget>(url)
}

async function fetchExclusions(url: string): Promise<ApiScopeExclusionListResponse> {
  return get<ApiScopeExclusionListResponse>(url)
}

async function fetchExclusion(url: string): Promise<ApiScopeExclusion> {
  return get<ApiScopeExclusion>(url)
}

async function fetchStats(url: string): Promise<ApiScopeStats> {
  return get<ApiScopeStats>(url)
}

// ============================================
// TARGETS HOOKS
// ============================================

/**
 * Fetch scope targets list for current tenant
 *
 * @example
 * ```typescript
 * function TargetsList() {
 *   const { data, error, isLoading } = useScopeTargetsApi({
 *     status: 'active',
 *     type: 'domain'
 *   })
 *
 *   if (isLoading) return <Loading />
 *   if (error) return <Error error={error} />
 *
 *   return (
 *     <ul>
 *       {data?.data.map(target => (
 *         <li key={target.id}>{target.pattern}</li>
 *       ))}
 *     </ul>
 *   )
 * }
 * ```
 */
export function useScopeTargetsApi(filters?: ScopeTargetFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? buildTargetsEndpoint(filters) : null

  return useSWR<ApiScopeTargetListResponse>(key, fetchTargets, { ...defaultConfig, ...config })
}

/**
 * Fetch a single scope target by ID
 */
export function useScopeTargetApi(targetId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && targetId ? `${BASE_URL}/targets/${targetId}` : null

  return useSWR<ApiScopeTarget>(key, fetchTarget, { ...defaultConfig, ...config })
}

/**
 * Create a new scope target
 */
export function useCreateScopeTargetApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/targets` : null,
    async (url: string, { arg }: { arg: CreateScopeTargetInput }) => {
      return post<ApiScopeTarget>(url, arg)
    }
  )
}

/**
 * Update a scope target
 */
export function useUpdateScopeTargetApi(targetId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && targetId ? `${BASE_URL}/targets/${targetId}` : null,
    async (url: string, { arg }: { arg: UpdateScopeTargetInput }) => {
      return put<ApiScopeTarget>(url, arg)
    }
  )
}

/**
 * Delete a scope target
 */
export function useDeleteScopeTargetApi(targetId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && targetId ? `${BASE_URL}/targets/${targetId}` : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

/**
 * Activate a scope target
 */
export function useActivateTargetApi(targetId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && targetId ? `${BASE_URL}/targets/${targetId}/activate` : null,
    async (url: string) => {
      return post<ApiScopeTarget>(url, {})
    }
  )
}

/**
 * Deactivate a scope target
 */
export function useDeactivateTargetApi(targetId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && targetId ? `${BASE_URL}/targets/${targetId}/deactivate` : null,
    async (url: string) => {
      return post<ApiScopeTarget>(url, {})
    }
  )
}

/**
 * Bulk delete scope targets
 */
export function useBulkDeleteTargetsApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/targets/bulk/delete` : null,
    async (url: string, { arg }: { arg: BulkDeleteTargetsInput }) => {
      return post<BulkOperationResponse>(url, arg)
    }
  )
}

/**
 * Bulk update scope targets
 */
export function useBulkUpdateTargetsApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/targets/bulk` : null,
    async (url: string, { arg }: { arg: BulkUpdateTargetsInput }) => {
      return post<BulkOperationResponse>(url, arg)
    }
  )
}

// ============================================
// EXCLUSIONS HOOKS
// ============================================

/**
 * Fetch scope exclusions list for current tenant
 */
export function useScopeExclusionsApi(filters?: ScopeExclusionFilters, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? buildExclusionsEndpoint(filters) : null

  return useSWR<ApiScopeExclusionListResponse>(key, fetchExclusions, {
    ...defaultConfig,
    ...config,
  })
}

/**
 * Fetch a single scope exclusion by ID
 */
export function useScopeExclusionApi(exclusionId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}` : null

  return useSWR<ApiScopeExclusion>(key, fetchExclusion, { ...defaultConfig, ...config })
}

/**
 * Create a new scope exclusion
 */
export function useCreateScopeExclusionApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/exclusions` : null,
    async (url: string, { arg }: { arg: CreateScopeExclusionInput }) => {
      return post<ApiScopeExclusion>(url, arg)
    }
  )
}

/**
 * Update a scope exclusion
 */
export function useUpdateScopeExclusionApi(exclusionId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}` : null,
    async (url: string, { arg }: { arg: UpdateScopeExclusionInput }) => {
      return put<ApiScopeExclusion>(url, arg)
    }
  )
}

/**
 * Delete a scope exclusion
 */
export function useDeleteScopeExclusionApi(exclusionId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}` : null,
    async (url: string) => {
      return del<void>(url)
    }
  )
}

/**
 * Approve a scope exclusion
 */
export function useApproveExclusionApi(exclusionId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}/approve` : null,
    async (url: string) => {
      return post<ApiScopeExclusion>(url, {})
    }
  )
}

/**
 * Activate a scope exclusion
 */
export function useActivateExclusionApi(exclusionId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}/activate` : null,
    async (url: string) => {
      return post<ApiScopeExclusion>(url, {})
    }
  )
}

/**
 * Deactivate a scope exclusion
 */
export function useDeactivateExclusionApi(exclusionId: string) {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant && exclusionId ? `${BASE_URL}/exclusions/${exclusionId}/deactivate` : null,
    async (url: string) => {
      return post<ApiScopeExclusion>(url, {})
    }
  )
}

/**
 * Bulk delete scope exclusions
 */
export function useBulkDeleteExclusionsApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/exclusions/bulk/delete` : null,
    async (url: string, { arg }: { arg: BulkDeleteExclusionsInput }) => {
      return post<BulkOperationResponse>(url, arg)
    }
  )
}

// ============================================
// STATS HOOK
// ============================================

/**
 * Fetch scope statistics for current tenant
 */
export function useScopeStatsApi(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()

  const key = currentTenant ? `${BASE_URL}/stats` : null

  return useSWR<ApiScopeStats>(key, fetchStats, { ...defaultConfig, ...config })
}

// ============================================
// CHECK SCOPE HOOK
// ============================================

/**
 * Check if a value is in scope
 */
export function useCheckScopeApi() {
  const { currentTenant } = useTenant()

  return useSWRMutation(
    currentTenant ? `${BASE_URL}/check` : null,
    async (url: string, { arg }: { arg: CheckScopeInput }) => {
      return post<ApiCheckScopeResponse>(url, arg)
    }
  )
}

// ============================================
// ENTRY DECISIONS (RFC-054 §6.1)
//
// Widening routes (create as an approver, approve, activate, a later expiry
// or a higher tier) answer 403 STEP_UP_REQUIRED until the session
// re-authenticated; the shared client opens the re-authentication dialog and
// retries once, so callers only see the final result.
// ============================================

/** POST /scope/targets: an entry (approver) or a request (member). */
export function createScopeTarget(input: CreateScopeTargetInput) {
  return post<ApiScopeTarget>(`${BASE_URL}/targets`, input)
}

/** POST /scope/targets/{id}/approve (scope:approve, step-up). */
export function approveScopeTarget(id: string) {
  return post<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}/approve`, {})
}

/**
 * POST /scope/targets/{id}/self-approve (scope:approve): an owner approves
 * their own pending entry when no other approver exists, with a reason and a
 * fresh authenticator code (RFC-054 §7).
 */
export function selfApproveScopeTarget(id: string, input: { reason: string; totp_code: string }) {
  return post<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}/self-approve`, input)
}

/** POST /scope/targets/{id}/remind (scope:write): at most once an hour. */
export function remindScopeApprovers(id: string) {
  return post<{ reminded: number; reminded_at?: string; can_remind_at: string }>(
    `${BASE_URL}/targets/${encodeURIComponent(id)}/remind`,
    {}
  )
}

/**
 * POST /scope/targets/{id}/attest (scope:approve): an active T2 entry keeps
 * intrusive probes for another period (RFC-054 §12.5).
 */
export function attestScopeTarget(id: string) {
  return post<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}/attest`, {})
}

/** POST /scope/targets/{id}/reject (scope:approve). */
export function rejectScopeTarget(id: string) {
  return post<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}/reject`, {})
}

/** POST /scope/targets/{id}/activate (widening) or /deactivate (narrowing). */
export function setScopeTargetActive(id: string, active: boolean) {
  const action = active ? 'activate' : 'deactivate'
  return post<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}/${action}`, {})
}

/** PUT /scope/targets/{id} */
export function updateScopeTarget(id: string, input: UpdateScopeTargetInput) {
  return put<ApiScopeTarget>(`${BASE_URL}/targets/${encodeURIComponent(id)}`, input)
}

// ============================================
// EXCLUSION DECISIONS (RFC-054 §6.2)
//
// Lifting an exclusion (deactivate, remove, an earlier end) widens scope and
// needs the exclusion-approve permission and step-up; the shared client
// handles step-up. Approving needs someone other than the requester.
// ============================================

export function createScopeExclusion(input: CreateScopeExclusionInput) {
  return post<ApiScopeExclusion>(`${BASE_URL}/exclusions`, input)
}

export function updateScopeExclusion(id: string, input: UpdateScopeExclusionInput) {
  return put<ApiScopeExclusion>(`${BASE_URL}/exclusions/${encodeURIComponent(id)}`, input)
}

export function decideScopeExclusion(id: string, approve: boolean) {
  const action = approve ? 'approve' : 'reject'
  return post<ApiScopeExclusion>(`${BASE_URL}/exclusions/${encodeURIComponent(id)}/${action}`, {})
}

export function setScopeExclusionActive(id: string, active: boolean) {
  const action = active ? 'activate' : 'deactivate'
  return post<ApiScopeExclusion>(`${BASE_URL}/exclusions/${encodeURIComponent(id)}/${action}`, {})
}

/**
 * PUT /scope/exclusions/{id}/testing: how a path exclusion may be tested.
 * Needs the exclusion-approve permission and step-up; audited, and every
 * administrator is notified. It never widens scope beyond the organization's
 * in-scope assets.
 */
export function setScopeExclusionTesting(id: string, input: SetExclusionTestingInput) {
  return put<ApiScopeExclusion & PathExclusionFields>(
    `${BASE_URL}/exclusions/${encodeURIComponent(id)}/testing`,
    input
  )
}

export function deleteScopeExclusion(id: string) {
  return del<void>(`${BASE_URL}/exclusions/${encodeURIComponent(id)}`)
}

// ============================================
// SETTINGS (RFC-054 §6.3)
// ============================================

const SETTINGS_URL = `${BASE_URL}/settings`

/** GET /scope/settings (scope:read). */
export function useScopeSettingsApi(enabled = true, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? SETTINGS_URL : null
  return useSWR<ApiScopeSettings>(key, (url: string) => get<ApiScopeSettings>(url), {
    ...defaultConfig,
    // A member without scope:read gets 403; the caller hides what needs it.
    onError: () => undefined,
    ...config,
  })
}

/** PUT /scope/settings (scope:approve, step-up). */
export function updateScopeSettings(input: UpdateScopeSettingsInput) {
  return put<ApiScopeSettings>(SETTINGS_URL, input)
}

/** PUT /scope/settings/intrusive: owner only, with a reason (RFC-054 §12.4). */
export function updateScopeIntrusiveSettings(input: {
  t2_max_duration: ScopeT2MaxDuration
  t2_attestation_days?: number
  reason: string
}) {
  return put<ApiScopeSettings>(`${SETTINGS_URL}/intrusive`, input)
}

// ============================================
// CACHE UTILITIES
// ============================================

/**
 * Invalidate all scope-related caches
 */
export async function invalidateScopeCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/scope'), undefined, {
    revalidate: true,
  })
}

/**
 * Invalidate scope targets cache
 */
export async function invalidateScopeTargetsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/scope/targets'), undefined, {
    revalidate: true,
  })
}

/**
 * Invalidate scope exclusions cache
 */
export async function invalidateScopeExclusionsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/scope/exclusions'), undefined, {
    revalidate: true,
  })
}

/**
 * Invalidate scope stats cache
 */
export async function invalidateScopeStatsCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/scope/stats'), undefined, {
    revalidate: true,
  })
}
