/**
 * SLA Policy API Hooks
 *
 * SWR hooks for the shipped /api/v1/sla-policies backend
 * (api: internal/infra/http/routes/misc.go + handler/sla_handler.go).
 *
 * A policy carries two sets of remediation windows: per CTEM priority class
 * (P0..P3, used for every finding that has a class) and per severity (used
 * only for findings without a class yet).
 *
 * Tenant is derived from the JWT on the server; no tenant param is sent.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del } from '@/lib/api/client'
import { handleApiError } from '@/lib/api/error-handler'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'

const BASE_URL = '/api/v1/sla-policies'

// ============================================
// TYPES (mirror sla_handler.go SLAPolicyResponse)
// ============================================

export interface SlaPolicy {
  id: string
  tenant_id: string
  /** Present only for per-asset override policies; empty/absent = tenant policy. */
  asset_id?: string
  name: string
  description?: string
  is_default: boolean
  critical_days: number
  high_days: number
  medium_days: number
  low_days: number
  info_days: number
  p0_days: number
  p1_days: number
  p2_days: number
  p3_days: number
  warning_threshold_pct: number
  escalation_enabled: boolean
  is_active: boolean
  /**
   * True when the organization has configured no policy and these are the
   * platform default windows (the id is then empty). Only the effective-policy
   * reads (`/default`, `/assets/{id}/sla-policy`) return it.
   */
  is_platform_default?: boolean
  created_at: string
  updated_at: string
}

export interface SlaPolicyListResponse {
  data: SlaPolicy[]
  total: number
}

/** POST body — matches CreateSLAPolicyRequest. Day fields are required 1..365. */
export interface CreateSlaPolicyInput {
  name: string
  description?: string
  is_default?: boolean
  critical_days: number
  high_days: number
  medium_days: number
  low_days: number
  info_days: number
  /** Priority-class windows; an omitted class keeps the platform default. */
  p0_days?: number
  p1_days?: number
  p2_days?: number
  p3_days?: number
  warning_threshold_pct: number
  escalation_enabled?: boolean
  /** Optional per-asset override; omit for a tenant-level policy. */
  asset_id?: string
}

/** PUT body — matches UpdateSLAPolicyRequest (all fields optional). */
export interface UpdateSlaPolicyInput extends Partial<CreateSlaPolicyInput> {
  is_active?: boolean
}

// ============================================
// SWR CONFIG
// ============================================

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 3,
  dedupingInterval: 2000,
  onError: (error) => handleApiError(error, { showToast: true, logError: true }),
}

// ============================================
// READ HOOKS
// ============================================

/** List all SLA policies for the current tenant. */
export function useSlaPoliciesApi(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key = currentTenant && can(Permission.SLARead) ? `${BASE_URL}/` : null
  return useSWR<SlaPolicyListResponse>(key, (url: string) => get<SlaPolicyListResponse>(url), {
    ...defaultConfig,
    ...config,
  })
}

/**
 * The organization's effective SLA windows: its default policy, else the
 * platform defaults (`is_platform_default`). The console states remediation
 * windows only from here or from {@link useAssetSlaPolicyApi}; it keeps no
 * copy of the numbers.
 */
export function useDefaultSlaPolicyApi(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key = currentTenant && can(Permission.SLARead) ? `${BASE_URL}/default` : null
  return useSWR<SlaPolicy>(key, (url: string) => get<SlaPolicy>(url), {
    ...defaultConfig,
    // Windows are supporting text: a failed read hides them, it is not an error to toast.
    onError: () => {},
    ...config,
  })
}

/**
 * The policy that governs an asset: its own override, else the tenant default,
 * else the platform defaults (`is_platform_default`).
 */
export function useAssetSlaPolicyApi(assetId: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && assetId ? assetSlaPolicyUrl(assetId) : null
  return useSWR<SlaPolicy>(key, (url: string) => get<SlaPolicy>(url), {
    ...defaultConfig,
    onError: () => {},
    shouldRetryOnError: false,
    ...config,
  })
}

function assetSlaPolicyUrl(assetId: string): string {
  return `/api/v1/assets/${encodeURIComponent(assetId)}/sla-policy/`
}

/**
 * The windows that apply: the asset's effective policy when an asset is
 * given, else the organization's (both fall back to the platform defaults
 * on the server). One request either way; undefined while loading or when
 * the caller may not read it.
 */
export function useEffectiveSlaPolicy(assetId?: string | null) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  let key: string | null = null
  if (currentTenant) {
    if (assetId) key = assetSlaPolicyUrl(assetId)
    else if (can(Permission.SLARead)) key = `${BASE_URL}/default`
  }
  return useSWR<SlaPolicy>(key, (url: string) => get<SlaPolicy>(url), {
    ...defaultConfig,
    onError: () => {},
    shouldRetryOnError: false,
  })
}

/** Get a single SLA policy by id. */
export function useSlaPolicyApi(id: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key = currentTenant && id && can(Permission.SLARead) ? `${BASE_URL}/${id}` : null
  return useSWR<SlaPolicy>(key, (url: string) => get<SlaPolicy>(url), {
    ...defaultConfig,
    ...config,
  })
}

// ============================================
// MUTATION HOOKS
// ============================================

export function useCreateSlaPolicy() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? `${BASE_URL}/` : null,
    (url: string, { arg }: { arg: CreateSlaPolicyInput }) => post<SlaPolicy>(url, arg)
  )
}

export function useUpdateSlaPolicy() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    (url: string, { arg }: { arg: { id: string } & UpdateSlaPolicyInput }) => {
      const { id, ...body } = arg
      return put<SlaPolicy>(`${url}/${id}`, body)
    }
  )
}

export function useDeleteSlaPolicy() {
  const { currentTenant } = useTenant()
  return useSWRMutation(
    currentTenant ? BASE_URL : null,
    (url: string, { arg }: { arg: { id: string } }) => del<void>(`${url}/${arg.id}`)
  )
}

// ============================================
// CACHE INVALIDATION
// ============================================

/** Revalidate every SLA-policy SWR key after a mutation. */
export async function invalidateSlaPoliciesCache() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.includes('/sla-policies'), undefined, {
    revalidate: true,
  })
}
