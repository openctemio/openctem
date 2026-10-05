/**
 * Tenant Settings API Hooks
 *
 * SWR hooks for fetching and updating tenant settings
 */

import useSWR, { useSWRConfig } from 'swr'
import useSWRMutation from 'swr/mutation'
import { tenantEndpoints } from '@/lib/api/endpoints'
import { fetcher, fetcherWithOptions } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type {
  SettingsSectionKey,
  TenantSettings,
  UpdateGeneralSettingsInput,
  UpdateSecuritySettingsInput,
  UpdateBrandingSettingsInput,
} from '../types/settings.types'

// ============================================
// UPDATE TENANT (Name, Slug)
// ============================================

/**
 * Input for updating tenant basic info
 */
export interface UpdateTenantInput {
  name?: string
  slug?: string
  description?: string
  logo_url?: string
}

/**
 * Tenant response from API
 */
export interface TenantResponse {
  id: string
  name: string
  slug: string
  description?: string
  logo_url?: string
  plan: string
  settings?: Record<string, unknown>
  created_at: string
  updated_at: string
}

async function updateTenant(url: string, { arg }: { arg: UpdateTenantInput }) {
  return fetcherWithOptions<TenantResponse>(url, {
    method: 'PATCH',
    body: JSON.stringify(arg),
  })
}

/**
 * Hook to update tenant basic info (name, slug)
 */
export function useUpdateTenant(tenantIdOrSlug: string | undefined) {
  const { trigger, isMutating, error } = useSWRMutation(
    tenantIdOrSlug ? tenantEndpoints.update(tenantIdOrSlug) : null,
    updateTenant
  )

  return {
    updateTenant: trigger,
    isUpdating: isMutating,
    error,
  }
}

// ============================================
// FETCH SETTINGS
// ============================================

/**
 * Hook to fetch tenant settings
 * Only fetches if user has team:read permission
 */
export function useTenantSettings(tenantIdOrSlug: string | undefined) {
  const { can } = usePermissions()
  const canReadTeam = can(Permission.TeamRead)

  // Only fetch if user has permission
  const shouldFetch = tenantIdOrSlug && canReadTeam

  const { data, error, isLoading, mutate } = useSWR<TenantSettings>(
    shouldFetch ? tenantEndpoints.settings(tenantIdOrSlug) : null,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000, // Cache for 30 seconds
    }
  )

  return {
    settings: data,
    isLoading: shouldFetch ? isLoading : false,
    isError: !!error,
    error,
    mutate,
  }
}

// ============================================
// SECTION WRITES WITH OPTIMISTIC CONCURRENCY
// ============================================

/**
 * True when the API refused a settings save because the section changed
 * since this page read it (409 SETTINGS_CONFLICT).
 */
export function isSettingsConflict(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === 'SETTINGS_CONFLICT'
}

/**
 * PATCH one settings section with If-Match set to the section ETag from the
 * cached GET /settings response. If someone else saved the section since,
 * the API answers 409 SETTINGS_CONFLICT instead of overwriting their change;
 * the cached settings are then revalidated so the form shows the current
 * values, and the error is re-thrown for the caller to report. On success
 * the cache takes the response, which carries the new ETags.
 */
function useSettingsSectionMutation<TInput>(
  tenantIdOrSlug: string | undefined,
  url: string | null,
  section: SettingsSectionKey
) {
  const { cache, mutate } = useSWRConfig()
  const settingsKey = tenantIdOrSlug ? tenantEndpoints.settings(tenantIdOrSlug) : null

  return useSWRMutation(url, async (endpoint: string, { arg }: { arg: TInput }) => {
    const cached = settingsKey
      ? (cache.get(settingsKey)?.data as TenantSettings | undefined)
      : undefined
    const etag = cached?.etags?.[section]
    try {
      const result = await fetcherWithOptions<TenantSettings>(endpoint, {
        method: 'PATCH',
        body: JSON.stringify(arg),
        headers: etag ? { 'If-Match': etag } : undefined,
      })
      if (settingsKey) await mutate(settingsKey, result, { revalidate: false })
      return result
    } catch (err) {
      if (settingsKey && isSettingsConflict(err)) await mutate(settingsKey)
      throw err
    }
  })
}

// ============================================
// UPDATE GENERAL SETTINGS
// ============================================

/**
 * Hook to update general settings
 */
export function useUpdateGeneralSettings(tenantIdOrSlug: string | undefined) {
  const { trigger, isMutating, error } = useSettingsSectionMutation<UpdateGeneralSettingsInput>(
    tenantIdOrSlug,
    tenantIdOrSlug ? tenantEndpoints.updateGeneralSettings(tenantIdOrSlug) : null,
    'general'
  )

  return {
    updateGeneralSettings: trigger,
    isUpdating: isMutating,
    error,
  }
}

// ============================================
// UPDATE SECURITY SETTINGS
// ============================================

/**
 * Hook to update security settings
 */
export function useUpdateSecuritySettings(tenantIdOrSlug: string | undefined) {
  const { trigger, isMutating, error } = useSettingsSectionMutation<UpdateSecuritySettingsInput>(
    tenantIdOrSlug,
    tenantIdOrSlug ? tenantEndpoints.updateSecuritySettings(tenantIdOrSlug) : null,
    'security'
  )

  return {
    updateSecuritySettings: trigger,
    isUpdating: isMutating,
    error,
  }
}

// ============================================
// UPDATE BRANDING SETTINGS
// ============================================

/**
 * Hook to update branding settings
 */
export function useUpdateBrandingSettings(tenantIdOrSlug: string | undefined) {
  const { trigger, isMutating, error } = useSettingsSectionMutation<UpdateBrandingSettingsInput>(
    tenantIdOrSlug,
    tenantIdOrSlug ? tenantEndpoints.updateBrandingSettings(tenantIdOrSlug) : null,
    'branding'
  )

  return {
    updateBrandingSettings: trigger,
    isUpdating: isMutating,
    error,
  }
}

// ============================================
// INVALIDATION HELPERS
// ============================================

/**
 * Get the SWR key for tenant settings
 */
export function getTenantSettingsKey(tenantIdOrSlug: string) {
  return tenantEndpoints.settings(tenantIdOrSlug)
}
