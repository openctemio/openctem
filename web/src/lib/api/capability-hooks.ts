/**
 * Capability API Hooks
 *
 * SWR hooks for Capability Management
 */

'use client'

import useSWR, { type SWRConfiguration, mutate } from 'swr'
import useSWRMutation from 'swr/mutation'
import { get, post, put, del } from './client'
import { handleApiError } from './error-handler'
import { capabilityEndpoints } from './endpoints'
import type {
  Capability,
  CapabilityListResponse,
  CapabilityListFilters,
  CapabilityAllResponse,
  CapabilityCategoriesResponse,
  CreateCapabilityRequest,
  UpdateCapabilityRequest,
  CapabilityUsageStats,
} from './capability-types'
import {
  getCapabilityIcon,
  getCapabilityColor,
  getCapabilityDisplayName,
  getCapabilityDescription,
} from './capability-types'

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
// CACHE KEYS
// ============================================

export const capabilityKeys = {
  all: ['capabilities'] as const,
  lists: () => [...capabilityKeys.all, 'list'] as const,
  list: (filters?: CapabilityListFilters) => [...capabilityKeys.lists(), filters] as const,
  allCapabilities: (usage = false) => [...capabilityKeys.all, 'all', usage] as const,
  categories: () => [...capabilityKeys.all, 'categories'] as const,
  details: () => [...capabilityKeys.all, 'detail'] as const,
  detail: (id: string) => [...capabilityKeys.details(), id] as const,
  usageStats: (id: string) => [...capabilityKeys.all, 'usage-stats', id] as const,
}

/** The list's page size cap. */
const CAPABILITY_PAGE_SIZE = 100
/** Pages read at most for "every capability" (the platform catalog is small). */
const CAPABILITY_MAX_PAGES = 20

/**
 * Every capability the organization sees, page by page.
 */
export async function fetchAllCapabilities(usage = false): Promise<Capability[]> {
  const all: Capability[] = []
  for (let page = 1; page <= CAPABILITY_MAX_PAGES; page++) {
    const resp = await get<CapabilityListResponse>(
      capabilityEndpoints.list({
        page,
        per_page: CAPABILITY_PAGE_SIZE,
        ...(usage ? { include: 'usage' } : {}),
      })
    )
    all.push(...(resp?.items ?? []))
    if (page >= (resp?.total_pages ?? 1)) break
  }
  return all
}

// ============================================
// CACHE INVALIDATION
// ============================================

/**
 * Invalidate all capability caches
 */
export async function invalidateCapabilitiesCache() {
  await mutate((key) => Array.isArray(key) && key[0] === 'capabilities', undefined, {
    revalidate: true,
  })
}

// ============================================
// READ HOOKS
// ============================================

/**
 * Fetch all capabilities (platform + tenant custom) with pagination
 */
export function useCapabilities(filters?: CapabilityListFilters, config?: SWRConfiguration) {
  return useSWR<CapabilityListResponse>(
    capabilityKeys.list(filters),
    () => get<CapabilityListResponse>(capabilityEndpoints.list(filters)),
    { ...defaultConfig, ...config }
  )
}

/**
 * Every capability the organization sees (all pages). With `usage`, each
 * carries which of the organization's tools and sensors have it (counts).
 */
export function useAllCapabilities(config?: SWRConfiguration, opts?: { usage?: boolean }) {
  const usage = opts?.usage ?? false
  return useSWR<CapabilityAllResponse>(
    capabilityKeys.allCapabilities(usage),
    async () => ({ items: await fetchAllCapabilities(usage) }),
    { ...defaultConfig, ...config }
  )
}

/**
 * Fetch a single capability by ID
 */
export function useCapability(capabilityId: string | null | undefined, config?: SWRConfiguration) {
  return useSWR<Capability>(
    capabilityId ? capabilityKeys.detail(capabilityId) : null,
    () => get<Capability>(capabilityEndpoints.get(capabilityId!)),
    { ...defaultConfig, ...config }
  )
}

/**
 * Fetch all capability categories (security, recon, analysis)
 */
export function useCapabilityCategories(config?: SWRConfiguration) {
  return useSWR<CapabilityCategoriesResponse>(
    capabilityKeys.categories(),
    () => get<CapabilityCategoriesResponse>(capabilityEndpoints.categories()),
    { ...defaultConfig, ...config }
  )
}

/**
 * Usage of one capability, with the tool and sensor names
 * (GET /capabilities/{id}?include=usage). Undefined when the caller may not
 * read it (the include is left out): unknown, never "unused".
 */
export function useCapabilityUsageStats(
  capabilityId: string | null | undefined,
  config?: SWRConfiguration
) {
  return useSWR<CapabilityUsageStats | undefined>(
    capabilityId ? capabilityKeys.usageStats(capabilityId) : null,
    async () => (await get<Capability>(capabilityEndpoints.get(capabilityId!, 'usage'))).usage,
    { ...defaultConfig, ...config }
  )
}

// ============================================
// MUTATION HOOKS (Custom Capabilities)
// ============================================

/**
 * Create a new custom capability
 */
export function useCreateCapability() {
  return useSWRMutation<Capability, Error, string, CreateCapabilityRequest>(
    'create-capability',
    async (_key, { arg }) => {
      const response = await post<Capability>(capabilityEndpoints.create(), arg)
      await invalidateCapabilitiesCache()
      return response
    }
  )
}

/**
 * Update a custom capability
 */
export function useUpdateCapability(capabilityId: string) {
  return useSWRMutation<Capability, Error, string, UpdateCapabilityRequest>(
    `update-capability-${capabilityId}`,
    async (_key, { arg }) => {
      const response = await put<Capability>(capabilityEndpoints.update(capabilityId), arg)
      await invalidateCapabilitiesCache()
      return response
    }
  )
}

/**
 * Delete a custom capability
 * @param capabilityId - The capability ID to delete
 */
export function useDeleteCapability(capabilityId: string) {
  return useSWRMutation<void, Error, string, { force?: boolean }>(
    `delete-capability-${capabilityId}`,
    async (_key, { arg }) => {
      await del(capabilityEndpoints.delete(capabilityId, arg?.force))
      await invalidateCapabilitiesCache()
    }
  )
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Find a capability by ID from a list of capabilities
 */
export function findCapabilityById(
  capabilities: Capability[] | undefined,
  capabilityId: string | undefined
): Capability | undefined {
  if (!capabilities || !capabilityId) return undefined
  return capabilities.find((c) => c.id === capabilityId)
}

/**
 * Find a capability by name from a list of capabilities
 */
export function findCapabilityByName(
  capabilities: Capability[] | undefined,
  name: string | undefined
): Capability | undefined {
  if (!capabilities || !name) return undefined
  return capabilities.find((c) => c.name === name)
}

/**
 * Get capability name from ID (returns capability name for icon/color lookups)
 * Falls back to 'unknown' if capability not found
 */
export function getCapabilityNameById(
  capabilities: Capability[] | undefined,
  capabilityId: string | undefined
): string {
  const capability = findCapabilityById(capabilities, capabilityId)
  return capability?.name || 'unknown'
}

/**
 * Get capability display name from ID
 * Falls back to 'Unknown' if capability not found
 */
export function getCapabilityDisplayNameById(
  capabilities: Capability[] | undefined,
  capabilityId: string | undefined
): string {
  const capability = findCapabilityById(capabilities, capabilityId)
  return capability?.display_name || 'Unknown'
}

/**
 * Get capabilities by names from a list
 */
export function getCapabilitiesByNames(
  capabilities: Capability[] | undefined,
  names: string[] | undefined
): Capability[] {
  if (!capabilities || !names || names.length === 0) return []
  return capabilities.filter((c) => names.includes(c.name))
}

// ============================================
// CAPABILITY METADATA HOOK
// ============================================

/**
 * Hook for easy access to capability metadata (icon, color, display name).
 * Fetches capabilities from API and provides helper functions.
 *
 * @example
 * ```tsx
 * const { getIcon, getColor, getDisplayName, isLoading } = useCapabilityMetadata();
 *
 * // Get icon for a capability
 * const icon = getIcon('sast'); // 'code'
 * const color = getColor('sast'); // 'purple'
 * const displayName = getDisplayName('sast'); // 'Static Analysis'
 * ```
 */
export function useCapabilityMetadata(config?: SWRConfiguration) {
  const { data, isLoading, error } = useAllCapabilities(config)

  const capabilities = data?.items

  return {
    /** Get the icon for a capability by name */
    getIcon: (name: string) => getCapabilityIcon(capabilities, name),
    /** Get the color for a capability by name */
    getColor: (name: string) => getCapabilityColor(capabilities, name),
    /** Get the display name for a capability by name */
    getDisplayName: (name: string) => getCapabilityDisplayName(capabilities, name),
    /** Get the description for a capability by name */
    getDescription: (name: string) => getCapabilityDescription(capabilities, name),
    /** Find a capability by name */
    findByName: (name: string) => findCapabilityByName(capabilities, name),
    /** All capabilities from the registry */
    capabilities,
    /** Loading state */
    isLoading,
    /** Error state */
    error,
  }
}

// Re-export helper functions for direct use
export { getCapabilityIcon, getCapabilityColor, getCapabilityDisplayName, getCapabilityDescription }
