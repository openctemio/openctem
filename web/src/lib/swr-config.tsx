'use client'

/**
 * SWR Global Configuration
 *
 * Provides optimized default configuration for all SWR hooks in the application.
 * This ensures consistent behavior across all data fetching operations.
 *
 * Key optimizations:
 * - Deduplication: Prevents duplicate requests within 2 seconds
 * - Smart revalidation: Disable on focus, enable on reconnect
 * - Error retry: Only retry on server/network errors, not client errors (4xx)
 * - Keep previous data: Show stale data while revalidating for better UX
 */

import { SWRConfig, type SWRConfiguration } from 'swr'
import { type ReactNode } from 'react'

/**
 * Default SWR configuration for the entire application
 */
export const swrDefaultConfig: SWRConfiguration = {
  // Deduplication: Prevent duplicate requests within 2 seconds
  dedupingInterval: 2000,

  // Revalidation settings
  revalidateOnFocus: false, // Don't refetch when window regains focus
  revalidateOnReconnect: true, // Refetch when network reconnects
  revalidateIfStale: true, // Revalidate if data is stale

  // Keep previous data while revalidating for smoother UX
  keepPreviousData: true,

  // Error retry configuration
  errorRetryCount: 3,
  errorRetryInterval: 1000,
  shouldRetryOnError: (error: unknown) => {
    // Don't retry on client errors (4xx) - these are expected errors
    const statusCode = (error as { statusCode?: number })?.statusCode
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return false
    }
    // Retry on server errors (5xx) or network errors
    return true
  },

  // Loading state configuration
  // suspense: false, // Don't use React Suspense by default
  // fallbackData: undefined, // No fallback data by default

  // Performance optimizations
  // focusThrottleInterval: 5000, // Throttle focus revalidation
  // loadingTimeout: 3000, // Show loading state after 3s
}

/**
 * Freshness by data class. Spread one into a hook's options instead of
 * hand-picking `dedupingInterval` / `revalidate*` per hook.
 *
 * - `SWR_STATIC`: catalogs that change only with a deploy or a platform
 *   change (finding sources, asset-type and tool registries, enum catalogs).
 *   Fetched once per session; a mounted hook with cached data never refetches.
 * - `SWR_REFERENCE`: tenant configuration that changes by a user action
 *   (saved views, groups, tags, business units). Served from cache when a
 *   page mounts; the mutation that changes it calls `mutate(key)`, and a
 *   WebSocket event may too.
 * - live data (lists, stats, statuses): the global defaults above.
 */
export const SWR_STATIC: SWRConfiguration = {
  revalidateIfStale: false,
  revalidateOnReconnect: false,
  dedupingInterval: 60 * 60 * 1000,
}

export const SWR_REFERENCE: SWRConfiguration = {
  revalidateIfStale: false,
  dedupingInterval: 5 * 60 * 1000,
}

type GlobalMutate = (
  matcher: (key: unknown) => boolean,
  data?: undefined,
  opts?: { revalidate?: boolean }
) => Promise<unknown>

/**
 * Drops every cached answer, then refetches what is mounted. For a change of
 * session identity (organization switch): SWR keys are endpoint URLs, the
 * identity is in the cookie, so nothing of the previous organization may stay
 * in the cache or on screen.
 */
export async function clearSwrCache(mutate: GlobalMutate): Promise<void> {
  await mutate(() => true, undefined, { revalidate: false })
  void mutate(() => true)
}

interface SWRProviderProps {
  children: ReactNode
  config?: SWRConfiguration
}

/**
 * SWR Provider component
 *
 * Wraps the application with SWR's global configuration.
 * Can be customized per-subtree if needed.
 *
 * @example
 * ```tsx
 * // In providers.tsx
 * <SWRProvider>
 *   {children}
 * </SWRProvider>
 *
 * // With custom config
 * <SWRProvider config={{ refreshInterval: 5000 }}>
 *   {children}
 * </SWRProvider>
 * ```
 */
export function SWRProvider({ children, config }: SWRProviderProps) {
  return <SWRConfig value={{ ...swrDefaultConfig, ...config }}>{children}</SWRConfig>
}

export default SWRProvider
