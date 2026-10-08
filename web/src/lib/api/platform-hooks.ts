/**
 * Platform scanning hook: GET /api/v1/platform/scanning (members who read
 * sensors or scans). The shared platform sensors as a service, never the
 * sensors themselves.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get } from './client'
import { platformEndpoints } from './endpoints'
import type { PlatformScanningResponse } from './platform-types'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  // A 4xx (no permission) is an answer, not a blip: no retry, no toast. The
  // callers render nothing then.
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 3,
  dedupingInterval: 2000,
}

export const platformKeys = {
  all: ['platform'] as const,
  scanning: () => [...platformKeys.all, 'scanning'] as const,
}

/**
 * Platform scanning as the organization may use it. `offered` is false while
 * loading, on an error, and when the organization may not use it: callers
 * then show nothing (no upsell).
 */
export function usePlatformScanning(config?: SWRConfiguration) {
  const { data, isLoading, error } = useSWR<PlatformScanningResponse>(
    platformKeys.scanning(),
    () => get<PlatformScanningResponse>(platformEndpoints.scanning()),
    { ...defaultConfig, ...config }
  )
  return { data, offered: data?.offered === true, isLoading, error }
}
