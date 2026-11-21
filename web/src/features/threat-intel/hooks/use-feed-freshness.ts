'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { threatIntelEndpoints } from '@/lib/api/endpoints'
import type { FeedFreshness } from '@/lib/api/threatintel-types'

/** How often an open page asks again (the server checks every 10 minutes). */
export const FEED_FRESHNESS_REFRESH_MS = 5 * 60 * 1000

/**
 * Freshness of the platform's vulnerability data. Every signed-in user may
 * read it (no permission): it says only whether the platform's data is
 * current. One shared request for the banner and every "data as of" line.
 */
export function useFeedFreshness(enabled = true) {
  const { data, error, isLoading } = useSWR<FeedFreshness>(
    enabled ? threatIntelEndpoints.freshness() : null,
    (url: string) => get<FeedFreshness>(url),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      refreshInterval: FEED_FRESHNESS_REFRESH_MS,
      dedupingInterval: 60_000,
    }
  )
  return { freshness: data ?? null, error, isLoading }
}
