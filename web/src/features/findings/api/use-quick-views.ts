'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { QuickViewsResponse } from '../lib/quick-views'

export const QUICK_VIEWS_URL = '/api/v1/findings/quick-views'

/**
 * The counts of the built-in findings views, in the caller's scope. One call,
 * private-cacheable for 60 s by the server; fetched only while `enabled` (the
 * sidebar asks on the Findings pages), so no other page pays for it.
 */
export function useFindingQuickViews(enabled: boolean) {
  const { currentTenant } = useTenant()
  const key = enabled && currentTenant?.id ? QUICK_VIEWS_URL : null
  return useSWR<QuickViewsResponse>(key, (url: string) => get<QuickViewsResponse>(url), {
    revalidateOnFocus: false,
    revalidateOnReconnect: false,
    dedupingInterval: 60_000,
    errorRetryCount: 1,
    // The sidebar shows nothing for a failed count; a toast would be noise.
    onError: () => {},
  })
}

/** Reloads the counts (after a change that moves findings between views). */
export function refreshFindingQuickViews() {
  return globalMutate(QUICK_VIEWS_URL)
}
