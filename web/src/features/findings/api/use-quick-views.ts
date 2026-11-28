'use client'

import useSWR from 'swr'
import { mutate as globalMutate } from '@/lib/swr-mutate'
import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type { QuickViewsResponse } from '../lib/quick-views'
import { DEFAULT_PRACTICE_VIEW, type PracticeView } from '../lib/practice'

export const QUICK_VIEWS_URL = '/api/v1/findings/quick-views'

/** The counts' URL under a practice view (the list's scope). */
export function quickViewsUrl(practice: PracticeView = DEFAULT_PRACTICE_VIEW): string {
  return `${QUICK_VIEWS_URL}?practice=${encodeURIComponent(practice)}`
}

/**
 * The counts of the built-in findings views, in the caller's scope, under the
 * practice view the list shows (the server counts under it, so "Active" here
 * is the list's own total; the default is the list's default view). One call,
 * private-cacheable for 60 s by the server; fetched only while `enabled` (the
 * sidebar asks on the Findings pages), so no other page pays for it.
 */
export function useFindingQuickViews(
  enabled: boolean,
  practice: PracticeView = DEFAULT_PRACTICE_VIEW
) {
  const { currentTenant } = useTenant()
  const key = enabled && currentTenant?.id ? quickViewsUrl(practice) : null
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
  return globalMutate((key) => typeof key === 'string' && key.startsWith(QUICK_VIEWS_URL))
}
