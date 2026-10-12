'use client'

import { useMemo } from 'react'
import useSWRInfinite from 'swr/infinite'
import { get } from '@/lib/api/client'
import type { EASMChangePage } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'
import { changesRequestUrl, type ChangeQuery } from '../lib/changes'

/**
 * Pages of typed attack-surface changes (GET /api/v1/easm/changes), newest
 * first, following next_cursor. Needs assets:read; the API narrows to the
 * caller's data scope. The relative window is fixed when the query changes,
 * so later pages continue the same window.
 */
export function useEASMChanges(q: ChangeQuery) {
  const { can } = usePermissions()
  const allowed = can(Permission.AssetsRead)
  const key = `${q.from ?? ''}|${q.to ?? ''}|${q.days}|${q.kinds.join(',')}`
  // eslint-disable-next-line react-hooks/exhaustive-deps -- a new window starts when the query changes
  const now = useMemo(() => new Date(), [key])
  const { data, error, isLoading, isValidating, size, setSize, mutate } =
    useSWRInfinite<EASMChangePage>(
      (index, previous: EASMChangePage | null) => {
        if (!allowed) return null
        if (index === 0) return changesRequestUrl(q, undefined, now)
        if (!previous?.next_cursor) return null
        return changesRequestUrl(q, previous.next_cursor, now)
      },
      get,
      { revalidateOnFocus: false, revalidateFirstPage: false }
    )
  const pages = useMemo(() => data ?? [], [data])
  const first = pages[0]
  return {
    items: pages.flatMap((p) => p.items ?? []),
    counts: (first?.counts ?? {}) as Record<string, number>,
    total: first?.total ?? 0,
    from: first?.from,
    to: first?.to,
    error,
    isLoading,
    allowed,
    loadingMore: isValidating && size > pages.length,
    hasMore: pages.length > 0 && !!pages[pages.length - 1]?.next_cursor,
    loadMore: () => setSize(size + 1),
    mutate,
  }
}
