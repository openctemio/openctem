/**
 * Counts use the queue's own list endpoint, one row per page, so the number
 * is the queue's total for the same reader; only the asked reason's request
 * is sent.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'
import type { AssetSearchFilters } from '../../../hooks/use-assets'

const calls = vi.hoisted(() => ({
  assets: [] as AssetSearchFilters[],
  suggestions: [] as boolean[],
  dedup: [] as boolean[],
}))

vi.mock('../../../hooks/use-assets', () => ({
  assetListKey: (q: AssetSearchFilters) => `assets:${q.monitoringState?.join(',')}:${q.pageSize}`,
  useAssets: (q: AssetSearchFilters) => {
    calls.assets.push(q)
    return { total: 549, hasLoaded: true }
  },
}))
vi.mock('@/features/relationships/api/use-relationship-suggestions', () => ({
  useSuggestionCount: (enabled: boolean) => {
    calls.suggestions.push(enabled)
    return { data: enabled ? { count: 12 } : undefined }
  },
}))
vi.mock('../../../api/use-asset-dedup', () => ({
  useDedupReviews: (enabled: boolean) => {
    calls.dedup.push(enabled)
    return { data: enabled ? { data: [], total: 3 } : undefined }
  },
}))

import { useAttentionCount } from '../use-attention-count'

beforeEach(() => {
  calls.assets = []
  calls.suggestions = []
  calls.dedup = []
})

describe('useAttentionCount', () => {
  it('counts an asset reason with its queue filter, attribution and one row', () => {
    const { result } = renderHook(() => useAttentionCount('no_owner'))
    expect(result.current).toBe(549)
    const q = calls.assets.at(-1)!
    expect(q).toMatchObject({ hasOwner: false, page: 1, pageSize: 1, skip: false })
    expect(q.attribution).not.toContain('needs_review')
    expect(calls.suggestions.at(-1)).toBe(false)
    expect(calls.dedup.at(-1)).toBe(false)
  })

  it('counts the root domains to validate across every attribution state', () => {
    const { result } = renderHook(() => useAttentionCount('validate_primary'))
    expect(result.current).toBe(549)
    const q = calls.assets.at(-1)!
    expect(q).toMatchObject({
      isPrimary: true,
      monitoringState: ['pending_decision', 'unvalidated'],
      page: 1,
      pageSize: 1,
      skip: false,
    })
    // Names awaiting review are what this queue is about: never hidden here.
    expect(q.attribution).toContain('needs_review')
  })

  it('reads relationships from the suggestion count and sends no asset query', () => {
    const { result } = renderHook(() => useAttentionCount('relationships'))
    expect(result.current).toBe(12)
    expect(calls.assets.at(-1)!.skip).toBe(true)
  })

  it('reads duplicates from the review list total', () => {
    const { result } = renderHook(() => useAttentionCount('duplicates'))
    expect(result.current).toBe(3)
    expect(calls.assets.at(-1)!.skip).toBe(true)
  })

  it('sends nothing while disabled', () => {
    const { result } = renderHook(() => useAttentionCount('context', false))
    expect(result.current).toBeUndefined()
    expect(calls.assets.at(-1)!.skip).toBe(true)
    expect(calls.suggestions.at(-1)).toBe(false)
  })

  describe('cacheOnly', () => {
    // A cache holding `entries`, and an app-wide fetcher that must not run.
    const fetcher = vi.fn()
    const withCache = (entries: [string, unknown][]) => {
      const cache = new Map(entries.map(([k, data]) => [k, { data }]))
      function Wrapper({ children }: { children: ReactNode }) {
        return (
          <SWRConfig value={{ provider: () => cache as never, fetcher, dedupingInterval: 0 }}>
            {children}
          </SWRConfig>
        )
      }
      return Wrapper
    }

    it('shows the figure another request already holds and sends nothing', () => {
      const { result } = renderHook(
        () => useAttentionCount('decide_monitoring', true, { cacheOnly: true }),
        { wrapper: withCache([['assets:pending_decision,unvalidated:1', { total: 462 }]]) }
      )
      expect(result.current).toBe(462)
      expect(calls.assets.at(-1)!.skip).toBe(true)
      expect(fetcher).not.toHaveBeenCalled()
    })

    it('shows nothing when the cache does not hold it', () => {
      const { result } = renderHook(
        () => useAttentionCount('decide_monitoring', true, { cacheOnly: true }),
        { wrapper: withCache([]) }
      )
      expect(result.current).toBeUndefined()
      expect(calls.assets.at(-1)!.skip).toBe(true)
      expect(fetcher).not.toHaveBeenCalled()
    })
  })
})
