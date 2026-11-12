/**
 * The practice switch's counts ride on the list (GET /findings?include=practice_counts):
 * - page 1 asks for them with the list, and the switch reads them from that answer
 * - a later page reads page 1's cached counts and does not ask again
 * - a later page with no cached page 1 (a direct link) asks itself
 * - the grouped view asks for one row with the counts
 * - an fq filter (POST /findings/search) has no counts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { SWRConfig } from 'swr'
import { usePracticeCountsList } from '../use-practice-counts'
import { buildFindingsEndpoint } from '../findings-query'
import type { ApiFindingListResponse, FindingApiFilters } from '../finding-api.types'

const mockGet = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => mockGet(...a),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-1' } }),
}))

const counts = {
  total: 7,
  vulnerabilities: 4,
  practices: [
    { practice: 'aspm', count: 1 },
    { practice: 'infra', count: 3 },
    { practice: 'compliance', count: 3 },
  ],
}

function page(n: number, withCounts: boolean): ApiFindingListResponse {
  return {
    data: [],
    total: 7,
    page: n,
    per_page: 25,
    total_pages: 1,
    ...(withCounts ? { practice_counts: counts } : {}),
  }
}

function setup(filters: FindingApiFilters, grouped = false, cache = new Map()) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}>{children}</SWRConfig>
  )
  return renderHook(() => usePracticeCountsList(filters, { enabled: true, grouped }), { wrapper })
}

const base: FindingApiFilters = { severities: ['high'], practice_not: 'compliance', per_page: 25 }

describe('usePracticeCountsList', () => {
  beforeEach(() => mockGet.mockReset())

  it('asks with page 1 and reads the counts from its answer', () => {
    const { result } = setup({ ...base, page: 1 })
    expect(result.current.listFilters.include).toBe('practice_counts')
    const got = result.current.countsFor(page(1, true))
    expect(got?.vulnerabilities).toBe(4)
    expect(got?.total).toBe(7)
    expect(got?.byPractice.infra).toBe(3)
    expect(mockGet).not.toHaveBeenCalled()
  })

  it('reads page 1 counts on a later page without asking again', () => {
    const cache = new Map()
    const first = buildFindingsEndpoint({ ...base, page: 1, include: 'practice_counts' })
    cache.set(first, { data: page(1, true) })
    const { result } = setup({ ...base, page: 2 }, false, cache)
    expect(result.current.listFilters.include).toBeUndefined()
    expect(result.current.countsFor(page(2, false))?.byPractice.compliance).toBe(3)
  })

  it('asks on a later page when page 1 is not cached', () => {
    const { result } = setup({ ...base, page: 3 })
    expect(result.current.listFilters.include).toBe('practice_counts')
    expect(result.current.countsFor(page(3, true))?.total).toBe(7)
  })

  it('asks for one row with the counts in the grouped view', async () => {
    mockGet.mockResolvedValue(page(1, true))
    const { result } = setup({ ...base, page: 1 }, true)
    expect(result.current.listFilters.include).toBeUndefined()
    await waitFor(() => expect(result.current.countsFor(undefined)?.total).toBe(7))
    const url = String(mockGet.mock.calls[0][0])
    expect(url).toContain('include=practice_counts')
    expect(url).toContain('per_page=1')
  })

  it('has no counts for an fq filter', () => {
    const { result } = setup({ ...base, page: 1, fq: 'severity:high' })
    expect(result.current.listFilters.include).toBeUndefined()
    expect(result.current.countsFor(page(1, true))).toBeUndefined()
  })
})
