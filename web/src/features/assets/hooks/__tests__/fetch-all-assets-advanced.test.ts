/**
 * An export of a filter given as query text runs the checked document, page by
 * page, never the plain list (which would ignore the text and export every asset).
 */
import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest'

const api = vi.hoisted(() => ({ parse: vi.fn() }))
vi.mock('@/features/query/api/query-api', () => ({ queryApi: { parse: api.parse } }))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))

import { get, post } from '@/lib/api/client'
import { fetchAllAssets } from '../use-assets'

describe('fetchAllAssets with a filter given as text', () => {
  beforeEach(() => vi.clearAllMocks())

  it('walks /assets/search pages and never GET /assets', async () => {
    api.parse.mockResolvedValue({
      valid: true,
      text: 't',
      document: { v: 1, filter: {} },
      problems: [],
    })
    ;(post as Mock)
      .mockResolvedValueOnce({ data: [{ id: 'a', name: 'a', type: 'host' }], total_pages: 2 })
      .mockResolvedValueOnce({ data: [{ id: 'b', name: 'b', type: 'host' }], total_pages: 2 })
    const all = await fetchAllAssets({ advanced: 'port=22 OR port=23' })
    expect(all.map((a) => a.id)).toEqual(['a', 'b'])
    expect(get).not.toHaveBeenCalled()
    expect((post as Mock).mock.calls[0][0]).toBe('/api/v1/assets/search')
    expect((post as Mock).mock.calls[1][1]).toMatchObject({ page: { page: 2, per_page: 100 } })
  })
})
