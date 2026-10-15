import { describe, it, expect, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (u: string) => get(u),
  post: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}))

import { fetchAllCampaigns } from '../use-remediation-campaigns'

describe('fetchAllCampaigns', () => {
  it('reads every page, not only the first 50', async () => {
    const page = (n: number, count: number) => ({
      data: Array.from({ length: count }, (_, i) => ({ id: `c${n}-${i}` })),
      total: 230,
      total_pages: 3,
    })
    get.mockImplementation((url: string) => {
      const n = Number(new URL(url, 'http://x').searchParams.get('page'))
      return Promise.resolve(page(n, n < 3 ? 100 : 30))
    })
    const res = await fetchAllCampaigns('/api/v1/remediation/campaigns?status=active')
    expect(res.data).toHaveLength(230)
    expect(get).toHaveBeenCalledTimes(3)
    expect(get.mock.calls[0][0]).toBe(
      '/api/v1/remediation/campaigns?status=active&page=1&per_page=100'
    )
  })
})
