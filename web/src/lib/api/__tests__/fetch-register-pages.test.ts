import { describe, it, expect, vi, beforeEach } from 'vitest'

const getMock = vi.fn()
vi.mock('../client', () => ({ get: (...a: unknown[]) => getMock(...a) }))

import { fetchRegisterPages } from '../fetch-all-pages'

const rows = (from: number, n: number) => Array.from({ length: n }, (_, i) => ({ id: from + i }))

describe('fetchRegisterPages', () => {
  beforeEach(() => getMock.mockReset())

  it('pages until it has every row the API reports', async () => {
    getMock
      .mockResolvedValueOnce({ data: rows(0, 100), total: 250 })
      .mockResolvedValueOnce({ data: rows(100, 100), total: 250 })
      .mockResolvedValueOnce({ data: rows(200, 50), total: 250 })
    const out = await fetchRegisterPages<{ id: number }>('/api/v1/x?per_page=100')
    expect(out.data).toHaveLength(250)
    expect(out.total).toBe(250)
    expect(getMock.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/x?per_page=100',
      '/api/v1/x?per_page=100&page=2',
      '/api/v1/x?per_page=100&page=3',
    ])
  })

  it('stops at the cap and reports the real total', async () => {
    getMock.mockImplementation(async (url: string) => {
      const page = Number(/page=(\d+)/.exec(url)?.[1] ?? 1)
      return { data: rows((page - 1) * 100, 100), total: 5000 }
    })
    const out = await fetchRegisterPages<{ id: number }>('/api/v1/x?per_page=100', 300)
    expect(out.data).toHaveLength(300)
    expect(out.total).toBe(5000)
    expect(getMock).toHaveBeenCalledTimes(3)
  })

  it('stops on an empty page', async () => {
    getMock.mockResolvedValueOnce({ data: rows(0, 100), total: 500 })
    getMock.mockResolvedValueOnce({ data: [], total: 500 })
    const out = await fetchRegisterPages('/api/v1/x?per_page=100')
    expect(out.data).toHaveLength(100)
    expect(getMock).toHaveBeenCalledTimes(2)
  })
})
