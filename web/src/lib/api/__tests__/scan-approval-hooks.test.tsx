import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { get } from '@/lib/api/client'
import { useScanApprovals } from '../scan-approval-hooks'

// The inbox read stopped at the first 100 requests and ignored the total.
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))

const page = (from: number, n: number, total: number) => ({
  data: Array.from({ length: n }, (_, i) => ({ id: `r${from + i}` })),
  total,
})

describe('useScanApprovals', () => {
  beforeEach(() => {
    vi.mocked(get).mockReset()
    vi.mocked(get).mockImplementation(async (url: string) =>
      url.includes('page=2') ? page(100, 30, 130) : page(0, 100, 130)
    )
  })

  it('pages by 100 and appends the next page on loadMore', async () => {
    const { result } = renderHook(() => useScanApprovals('pending'), {
      wrapper: ({ children }) => (
        <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
      ),
    })
    await waitFor(() => expect(result.current.data?.data).toHaveLength(100))
    expect(result.current.data?.total).toBe(130)
    expect(vi.mocked(get).mock.calls[0][0]).toContain('page=1&per_page=100')
    act(() => result.current.loadMore())
    await waitFor(() => expect(result.current.data?.data).toHaveLength(130))
    expect(vi.mocked(get).mock.calls.some((c) => String(c[0]).includes('page=2'))).toBe(true)
  })
})
