import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { get } from '@/lib/api/client'
import { scanApprovalKeys, useScanApprovals } from '../scan-approval-hooks'

// The inbox read once stopped at the first 100 requests and ignored the total:
// the queue now reads the page it shows and keeps the total for its pager.
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
      url.includes('page=6') ? page(125, 5, 130) : page(0, 25, 130)
    )
  })

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <SWRConfig value={{ provider: () => new Map() }}>{children}</SWRConfig>
  )

  it('reads the page asked for and keeps the total, so the last request is reachable', async () => {
    const { result, rerender } = renderHook(
      ({ p }: { p: number }) => useScanApprovals('pending', p, 25),
      { wrapper, initialProps: { p: 1 } }
    )
    await waitFor(() => expect(result.current.data?.data).toHaveLength(25))
    expect(result.current.data?.total).toBe(130)
    expect(vi.mocked(get).mock.calls[0][0]).toContain('status=pending&page=1&per_page=25')
    rerender({ p: 6 })
    await waitFor(() => expect(result.current.data?.data).toHaveLength(5))
    expect(result.current.data?.data[4].id).toBe('r129')
  })

  it('never asks the API for more than its cap of 100 a page', () => {
    expect(scanApprovalKeys.list('', 1, 500)).toContain('per_page=100')
  })
})
