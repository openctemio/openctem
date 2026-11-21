/**
 * The scope page's counts: while the entries list is on screen it carries the
 * entry counts itself, so the one-row entries request is not sent again.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))

import { useScopeStatusCounts } from '../use-scope-api'

const wrapper = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

describe('useScopeStatusCounts', () => {
  beforeEach(() => {
    api.get.mockReset()
    api.get.mockResolvedValue({ data: [], status_counts: { active: 2 } })
  })

  it('reads the entry counts with their own request on other tabs', async () => {
    const { result } = renderHook(() => useScopeStatusCounts(false, true), { wrapper })
    await waitFor(() => expect(result.current.targets).toEqual({ active: 2 }))
    expect(api.get).toHaveBeenCalledWith('/api/v1/scope/targets?per_page=1&include=status_counts')
  })

  it('skips the entries request while the entries list carries the counts', async () => {
    const { result } = renderHook(() => useScopeStatusCounts(true), { wrapper })
    await waitFor(() => expect(result.current.exclusions).toEqual({ active: 2 }))
    expect(result.current.targets).toBeUndefined()
    expect(api.get).not.toHaveBeenCalledWith(expect.stringContaining('/scope/targets'))
  })

  it('reads the exclusion counts only when the page needs them', async () => {
    const { result, rerender } = renderHook(
      ({ needed }) => useScopeStatusCounts(true, needed),
      { wrapper, initialProps: { needed: false } }
    )
    await Promise.resolve()
    expect(api.get).not.toHaveBeenCalled()
    expect(result.current.isLoading).toBe(false)
    rerender({ needed: true })
    await waitFor(() => expect(result.current.exclusions).toEqual({ active: 2 }))
    expect(api.get).toHaveBeenCalledWith('/api/v1/scope/exclusions?per_page=1&include=status_counts')
  })
})
