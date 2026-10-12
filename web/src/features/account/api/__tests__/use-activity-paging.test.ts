import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import useSWR from 'swr'

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

import { useAccountActivity } from '../use-activity'

function lastParams() {
  const calls = vi.mocked(useSWR).mock.calls
  return new URL(calls[calls.length - 1][0] as string, 'http://x').searchParams
}

describe('useAccountActivity server paging (23a B20)', () => {
  beforeEach(() => vi.mocked(useSWR).mockClear())

  it('requests one 1-based server page instead of a 100-event browser slice', () => {
    renderHook(() => useAccountActivity('u1', 12, 10))
    const p = lastParams()
    expect(p.get('page')).toBe('12')
    expect(p.get('per_page')).toBe('10')
  })

  it('never asks for page 0', () => {
    renderHook(() => useAccountActivity('u1', 0))
    expect(lastParams().get('page')).toBe('1')
  })

  it('no request without a user (never an unscoped query)', () => {
    renderHook(() => useAccountActivity(undefined))
    const calls = vi.mocked(useSWR).mock.calls
    expect(calls[calls.length - 1][0]).toBeNull()
  })
})
