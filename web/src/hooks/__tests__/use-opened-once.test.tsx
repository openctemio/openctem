import { renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { useOpenedOnce } from '../use-opened-once'

describe('useOpenedOnce', () => {
  it('stays false until the first open, then true for good', () => {
    const { result, rerender } = renderHook(({ open }) => useOpenedOnce(open), {
      initialProps: { open: false },
    })
    expect(result.current).toBe(false)
    rerender({ open: false })
    expect(result.current).toBe(false)
    rerender({ open: true })
    expect(result.current).toBe(true)
    rerender({ open: false })
    expect(result.current).toBe(true)
  })

  it('is true at once when it starts open', () => {
    const { result } = renderHook(() => useOpenedOnce(true))
    expect(result.current).toBe(true)
  })
})
