import { describe, it, expect, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'

let routerPathname = '/findings'
vi.mock('next/navigation', () => ({
  usePathname: () => routerPathname,
}))

import { useUrlSettled, useUrlParam } from '../use-url-param'

describe('useUrlSettled', () => {
  it('is false while the address bar still holds the previous page, true once it catches up', () => {
    routerPathname = '/findings'
    window.history.replaceState(null, '', '/assets?sort=-risk_score')
    const { result } = renderHook(() => ({ settled: useUrlSettled(), sort: useUrlParam('sort') }))
    expect(result.current.settled).toBe(false)
    // What the page would have sent: the previous page's sort.
    expect(result.current.sort).toBe('-risk_score')

    act(() => {
      window.history.pushState(null, '', '/findings?asset_id=x')
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    expect(result.current.settled).toBe(true)
    expect(result.current.sort).toBeNull()
  })

  it('compares percent-encoded and decoded pathnames as equal', () => {
    routerPathname = '/assets/a b'
    window.history.replaceState(null, '', '/assets/a%20b')
    const { result } = renderHook(() => useUrlSettled())
    expect(result.current).toBe(true)
  })
})
