import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useAppHost, useAppOrigin } from '../use-app-origin'

describe('useAppOrigin / useAppHost', () => {
  it('state the host the console is served from', () => {
    expect(renderHook(() => useAppOrigin()).result.current).toBe(window.location.origin)
    expect(renderHook(() => useAppHost()).result.current).toBe(window.location.host)
  })
})
