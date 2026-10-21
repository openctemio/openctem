import * as React from 'react'
import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, afterEach } from 'vitest'

import { useFullscreen } from './use-fullscreen'

function setup(opts: { enabled: boolean; reject?: boolean }) {
  const el = document.createElement('div')
  let current: Element | null = null
  Object.defineProperty(document, 'fullscreenEnabled', { value: opts.enabled, configurable: true })
  Object.defineProperty(document, 'fullscreenElement', {
    get: () => current,
    configurable: true,
  })
  document.exitFullscreen = async () => {
    current = null
    document.dispatchEvent(new Event('fullscreenchange'))
  }
  el.requestFullscreen = async () => {
    if (opts.reject) throw new Error('blocked')
    current = el
    document.dispatchEvent(new Event('fullscreenchange'))
  }
  const ref = { current: el } as React.RefObject<HTMLDivElement>
  return {
    el,
    ref,
    leaveByBrowser: () => {
      current = null
      document.dispatchEvent(new Event('fullscreenchange'))
    },
  }
}

describe('useFullscreen', () => {
  afterEach(() => {
    Reflect.deleteProperty(document, 'fullscreenEnabled')
    Reflect.deleteProperty(document, 'fullscreenElement')
  })

  it('enters and exits native full screen', async () => {
    const { ref } = setup({ enabled: true })
    const { result } = renderHook(() => useFullscreen(ref))
    await act(async () => result.current.toggle())
    expect(result.current.isFullscreen).toBe(true)
    expect(result.current.isOverlay).toBe(false)
    await act(async () => result.current.toggle())
    expect(result.current.isFullscreen).toBe(false)
  })

  it('syncs when the browser leaves full screen on Esc', async () => {
    const { ref, leaveByBrowser } = setup({ enabled: true })
    const { result } = renderHook(() => useFullscreen(ref))
    await act(async () => result.current.toggle())
    act(() => leaveByBrowser())
    expect(result.current.isFullscreen).toBe(false)
  })

  it('falls back to the overlay when the API is unavailable, Esc exits', async () => {
    const { ref } = setup({ enabled: false })
    const { result } = renderHook(() => useFullscreen(ref))
    await act(async () => result.current.toggle())
    expect(result.current.isOverlay).toBe(true)
    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    })
    expect(result.current.isFullscreen).toBe(false)
  })

  it('falls back to the overlay when the browser blocks the request', async () => {
    const { ref } = setup({ enabled: true, reject: true })
    const { result } = renderHook(() => useFullscreen(ref))
    await act(async () => result.current.toggle())
    expect(result.current.isOverlay).toBe(true)
  })
})
