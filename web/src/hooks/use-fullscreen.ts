'use client'

import * as React from 'react'

/**
 * Full-screen toggle for one element.
 *
 * Uses the browser Fullscreen API on the element. When the API is missing or
 * the browser refuses the request, falls back to a full-viewport overlay: the
 * hook reports `isFullscreen` and `isOverlay` so the caller can add
 * `fixed inset-0 z-50` classes. Esc exits in both modes (the browser handles
 * it for the native mode).
 */
export function useFullscreen<T extends HTMLElement>(ref: React.RefObject<T | null>) {
  const [mode, setMode] = React.useState<'off' | 'native' | 'overlay'>('off')

  // Keep state in sync when the browser leaves native full screen itself (Esc).
  React.useEffect(() => {
    const onChange = () => {
      if (document.fullscreenElement === ref.current) {
        setMode('native')
      } else {
        setMode((m) => (m === 'native' ? 'off' : m))
      }
    }
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [ref])

  // Esc leaves the overlay fallback.
  React.useEffect(() => {
    if (mode !== 'overlay') return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMode('off')
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [mode])

  const enter = React.useCallback(async () => {
    const el = ref.current
    if (el && document.fullscreenEnabled && typeof el.requestFullscreen === 'function') {
      try {
        await el.requestFullscreen()
        setMode('native')
        return
      } catch {
        // Blocked by the browser or a policy: use the overlay instead.
      }
    }
    setMode('overlay')
  }, [ref])

  const exit = React.useCallback(async () => {
    if (document.fullscreenElement && typeof document.exitFullscreen === 'function') {
      try {
        await document.exitFullscreen()
      } catch {
        // Already left.
      }
    }
    setMode('off')
  }, [])

  const toggle = React.useCallback(() => {
    return mode === 'off' ? enter() : exit()
  }, [mode, enter, exit])

  return { isFullscreen: mode !== 'off', isOverlay: mode === 'overlay', toggle, exit }
}
