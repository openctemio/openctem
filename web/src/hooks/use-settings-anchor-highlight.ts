'use client'

import { useEffect } from 'react'
import { usePathname } from 'next/navigation'
import { SETTINGS_ANCHOR_EVENT } from '@/config/settings-search'

const ANCHOR_ID = /^[a-z0-9][a-z0-9-]{0,63}$/

/**
 * Scrolls to the setting named by the URL hash and outlines it for a moment
 * (`data-anchor-highlight`, styled in globals.css), then moves focus there so
 * keyboard and screen-reader users land on it too. Runs on every settings
 * route change, on hashchange, and on SETTINGS_ANCHOR_EVENT (an in-app link
 * to a hash on the page already open). Settings load after the route, so the
 * element is waited for up to 4 s.
 */
export function useSettingsAnchorHighlight() {
  const pathname = usePathname()
  useEffect(() => {
    let raf = 0
    let timer = 0
    let cancelled = false
    const run = () => {
      cancelAnimationFrame(raf)
      const id = decodeURIComponent(window.location.hash.slice(1))
      if (!ANCHOR_ID.test(id)) return
      const started = Date.now()
      const tick = () => {
        if (cancelled) return
        const el = document.getElementById(id)
        if (!el) {
          if (Date.now() - started < 4000) raf = requestAnimationFrame(tick)
          return
        }
        const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
        el.scrollIntoView({ block: 'center', behavior: reduce ? 'auto' : 'smooth' })
        if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1')
        el.focus({ preventScroll: true })
        el.removeAttribute('data-anchor-highlight')
        // Restart the animation when the same setting is opened again.
        void el.offsetWidth
        el.setAttribute('data-anchor-highlight', '')
        window.clearTimeout(timer)
        timer = window.setTimeout(() => el.removeAttribute('data-anchor-highlight'), 2600)
      }
      tick()
    }
    // An in-app link to a hash on the page already open changes the URL with
    // pushState (no hashchange): run once the router has updated it.
    const onClick = (e: MouseEvent) => {
      const a = (e.target as Element | null)?.closest?.('a[href*="#"]') as HTMLAnchorElement | null
      if (!a) return
      const url = new URL(a.href, window.location.href)
      if (url.origin === window.location.origin && url.pathname === window.location.pathname) {
        window.setTimeout(run, 50)
      }
    }
    run()
    document.addEventListener('click', onClick)
    window.addEventListener('hashchange', run)
    window.addEventListener(SETTINGS_ANCHOR_EVENT, run)
    return () => {
      cancelled = true
      cancelAnimationFrame(raf)
      window.clearTimeout(timer)
      document.removeEventListener('click', onClick)
      window.removeEventListener('hashchange', run)
      window.removeEventListener(SETTINGS_ANCHOR_EVENT, run)
    }
  }, [pathname])
}
