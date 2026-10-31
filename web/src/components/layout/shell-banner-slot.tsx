'use client'

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { getCookie } from '@/lib/cookies'
import { env } from '@/lib/env'

const KEY_PREFIX = 'openctem.shellBannerHeight.'

function storageKey(): string {
  // Per organization: the support-access banner is per organization.
  return KEY_PREFIX + (getCookie(env.cookies.tenant) ?? '')
}

function readHeight(): number {
  try {
    const n = Number(window.sessionStorage.getItem(storageKey()))
    return Number.isFinite(n) && n > 0 && n < 1000 ? n : 0
  } catch {
    return 0
  }
}

function writeHeight(px: number) {
  try {
    if (px > 0) window.sessionStorage.setItem(storageKey(), String(Math.round(px)))
    else window.sessionStorage.removeItem(storageKey())
  } catch {
    // Storage unavailable: the banners may move the page once on reload.
  }
}

/**
 * The place under the header for the shell's banners (platform notices,
 * support access). Within a session the page renders before the session
 * bootstrap that carries the banners has answered, so a banner used to appear
 * a moment later and push the whole page down (a layout shift of 0.12 to 0.16
 * on every page on a phone). While the bootstrap is pending, the slot keeps
 * the height its banners had on the last page of this session, so they land
 * in space already held. Only that number is stored (session storage, per
 * organization), never what a banner says.
 */
export function ShellBannerSlot({ children }: { children: ReactNode }) {
  const pending = useBootstrapPending()
  const ref = useRef<HTMLDivElement>(null)
  const [reserved, setReserved] = useState(0)

  // Read before paint (not in the first render: the server renders 0, and
  // hydration must match).
  useLayoutEffect(() => {
    if (pending) setReserved(readHeight())
  }, [pending])

  useEffect(() => {
    const el = ref.current
    if (pending || !el) return
    writeHeight(el.offsetHeight)
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => writeHeight(el.offsetHeight))
    ro.observe(el)
    return () => ro.disconnect()
  }, [pending])

  return (
    <div
      ref={ref}
      data-slot="shell-banners"
      style={pending && reserved > 0 ? { minHeight: reserved } : undefined}
    >
      {children}
    </div>
  )
}
