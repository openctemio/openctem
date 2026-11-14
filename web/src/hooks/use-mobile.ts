import * as React from 'react'

const MOBILE_BREAKPOINT = 768

function subscribe(onChange: () => void) {
  // Absent in some non-browser environments (jsdom); width is then fixed.
  if (typeof window.matchMedia !== 'function') return () => {}
  const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`)
  mql.addEventListener('change', onChange)
  return () => mql.removeEventListener('change', onChange)
}

const isMobileNow = () => window.innerWidth < MOBILE_BREAKPOINT
const isMobileOnServer = () => false

/**
 * Whether the viewport is phone-sized (under `md`). The server and hydration
 * render say `false`; anything mounted after hydration (a drawer opened by a
 * click) reads the real width on its first render, so it never renders its
 * desktop form first and then swaps.
 */
export function useIsMobile() {
  return React.useSyncExternalStore(subscribe, isMobileNow, isMobileOnServer)
}

/** From here up the app sidebar shows expanded; below it (down to 768) it is the icon rail. */
export const RAIL_BREAKPOINT = 1024

function subscribeTablet(onChange: () => void) {
  if (typeof window.matchMedia !== 'function') return () => {}
  const mql = window.matchMedia(
    `(min-width: ${MOBILE_BREAKPOINT}px) and (max-width: ${RAIL_BREAKPOINT - 1}px)`
  )
  mql.addEventListener('change', onChange)
  return () => mql.removeEventListener('change', onChange)
}

/**
 * Whether the viewport is between the phone and the full desktop shell
 * (768-1023 px), where the app sidebar is the 48 px icon rail and opens as a
 * sheet over the page. The server and hydration render say `false`.
 */
export function useIsTablet() {
  return React.useSyncExternalStore(
    subscribeTablet,
    () => window.innerWidth >= MOBILE_BREAKPOINT && window.innerWidth < RAIL_BREAKPOINT,
    () => false
  )
}

const WIDE_BREAKPOINT = 1280

function subscribeWide(onChange: () => void) {
  if (typeof window.matchMedia !== 'function') return () => {}
  const mql = window.matchMedia(`(min-width: ${WIDE_BREAKPOINT}px)`)
  mql.addEventListener('change', onChange)
  return () => mql.removeEventListener('change', onChange)
}

/**
 * Whether the viewport is `xl` or wider, for layouts that move a block (an
 * editor's side rail) rather than restyle it: render the block once, in the
 * place this says, so its fields and ids exist once. The server says `false`.
 */
export function useIsWide() {
  return React.useSyncExternalStore(
    subscribeWide,
    () => window.innerWidth >= WIDE_BREAKPOINT,
    () => false
  )
}
