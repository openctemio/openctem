/**
 * Placement rules shared by every anchored floating surface of the kit (menu,
 * popover, select list, tooltip): how near a screen edge it may come, which
 * edge of its trigger it lines up with, and what it must stay clear of. The
 * rules are listed in `web/docs/ui-style-contract.md` ("Floating surfaces").
 */
import * as React from 'react'

/**
 * How close a floating surface (menu, popover, select list, tooltip, date
 * picker) may come to a screen edge: the page gutter (`px-4` on a phone).
 *
 * Without it Radix lets a popup slide flush against the edge: a right-aligned
 * menu whose trigger sits at the left of a phone row (the page-header More
 * after the actions wrap) opened at x = 0. Every kit wrapper passes it, so a
 * popup is never nearer an edge than the page content is.
 */
export const FLOATING_COLLISION_PADDING = 16

/**
 * The one exception: a menu opened from the phone top bar is a sheet as wide
 * as the screen less the bar's own 8 px padding, its end under its trigger
 * (`PHONE_BAR_MENU` in `components/layout/header-controls.ts`). It keeps the
 * bar's gutter rather than the page's.
 */
export const PHONE_BAR_COLLISION_PADDING = 8

export type FloatingAlign = 'start' | 'end'
export type FloatingSide = 'top' | 'right' | 'bottom' | 'left'
export type FloatingPadding = { top: number; right: number; bottom: number; left: number }

/**
 * Which edge of its trigger a popup lines up with when the call site does not
 * say: the trigger's centre in the inline-start half of the viewport lines it
 * up with the start edge (the popup grows towards the far side, where the
 * room is), otherwise with the end edge. Logical, so a right-to-left page
 * mirrors it.
 */
export function chooseAlign(
  trigger: { left: number; right: number },
  viewportWidth: number,
  dir: 'ltr' | 'rtl' = 'ltr'
): FloatingAlign {
  const centre = (trigger.left + trigger.right) / 2
  const half = viewportWidth / 2
  const inStartHalf = dir === 'rtl' ? centre > half : centre < half
  return inStartHalf ? 'start' : 'end'
}

/** What a popup must keep clear of, measured when it opens. */
export type FloatingEnvironment = {
  /** `env(safe-area-inset-*)`: notch, rounded corners, home indicator. */
  safe: FloatingPadding
  /**
   * Height of fixed rows along the bottom of the visible viewport (the bulk
   * bar of selected rows), measured from the viewport's bottom edge.
   */
  bottomObstruction: number
}

export const NO_FLOATING_ENVIRONMENT: FloatingEnvironment = {
  safe: { top: 0, right: 0, bottom: 0, left: 0 },
  bottomObstruction: 0,
}

/**
 * Collision padding of a popup: the gutter on every side, at least the safe
 * area, and above a fixed bottom row the row plus the gutter, so a menu never
 * opens under (or over) the bar the user is working in.
 */
export function floatingPadding(base: number, env: FloatingEnvironment): FloatingPadding {
  return {
    top: Math.max(base, env.safe.top),
    right: Math.max(base, env.safe.right),
    bottom:
      env.bottomObstruction > 0 ? env.bottomObstruction + base : Math.max(base, env.safe.bottom),
    left: Math.max(base, env.safe.left),
  }
}

// Fixed bottom rows registered by `useFloatingObstruction`.
const obstructions = new Set<HTMLElement>()

/**
 * Registers a fixed row along the bottom of the screen (the bulk bar of
 * selected rows) while it is shown: popups opened meanwhile keep the gutter
 * above it instead of opening under it.
 */
export function useFloatingObstruction(
  ref: React.RefObject<HTMLElement | null>,
  active = true
): void {
  React.useEffect(() => {
    const el = ref.current
    if (!active || !el) return
    obstructions.add(el)
    return () => {
      obstructions.delete(el)
    }
  }, [ref, active])
}

let safeAreaProbe: HTMLDivElement | null = null

function px(value: string): number {
  const n = parseFloat(value)
  return Number.isFinite(n) ? n : 0
}

function measureSafeArea(): FloatingPadding {
  if (!safeAreaProbe || !safeAreaProbe.isConnected) {
    // One hidden element whose padding is the safe area: the only way to read
    // env() from script. Set through CSSOM (allowed by the style CSP).
    const probe = document.createElement('div')
    probe.setAttribute('aria-hidden', 'true')
    probe.dataset.slot = 'floating-safe-area-probe'
    const s = probe.style
    s.setProperty('position', 'fixed')
    s.setProperty('top', '0')
    s.setProperty('left', '0')
    s.setProperty('width', '0')
    s.setProperty('height', '0')
    s.setProperty('visibility', 'hidden')
    s.setProperty('pointer-events', 'none')
    s.setProperty('padding-top', 'env(safe-area-inset-top, 0px)')
    s.setProperty('padding-right', 'env(safe-area-inset-right, 0px)')
    s.setProperty('padding-bottom', 'env(safe-area-inset-bottom, 0px)')
    s.setProperty('padding-left', 'env(safe-area-inset-left, 0px)')
    document.body.appendChild(probe)
    safeAreaProbe = probe
  }
  const cs = getComputedStyle(safeAreaProbe)
  return {
    top: px(cs.paddingTop),
    right: px(cs.paddingRight),
    bottom: px(cs.paddingBottom),
    left: px(cs.paddingLeft),
  }
}

/** Height of the registered fixed rows above the bottom of the visible viewport. */
export function measureBottomObstruction(): number {
  // The visible viewport: with the on-screen keyboard up it ends above it.
  // The positioning engine already clips popups to the visual viewport, so
  // only rows above its bottom edge count here.
  const vv = window.visualViewport
  const bottom = vv ? vv.offsetTop + vv.height : window.innerHeight
  let inset = 0
  for (const el of obstructions) {
    if (!el.isConnected) continue
    const r = el.getBoundingClientRect()
    if (r.height === 0 || r.top >= bottom) continue
    inset = Math.max(inset, bottom - r.top)
  }
  return Math.round(inset)
}

/** Safe area and fixed bottom rows, measured now. */
export function measureFloatingEnvironment(): FloatingEnvironment {
  return { safe: measureSafeArea(), bottomObstruction: measureBottomObstruction() }
}

function sameEnvironment(a: FloatingEnvironment, b: FloatingEnvironment): boolean {
  return (
    a.bottomObstruction === b.bottomObstruction &&
    a.safe.top === b.safe.top &&
    a.safe.right === b.safe.right &&
    a.safe.bottom === b.safe.bottom &&
    a.safe.left === b.safe.left
  )
}

type FloatingAnchorState = {
  /** Records the trigger; called by the kit's Trigger wrappers. */
  setTrigger: (el: HTMLElement | null) => void
  /** Records a `PopoverAnchor`, when there is one: the popup is placed against it. */
  setAnchor: (el: HTMLElement | null) => void
  /** Edge to line up with, from where the trigger was when the popup opened. */
  align: FloatingAlign | undefined
  env: FloatingEnvironment
}

const FloatingAnchorContext = React.createContext<FloatingAnchorState | null>(null)

/**
 * Root state of one floating surface: measures its trigger and the screen each
 * time it opens (and on resize while open), so the content can pick its
 * alignment and padding. Nothing is measured while it is closed.
 */
function useFloatingAnchorState(open: boolean): FloatingAnchorState {
  const triggerRef = React.useRef<HTMLElement | null>(null)
  const anchorRef = React.useRef<HTMLElement | null>(null)
  const [align, setAlign] = React.useState<FloatingAlign | undefined>(undefined)
  const [env, setEnv] = React.useState<FloatingEnvironment>(NO_FLOATING_ENVIRONMENT)

  const setTrigger = React.useCallback((el: HTMLElement | null) => {
    triggerRef.current = el
  }, [])
  const setAnchor = React.useCallback((el: HTMLElement | null) => {
    anchorRef.current = el
  }, [])

  React.useLayoutEffect(() => {
    if (!open) return
    const measure = () => {
      const el = anchorRef.current ?? triggerRef.current
      if (el) {
        const dir = getComputedStyle(el).direction === 'rtl' ? 'rtl' : 'ltr'
        setAlign(chooseAlign(el.getBoundingClientRect(), window.innerWidth, dir))
      }
      const next = measureFloatingEnvironment()
      setEnv((prev) => (sameEnvironment(prev, next) ? prev : next))
    }
    measure()
    const vv = window.visualViewport
    window.addEventListener('resize', measure)
    vv?.addEventListener('resize', measure)
    return () => {
      window.removeEventListener('resize', measure)
      vv?.removeEventListener('resize', measure)
    }
  }, [open])

  return React.useMemo(
    () => ({ setTrigger, setAnchor, align, env }),
    [setTrigger, setAnchor, align, env]
  )
}

/**
 * Wraps a kit Root (`DropdownMenu`, `Popover`, `Select`): mirrors its open
 * state without taking control of it and provides the anchor state.
 */
export function useFloatingRoot<P extends { open?: boolean; defaultOpen?: boolean }>(
  props: P & { onOpenChange?: (open: boolean) => void }
) {
  const { open: openProp, defaultOpen, onOpenChange } = props
  const [openMirror, setOpenMirror] = React.useState(defaultOpen ?? false)
  const handleOpenChange = React.useCallback(
    (next: boolean) => {
      setOpenMirror(next)
      onOpenChange?.(next)
    },
    [onOpenChange]
  )
  const state = useFloatingAnchorState(openProp ?? openMirror)
  return { state, onOpenChange: handleOpenChange }
}

export function FloatingAnchorProvider({
  state,
  children,
}: {
  state: FloatingAnchorState
  children: React.ReactNode
}) {
  return React.createElement(FloatingAnchorContext.Provider, { value: state }, children)
}

/**
 * Records the element a popup is placed against: a kit Trigger wrapper (or
 * `PopoverAnchor`) calls it from its ref, next to the caller's own ref.
 */
export function useFloatingAnchorSetter(
  kind: 'trigger' | 'anchor' = 'trigger'
): (el: HTMLElement | null) => void {
  const ctx = React.useContext(FloatingAnchorContext)
  return (kind === 'anchor' ? ctx?.setAnchor : ctx?.setTrigger) ?? noop
}

function noop() {}

const CROSS_AXIS_SIDES = new Set<string>(['left', 'right'])

/**
 * Alignment, collision padding and the max-width variable of a kit Content
 * wrapper. A call site that passes `align` keeps it; a popup placed beside
 * its trigger (side left/right) keeps the caller's alignment too, since the
 * half-of-the-screen rule is about the horizontal axis.
 */
export function useFloatingContent({
  align,
  side,
  collisionPadding,
  fallbackAlign,
}: {
  align?: 'start' | 'center' | 'end'
  side?: FloatingSide
  collisionPadding?: number | Partial<FloatingPadding>
  /** Alignment before the first measurement, or outside a kit Root. */
  fallbackAlign: 'start' | 'center' | 'end'
}) {
  const ctx = React.useContext(FloatingAnchorContext)
  const env = ctx?.env ?? NO_FLOATING_ENVIRONMENT
  const padding = React.useMemo<number | Partial<FloatingPadding>>(() => {
    if (typeof collisionPadding === 'object') return collisionPadding
    return floatingPadding(collisionPadding ?? FLOATING_COLLISION_PADDING, env)
  }, [collisionPadding, env])
  const resolvedAlign =
    align ?? (side && CROSS_AXIS_SIDES.has(side) ? undefined : ctx?.align) ?? fallbackAlign
  const gutterX =
    typeof padding === 'number' ? padding * 2 : (padding.left ?? 0) + (padding.right ?? 0)
  const style = React.useMemo(
    () => ({ '--float-gutter-x': `${gutterX}px` }) as React.CSSProperties,
    [gutterX]
  )
  return { align: resolvedAlign, collisionPadding: padding, style }
}

/**
 * Classes every anchored surface shares: never wider than the screen less its
 * gutters (reflow at 320 px), no motion when the user asked for less.
 */
export const FLOATING_SURFACE_CLASSES =
  'max-w-[calc(100vw_-_var(--float-gutter-x,2rem))] motion-reduce:animate-none'
