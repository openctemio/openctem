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
 * Width of a menu: its content's, between a floor and a ceiling. The floor is
 * the trigger's width or 128 px (160 px when its items carry icons), the
 * ceiling 360 px or the screen less both gutters. A call site sets a width of
 * its own only when the content needs one (`floating-width-guard.test.ts`).
 */
export const FLOATING_MENU_MIN_WIDTH = 128
export const FLOATING_MENU_MIN_WIDTH_ICONS = 160
export const FLOATING_MENU_MAX_WIDTH = 360

/**
 * How far inside a drawer, sheet or dialog a popup opened from it stays from
 * that overlay's edges (it is placed within the overlay when it fits).
 */
export const FLOATING_OVERLAY_INSET = 8

/** The horizontal room a popup may use, in viewport coordinates. */
export type FloatingBounds = { left: number; right: number }

// Half a pixel of rounding either way.
const FIT_TOLERANCE = 0.5

/**
 * Which edge of its trigger a popup lines up with when the call site does not
 * say. The start edge (the popup's left edge on the trigger's left edge, in a
 * left-to-right page), unless the popup would then cross the end of the room
 * it has (the screen less its gutter, or the drawer it was opened from): then
 * the end edge, when that fits. When neither fits, the edge with more room;
 * the positioning engine shifts it the rest of the way. So a trigger at the
 * end of its row (a row's "..." button, the page header's More) ends up
 * end-aligned because the start would collide, not because of where on the
 * screen it is. Logical, so a right-to-left page mirrors it.
 */
export function chooseAlign(
  trigger: { left: number; right: number },
  width: number,
  bounds: FloatingBounds,
  dir: 'ltr' | 'rtl' = 'ltr'
): FloatingAlign {
  const rtl = dir === 'rtl'
  // Room from each candidate edge of the trigger to the far side of the bounds.
  const roomStart = rtl ? trigger.right - bounds.left : bounds.right - trigger.left
  const roomEnd = rtl ? bounds.right - trigger.left : trigger.right - bounds.left
  if (width <= roomStart + FIT_TOLERANCE) return 'start'
  if (width <= roomEnd + FIT_TOLERANCE) return 'end'
  return roomStart >= roomEnd ? 'start' : 'end'
}

/** The drawer, sheet, dialog or popover an element sits in, if any. */
export function containingOverlay(el: Element): Element | null {
  return el.closest('[role="dialog"],[role="alertdialog"]')
}

/**
 * The room a popup has across the screen: the viewport less its padding, and
 * inside the overlay its trigger sits in (less `FLOATING_OVERLAY_INSET`) when
 * the popup fits there. `overlay` is true when the overlay bounds it.
 */
export function floatingBounds(
  viewportWidth: number,
  padding: { left: number; right: number },
  width: number,
  overlay: { left: number; right: number } | null
): FloatingBounds & { overlay: boolean } {
  const screen = { left: padding.left, right: viewportWidth - padding.right }
  if (!overlay) return { ...screen, overlay: false }
  const inner = {
    left: Math.max(screen.left, overlay.left + FLOATING_OVERLAY_INSET),
    right: Math.min(screen.right, overlay.right - FLOATING_OVERLAY_INSET),
  }
  if (width > inner.right - inner.left + FIT_TOLERANCE) return { ...screen, overlay: false }
  return { ...inner, overlay: true }
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

type FloatingAnchorState = {
  /** Records the trigger; called by the kit's Trigger wrappers. */
  setTrigger: (el: HTMLElement | null) => void
  /** Records a `PopoverAnchor`, when there is one: the popup is placed against it. */
  setAnchor: (el: HTMLElement | null) => void
  /** The element the popup is placed against: the anchor, else the trigger. */
  getAnchor: () => HTMLElement | null
}

const FloatingAnchorContext = React.createContext<FloatingAnchorState | null>(null)

/** Root state of one floating surface: where its trigger (or anchor) is. */
function useFloatingAnchorState(): FloatingAnchorState {
  const triggerRef = React.useRef<HTMLElement | null>(null)
  const anchorRef = React.useRef<HTMLElement | null>(null)
  return React.useMemo(
    () => ({
      setTrigger: (el: HTMLElement | null) => {
        triggerRef.current = el
      },
      setAnchor: (el: HTMLElement | null) => {
        anchorRef.current = el
      },
      getAnchor: () => anchorRef.current ?? triggerRef.current,
    }),
    []
  )
}

/**
 * Wraps a kit Root (`DropdownMenu`, `Popover`, `Select`) and provides the
 * anchor state its Trigger records and its Content measures.
 */
export function useFloatingRoot<P extends { open?: boolean; defaultOpen?: boolean }>(
  props: P & { onOpenChange?: (open: boolean) => void }
) {
  const state = useFloatingAnchorState()
  return { state, onOpenChange: props.onOpenChange }
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

type Placement = { align: FloatingAlign | undefined; padding: FloatingPadding | null }

function samePlacement(a: Placement, b: Placement): boolean {
  if (a.align !== b.align) return false
  if (a.padding === b.padding) return true
  if (!a.padding || !b.padding) return false
  return (
    a.padding.top === b.padding.top &&
    a.padding.right === b.padding.right &&
    a.padding.bottom === b.padding.bottom &&
    a.padding.left === b.padding.left
  )
}

/**
 * Alignment, collision padding, the max-width variable and the `attach`
 * callback (pass it as the Content's ref) of a kit
 * Content wrapper. Each time the popup opens (and when the screen or the
 * popup's own size changes while it is open) it measures the popup, its
 * trigger, the screen and the drawer or dialog the trigger sits in, and
 * places the popup by `chooseAlign` within that room. A call site that passes
 * `align` keeps it; a popup beside its trigger (side left/right) keeps the
 * caller's alignment too, since the rule is about the horizontal axis.
 */
export function useFloatingContent<E extends HTMLElement>({
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
  const [node, setNode] = React.useState<E | null>(null)
  // Named `attach`, not a ref: the content element is kept in state.
  const attach = React.useCallback((el: E | null) => setNode(el), [])
  const fixedPadding = typeof collisionPadding === 'object' ? collisionPadding : null
  const base = typeof collisionPadding === 'number' ? collisionPadding : FLOATING_COLLISION_PADDING
  const auto = align === undefined && !(side && CROSS_AXIS_SIDES.has(side))
  const [placement, setPlacement] = React.useState<Placement>({
    align: undefined,
    padding: null,
  })

  React.useLayoutEffect(() => {
    if (!node || fixedPadding) return
    const measure = () => {
      const env = measureFloatingEnvironment()
      const padding = floatingPadding(base, env)
      let nextAlign: FloatingAlign | undefined
      const anchor = ctx?.getAnchor()
      if (anchor?.isConnected) {
        const a = anchor.getBoundingClientRect()
        // Before the first placement the popup has no min-width from its
        // trigger yet: it is at least as wide as the trigger.
        const width = Math.max(node.getBoundingClientRect().width, a.width)
        const overlay = containingOverlay(anchor)
        const bounds = floatingBounds(
          window.innerWidth,
          padding,
          width,
          overlay ? overlay.getBoundingClientRect() : null
        )
        if (bounds.overlay) {
          padding.left = bounds.left
          padding.right = window.innerWidth - bounds.right
        }
        if (auto) {
          const dir = getComputedStyle(anchor).direction === 'rtl' ? 'rtl' : 'ltr'
          nextAlign = chooseAlign(a, width, bounds, dir)
        }
      }
      const next = { align: nextAlign, padding }
      setPlacement((prev) => (samePlacement(prev, next) ? prev : next))
    }
    measure()
    const vv = window.visualViewport
    window.addEventListener('resize', measure)
    vv?.addEventListener('resize', measure)
    // The content can change after it opens (moves that load, a filtered list).
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    observer?.observe(node)
    return () => {
      window.removeEventListener('resize', measure)
      vv?.removeEventListener('resize', measure)
      observer?.disconnect()
    }
  }, [node, fixedPadding, base, auto, ctx])

  const padding = React.useMemo<number | Partial<FloatingPadding>>(
    () => fixedPadding ?? placement.padding ?? floatingPadding(base, NO_FLOATING_ENVIRONMENT),
    [fixedPadding, placement.padding, base]
  )
  const resolvedAlign = align ?? (auto ? placement.align : undefined) ?? fallbackAlign
  const gutterX =
    typeof padding === 'number' ? padding * 2 : (padding.left ?? 0) + (padding.right ?? 0)
  const style = React.useMemo(
    () => ({ '--float-gutter-x': `${gutterX}px` }) as React.CSSProperties,
    [gutterX]
  )
  return { align: resolvedAlign, collisionPadding: padding, style, attach }
}

/**
 * Classes every anchored surface shares: never wider than the screen less its
 * gutters (reflow at 320 px), no motion when the user asked for less.
 */
export const FLOATING_SURFACE_CLASSES =
  'max-w-[calc(100vw_-_var(--float-gutter-x,2rem))] motion-reduce:animate-none'
