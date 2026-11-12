'use client'

/**
 * Shared parts of the small connected visuals (the exposure flow and the
 * intake panel; api docs/architecture/dashboards.md, "Exposure flow and
 * intake"): wires drawn as plain SVG paths between measured DOM rows, the
 * focus model (hover, keyboard focus or a first tap lights an element and
 * its path and dims the rest), and the tooltip every focusable figure opens.
 *
 * Volume is the wire's width, health its line style: solid for a healthy
 * source (with a moving dash unless motion is reduced), dotted amber for a
 * stale one, dotted red for a failed one. Colour is never the only cue: the
 * row says "stale" or "failed" in words.
 */

import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from 'react'
import Link from '@/components/link'
import { KeyValueList } from '@/features/shared/components/text-layout'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import type { SourceHealth } from './types'
import { usePrefersReducedMotion } from './viz-parts'

/** A cubic wire from (x1, y1) to (x2, y2), leaving and entering horizontally. */
export function wirePath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = Math.max(24, Math.abs(x2 - x1) * 0.45)
  return `M${x1} ${y1} C${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
}

/** Wire width for a volume: 1 to 6 px, proportional to its share of the largest. */
export function wireWidth(value: number, max: number): number {
  if (max <= 0 || value <= 0) return 1
  return Math.round((1 + 5 * Math.min(1, value / max)) * 100) / 100
}

/**
 * The glow of the one focused wire or segment: a soft shadow in its own
 * colour (CSS filter, so it costs nothing until something is focused).
 */
export function focusGlow(color: string): string {
  return `drop-shadow(0 0 4px color-mix(in oklab, ${color} 60%, transparent))`
}

/** Stroke of a wire by the health of its source. */
export function wireStroke(health: SourceHealth | 'neutral' | 'bad'): {
  stroke: string
  dash?: string
} {
  switch (health) {
    case 'stale':
      return { stroke: 'var(--warning)', dash: '1 5' }
    case 'failed':
    case 'bad':
      return { stroke: 'var(--destructive)', dash: health === 'failed' ? '1 5' : undefined }
    default:
      return { stroke: 'var(--border-strong, var(--border))' }
  }
}

/** Slowest and fastest travel of a wire's light, in seconds per cycle. */
export const FLOW_SLOW_S = 3.2
export const FLOW_FAST_S = 1.1

/**
 * How long one cycle of a wire's travelling light takes: faster for more
 * volume, on a log scale (a source with ten times the findings is visibly
 * quicker, never a hundred times), from FLOW_SLOW_S for the smallest to
 * FLOW_FAST_S for the largest. Null when nothing flows: no light at all.
 */
export function flowDuration(value: number, max: number): number | null {
  if (value <= 0) return null
  const top = Math.max(value, max, 1)
  const share = top <= 1 ? 1 : Math.log1p(value) / Math.log1p(top)
  return Math.round((FLOW_SLOW_S - (FLOW_SLOW_S - FLOW_FAST_S) * share) * 100) / 100
}

/**
 * One wire of a connected visual, the same in every widget: a line from its
 * source row to its target, its width the volume.
 *
 * - healthy with data: a travelling light (a short bright dash) runs along the
 *   wire from source to target, faster for more volume (`flowDuration`);
 * - nothing received: a thin dashed line, still (the source is connected and
 *   listed, nothing flowed);
 * - stale: dotted amber, failed: dotted red, both still (the row says why);
 * - no motion at all under prefers-reduced-motion or data-motion="off", and
 *   paused while its layer is off screen or the tab is hidden (FlowWireLayer).
 * The light is a CSS animation of the dash offset (no per-frame script); the
 * numbers and the width carry the volume, the motion only repeats it.
 */
export function FlowWire({
  d,
  value,
  max,
  health,
  focused,
  focusColor = 'var(--signal)',
  className,
  wireKey,
}: {
  d: string
  value: number
  max: number
  health: SourceHealth | 'neutral' | 'bad'
  focused?: boolean
  focusColor?: string
  className?: string
  wireKey: string
}) {
  const reduced = usePrefersReducedMotion()
  const silent = health === 'ok' && value <= 0
  const base = silent
    ? { stroke: 'var(--border-strong, var(--border))', dash: '4 4' as string | undefined }
    : wireStroke(health)
  const width = silent ? 1 : wireWidth(value, max)
  const duration = health === 'ok' && !reduced ? flowDuration(value, max) : null
  return (
    <g
      className={className}
      data-wire={health}
      data-wire-key={wireKey}
      data-wire-motion={duration ? 'on' : 'off'}
    >
      <path
        d={d}
        fill="none"
        stroke={focused ? focusColor : base.stroke}
        style={focused ? { filter: focusGlow(focusColor) } : undefined}
        strokeWidth={width}
        strokeDasharray={base.dash}
        strokeLinecap="round"
      />
      {duration && (
        <path
          d={d}
          fill="none"
          stroke="var(--signal)"
          strokeOpacity={0.9}
          strokeWidth={Math.max(2, width)}
          strokeLinecap="round"
          className="animate-flow-light"
          style={{ animationDuration: `${duration}s` }}
          data-flow-duration={duration}
        />
      )}
    </g>
  )
}

/**
 * Whether an element is worth animating: on screen (IntersectionObserver)
 * and in a visible tab (document.visibilityState). Without the observer
 * (old browsers, tests) it counts as on screen.
 */
export function useInViewAndVisible(ref: RefObject<Element | null>): boolean {
  const [onScreen, setOnScreen] = useState(true)
  const [tabVisible, setTabVisible] = useState(true)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof IntersectionObserver === 'undefined') return
    const io = new IntersectionObserver((entries) => {
      const last = entries[entries.length - 1]
      if (last) setOnScreen(last.isIntersecting)
    })
    io.observe(el)
    return () => io.disconnect()
  }, [ref])
  useEffect(() => {
    if (typeof document === 'undefined') return
    const on = () => setTabVisible(document.visibilityState !== 'hidden')
    on()
    document.addEventListener('visibilitychange', on)
    return () => document.removeEventListener('visibilitychange', on)
  }, [])
  return onScreen && tabVisible
}

/**
 * The layer every connected visual draws its wires on: one SVG over the
 * visual, never hit by the pointer, hidden from assistive technology (the
 * rows and figures carry the same numbers). Off screen or in a hidden tab it
 * marks itself paused and the wires' lights stop (`data-flow-paused`, CSS
 * animation-play-state), so a dashboard below the fold costs no paint.
 */
export function FlowWireLayer({
  width,
  height,
  children,
}: {
  width: number
  height: number
  children: ReactNode
}) {
  const ref = useRef<SVGSVGElement>(null)
  const running = useInViewAndVisible(ref)
  return (
    <svg
      ref={ref}
      aria-hidden
      className="pointer-events-none absolute inset-0 h-full w-full overflow-visible"
      width={width}
      height={height}
      data-testid="flow-wires"
      data-flow-paused={running ? undefined : ''}
    >
      {children}
    </svg>
  )
}

/**
 * Width bands of a connected visual, measured on the widget's own width (a
 * container, never the viewport: a widget sits in grid cells of any size).
 * The layout classes use the same numbers as container queries
 * (`@min-[660px]`, `@min-[900px]`); the wires use the measured band, so a
 * wire is drawn only when both of its ends sit side by side.
 *
 * The widths are the visual's own (the card less its padding).
 *
 * - narrow (< 660 px): one column, no wires; every number stays a link.
 * - mid (660 to 899 px): the core and the outcomes side by side, sources as a
 *   list above; wires to the outcomes.
 * - wide (900 px and more): three columns that fill the card: sources and
 *   outcomes at a reading width against the edges, the core taking the rest
 *   (a full-width dashboard card from a 1280 px window with the sidebar open).
 */
/**
 * The thin dashed frame of a connected visual's columns (sources, outcomes,
 * the intake summary) from 660 px; a phone stacks them unframed. Wires meet
 * its edge: FRAME_INSET is its padding plus its border, from a row's edge to
 * the frame's.
 */
export const FLOW_FRAME =
  '@min-[660px]:rounded-lg @min-[660px]:border @min-[660px]:border-dashed @min-[660px]:border-border-strong @min-[660px]:p-1.5'
export const FRAME_INSET = 7

export const FLOW_MID = 660
export const FLOW_WIDE = 900

export type FlowBand = 'narrow' | 'mid' | 'wide'

export function flowBand(width: number | undefined): FlowBand {
  if (!width || width < FLOW_MID) return 'narrow'
  return width < FLOW_WIDE ? 'mid' : 'wide'
}

/** The width of an element, followed on resize (0 until measured). */
export function useElementWidth(ref: RefObject<HTMLElement | null>): number {
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setWidth(el.getBoundingClientRect().width)
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setWidth(el.getBoundingClientRect().width))
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return width
}

export interface Anchor {
  x: number
  y: number
}

/**
 * Measures the anchors of a container's wires: every element with
 * `data-wire-out` (its right edge) or `data-wire-in` (its left edge), keyed by
 * the attribute's value, relative to the container. Re-measures on resize.
 * Returns null while the wires are hidden (narrow screens: the columns stack).
 */
export function useWireAnchors(
  ref: RefObject<HTMLElement | null>,
  /** Changes when the content that is measured changes (re-measures). */
  contentKey: string | number
): {
  width: number
  height: number
  out: Record<string, Anchor>
  in: Record<string, Anchor>
} | null {
  const [layout, setLayout] = useState<ReturnType<typeof measure>>(null)
  const measure = useCallback(() => {
    const el = ref.current
    if (!el) return null
    const box = el.getBoundingClientRect()
    if (box.width === 0) return null
    const out: Record<string, Anchor> = {}
    const inn: Record<string, Anchor> = {}
    // A row's wire leaves from its main line (name and bar), never from the
    // middle of the whole row: a note line under the name (stale, failed) makes
    // the row taller without moving the line the wire belongs to.
    const centreY = (n: HTMLElement, r: DOMRect) => {
      const main = [...n.querySelectorAll<HTMLElement>('[data-wire-main]')]
        .map((m) => m.getBoundingClientRect())
        .filter((m) => m.width > 0 || m.height > 0)
      if (main.length === 0) return r.top + r.height / 2 - box.top
      const top = Math.min(...main.map((m) => m.top))
      const bottom = Math.max(...main.map((m) => m.bottom))
      return (top + bottom) / 2 - box.top
    }
    // An anchor outside the card (a row scrolled or clipped out, a stale
    // measurement) has no wire: a wire never runs off the card.
    const inside = (y: number) => y >= 0 && y <= box.height
    el.querySelectorAll<HTMLElement>('[data-wire-out]').forEach((n) => {
      const r = n.getBoundingClientRect()
      // A row that is not laid out (no size) has no anchor: no wire, never a default point.
      if (r.width === 0 && r.height === 0) return
      const y = centreY(n, r)
      if (!inside(y)) return
      out[n.dataset.wireOut ?? ''] = { x: r.right - box.left, y }
    })
    el.querySelectorAll<HTMLElement>('[data-wire-in]').forEach((n) => {
      const r = n.getBoundingClientRect()
      if (r.width === 0 && r.height === 0) return
      const y = r.top + r.height / 2 - box.top
      if (!inside(y)) return
      inn[n.dataset.wireIn ?? ''] = { x: r.left - box.left, y }
    })
    return { width: box.width, height: box.height, out, in: inn }
  }, [ref])

  useLayoutEffect(() => {
    // contentKey is a re-measure trigger, not read here.
    void contentKey
    const el = ref.current
    let gone = false
    // Rows that slide to a new place (the ranked bars' FLIP) are measured where
    // the slide starts, not where they settle: measure again when every script
    // animation under the container has finished (CSS animations, such as the
    // wires' own dash, never end and never move a row).
    const settle = () => {
      const running = (el?.getAnimations?.({ subtree: true }) ?? []).filter(
        (a) => !(typeof CSSAnimation !== 'undefined' && a instanceof CSSAnimation)
      )
      if (running.length === 0) return
      void Promise.allSettled(running.map((a) => a.finished)).then(() => {
        if (!gone) setLayout(measure())
      })
    }
    // Every anchor row is watched too: a row that grows or shrinks (a stale
    // note line appears on a data refresh) moves the rows below it without
    // changing the container's size, which the container's observer misses.
    const watched = new Set<Element>()
    const roRef: { current: ResizeObserver | null } = { current: null }
    const watchAnchors = () => {
      const ro = roRef.current
      if (!el || !ro) return
      const now = new Set(el.querySelectorAll('[data-wire-out],[data-wire-in],[data-wire-main]'))
      watched.forEach((n) => {
        if (!now.has(n)) {
          ro.unobserve(n)
          watched.delete(n)
        }
      })
      now.forEach((n) => {
        if (!watched.has(n)) {
          ro.observe(n)
          watched.add(n)
        }
      })
    }
    const remeasure = () => {
      setLayout(measure())
      watchAnchors()
      settle()
    }
    // Web fonts change text height and width once loaded.
    void document.fonts?.ready?.then(() => {
      if (!gone) remeasure()
    })
    remeasure()
    if (!el || typeof ResizeObserver === 'undefined') {
      return () => {
        gone = true
      }
    }
    const ro = new ResizeObserver(remeasure)
    roRef.current = ro
    ro.observe(el)
    watchAnchors()
    // The anchors are the rows rendered right now: a row folded or listed by
    // the user (ranked bars' "with nothing" line) changes them without
    // changing the container's width, so a change of the anchor set re-measures.
    // Watching the set (not every mutation) keeps the wires' own svg out of the loop.
    const sig = () =>
      [...el.querySelectorAll<HTMLElement>('[data-wire-out],[data-wire-in]')]
        .map((n) => n.dataset.wireOut ?? n.dataset.wireIn)
        .join('\u0000')
    let last = sig()
    const mo =
      typeof MutationObserver === 'undefined'
        ? null
        : new MutationObserver(() => {
            const next = sig()
            if (next === last) return
            last = next
            remeasure()
          })
    mo?.observe(el, { childList: true, subtree: true })
    return () => {
      gone = true
      ro.disconnect()
      mo?.disconnect()
    }
  }, [ref, measure, contentKey])
  return layout
}

/**
 * The focus model of a connected visual. `bind(key)` gives an element the
 * handlers that light it: hover, keyboard focus, and on touch a first tap
 * (the second tap follows the link). Escape, leaving the visual with the
 * pointer or moving focus out of it clears.
 */
export function useFlowFocus(containerRef: RefObject<HTMLElement | null>) {
  const [active, setActive] = useState<string | null>(null)
  const [anchor, setAnchor] = useState<{ el: DOMRect; box: DOMRect } | null>(null)
  const pointer = useRef<string>('mouse')
  const tipId = useId()

  const clear = useCallback(() => {
    setActive(null)
    setAnchor(null)
  }, [])

  useEffect(() => {
    if (!active) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') clear()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [active, clear])

  const open = useCallback(
    (key: string, el: Element) => {
      setActive(key)
      const box = containerRef.current?.getBoundingClientRect()
      setAnchor(box ? { el: el.getBoundingClientRect(), box } : null)
    },
    [containerRef]
  )

  const bind = useCallback(
    // anchorFrom: a selector of an ancestor the tooltip sits beside (the
    // ring for an arc), so it never covers the figure it explains.
    (key: string, anchorFrom?: string) => {
      const at = (el: Element) => (anchorFrom ? (el.closest(anchorFrom) ?? el) : el)
      return {
        'data-k': key,
        onPointerDown: (e: React.PointerEvent) => {
          pointer.current = e.pointerType
        },
        onMouseEnter: (e: React.MouseEvent) => open(key, at(e.currentTarget)),
        onFocus: (e: React.FocusEvent) => open(key, at(e.currentTarget)),
        onClick: (e: React.MouseEvent) => {
          // Touch: the first tap explains, the second opens the list.
          if (pointer.current === 'touch' && active !== key) {
            e.preventDefault()
            open(key, at(e.currentTarget))
          }
        },
        'aria-describedby': active === key ? tipId : undefined,
      }
    },
    [active, open, tipId]
  )

  const containerProps = {
    onMouseLeave: clear,
    onBlur: (e: React.FocusEvent) => {
      const next = e.relatedTarget as Node | null
      if (!next || !containerRef.current?.contains(next)) clear()
    },
  }
  return { active, anchor, tipId, bind, clear, containerProps }
}

export interface FlowTipContent {
  title: string
  rows: Array<[string, string]>
  definition?: string
  link?: { label: string; href: string | null | undefined }
  /** Further lists the figure relates to (a sensor's page), after the main link. */
  more?: Array<{ label: string; href: string | null | undefined }>
}

/**
 * The tooltip of a focused figure: a title, two or three key/value rows, one
 * plain-words definition and a link to the list. It opens on focus as well
 * as hover, never traps focus, and Escape closes it.
 */
export function FlowTip({
  id,
  content,
  anchor: at,
}: {
  id: string
  content: FlowTipContent | null
  /** The focused element's box and the visual's box, measured when it lit. */
  anchor: { el: DOMRect; box: DOMRect } | null
}) {
  if (!content || !at) return null
  const { el: anchor, box } = at
  const width = Math.min(260, box.width - 16)
  // Beside the element when there is room, else under it; never outside the visual.
  let left = anchor.right - box.left + 12
  let top = anchor.top - box.top
  if (left + width > box.width) {
    left = anchor.left - box.left - width - 12
  }
  if (left < 8) {
    left = Math.max(8, Math.min(anchor.left - box.left, box.width - width - 8))
    top = anchor.bottom - box.top + 8
  }
  const href = safeInternalHref(content.link?.href)
  return (
    <div
      id={id}
      role="tooltip"
      data-testid="flow-tip"
      className="absolute z-20 rounded-lg border bg-popover p-3 text-popover-foreground shadow-md"
      style={{ left, top, width }}
    >
      <p className="mb-2 text-sm font-semibold">{content.title}</p>
      {content.rows.length > 0 && (
        <KeyValueList
          size="meta"
          className="mb-2"
          items={content.rows.map(([k, v]) => ({ key: k, label: k, value: v }))}
        />
      )}
      {content.definition && (
        <p className="mb-2 text-xs leading-relaxed text-muted-foreground">{content.definition}</p>
      )}
      {content.link && href && (
        <Link
          href={safeInternalHref(content.link.href) ?? '/'}
          className="text-xs font-semibold text-signal-text hover:underline"
        >
          {content.link.label}
        </Link>
      )}
      {content.more?.map((m) => {
        const to = safeInternalHref(m.href)
        return to ? (
          <Link
            key={m.label}
            href={to}
            className="mt-1 block text-xs text-signal-text hover:underline"
          >
            {m.label}
          </Link>
        ) : null
      })}
    </div>
  )
}

/** A figure that opens its list (plain text without a safe same-origin list). */
export function FlowLink({
  to,
  label,
  className,
  children,
  ...rest
}: {
  to: string | null | undefined
  label?: string
  className?: string
  children: ReactNode
} & Record<string, unknown>) {
  const href = safeInternalHref(to)
  if (!href) {
    return (
      <span className={className} {...rest} tabIndex={0}>
        {children}
      </span>
    )
  }
  return (
    <Link
      href={safeInternalHref(to) ?? '/'}
      aria-label={label}
      className={cn('rounded-sm focus-visible:outline-2', className)}
      {...rest}
    >
      {children}
    </Link>
  )
}

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** A counted phrase: the `.one` form for exactly one, the `.other` form otherwise. */
export function tCount(
  t: Translate,
  key: string,
  other: string,
  one: string,
  count: number,
  vars: Record<string, string | number>
): string {
  return count === 1 ? t(`${key}.one`, one, vars) : t(`${key}.other`, other, vars)
}

/** Opacity of an element under the focus model: dimmed when something else is lit. */
export function dimClass(active: string | null, lit: boolean): string {
  return cn(
    'transition-opacity duration-200 motion-reduce:transition-none',
    active && !lit && 'opacity-30'
  )
}
