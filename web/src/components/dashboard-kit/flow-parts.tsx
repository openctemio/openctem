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

/** A cubic wire from (x1, y1) to (x2, y2), leaving and entering horizontally. */
export function wirePath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = Math.max(24, Math.abs(x2 - x1) * 0.45)
  return `M${x1} ${y1} C${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
}

/** Wire width for a volume: 1 to 6 px on a square-root scale of the largest. */
export function wireWidth(value: number, max: number): number {
  if (max <= 0 || value <= 0) return 1
  return Math.round((1 + 5 * Math.sqrt(value / max)) * 100) / 100
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

/**
 * Width bands of a connected visual, measured on the widget's own width (a
 * container, never the viewport: a widget sits in grid cells of any size).
 * The layout classes use the same numbers as container queries
 * (`@min-[660px]`, `@min-[960px]`); the wires use the measured band, so a
 * wire is drawn only when both of its ends sit side by side.
 *
 * The widths are the visual's own (the card less its padding).
 *
 * - narrow (< 660 px): one column, no wires; every number stays a link.
 * - mid (660 to 959 px): the core and the outcomes side by side, sources as a
 *   short list above (the first three and "N more"); wires to the outcomes.
 * - wide (960 px and more): three columns of bounded width, centred, so the
 *   wires stay short and proportional however wide the card is.
 */
export const FLOW_MID = 660
export const FLOW_WIDE = 960

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
    el.querySelectorAll<HTMLElement>('[data-wire-out]').forEach((n) => {
      const r = n.getBoundingClientRect()
      out[n.dataset.wireOut ?? ''] = { x: r.right - box.left, y: r.top + r.height / 2 - box.top }
    })
    el.querySelectorAll<HTMLElement>('[data-wire-in]').forEach((n) => {
      const r = n.getBoundingClientRect()
      inn[n.dataset.wireIn ?? ''] = { x: r.left - box.left, y: r.top + r.height / 2 - box.top }
    })
    return { width: box.width, height: box.height, out, in: inn }
  }, [ref])

  useLayoutEffect(() => {
    // contentKey is a re-measure trigger, not read here.
    void contentKey
    setLayout(measure())
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setLayout(measure()))
    ro.observe(el)
    return () => ro.disconnect()
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
