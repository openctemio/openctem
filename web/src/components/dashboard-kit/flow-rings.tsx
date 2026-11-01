'use client'

/**
 * Concentric rings of a connected visual (the exposure flow's core; api
 * docs/architecture/dashboards.md, "Exposure flow and intake"). Each ring is
 * one step of a funnel read from the outside in, split into proportional
 * segments: rounded caps, a small gap between segments, the largest segment
 * centred at the bottom (away from the wire joints at 9 and 3 o'clock), a
 * muted track under every ring so an empty ring still reads as a ring.
 *
 * Segments take the focus model of the visual (`bind`): hover, keyboard focus
 * or a first tap lights a segment (slightly thicker, a soft glow in its own
 * colour) and dims the rest. Interactive segments are links (Enter or a click
 * opens their list); a small, decorative copy (a phone headline) only lights
 * and opens the tooltip on tap. The rings draw in once when they mount; never
 * under reduced motion.
 */

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { dimClass } from './flow-parts'

/** The viewBox is -VIEW..VIEW on both axes. */
const VIEW = 160

/** Ring radius and stroke width, outermost first, by the number of rings. */
const GEOMETRY: Record<number, Array<{ r: number; w: number }>> = {
  1: [{ r: 128, w: 22 }],
  2: [
    { r: 136, w: 14 },
    { r: 108, w: 20 },
  ],
  3: [
    { r: 140, w: 12 },
    { r: 118, w: 12 },
    { r: 92, w: 18 },
  ],
}

/** Extra stroke width of a lit segment. */
const LIT_EXTRA = 4
/** Visible gap between two segments, in viewBox units (after the round caps). */
const GAP_UNITS = 4
/** Smallest drawn sweep (radians) beyond the caps, so a tiny part stays visible. */
const MIN_SWEEP = 0.02

export interface RingPart {
  /** The focus key of the segment (shared with the rows it stands for). */
  key: string
  value: number
  color: string
  /** Accessible name: what, how many, share of the ring. */
  aria: string
  href?: string | null
}

export interface Ring {
  id: string
  parts: RingPart[]
}

export interface RingSegment extends RingPart {
  d: string
  /** Start and end angle (radians, clockwise from 12 o'clock). */
  a0: number
  a1: number
}

function point(r: number, a: number): string {
  return `${(r * Math.sin(a)).toFixed(2)} ${(-r * Math.cos(a)).toFixed(2)}`
}

/**
 * The segments of one ring: one per part with a value, in the given order,
 * each at least MIN_SWEEP long, separated so the visible gap is GAP_UNITS
 * whatever the stroke width, the largest centred at 6 o'clock. One part is a
 * closed circle.
 */
export function ringSegments(parts: RingPart[], r: number, w: number): RingSegment[] {
  const live = parts.filter((p) => p.value > 0)
  const total = live.reduce((s, p) => s + p.value, 0)
  if (total === 0) return []
  if (live.length === 1) {
    return [
      {
        ...live[0],
        a0: 0,
        a1: 2 * Math.PI,
        d: `M0 ${-r} A${r} ${r} 0 1 1 0 ${r} A${r} ${r} 0 1 1 0 ${-r}`,
      },
    ]
  }
  const n = live.length
  // The round caps reach w/2 past each end: the gap covers both caps plus GAP_UNITS.
  const gap = (w + GAP_UNITS) / r
  const spare = Math.max(0, 2 * Math.PI - n * (gap + MIN_SWEEP))
  const sweeps = live.map((p) => MIN_SWEEP + (spare * p.value) / total)
  let big = 0
  live.forEach((p, i) => {
    if (p.value > live[big].value) big = i
  })
  let before = 0
  for (let i = 0; i < big; i++) before += sweeps[i] + gap
  let a = Math.PI - (before + sweeps[big] / 2)
  return live.map((p, i) => {
    const a0 = a
    const a1 = a + sweeps[i]
    a = a1 + gap
    return {
      ...p,
      a0,
      a1,
      d: `M${point(r, a0)} A${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${point(r, a1)}`,
    }
  })
}

/** Where the wires meet the rings: the outer edge, as a share of the box from its side. */
export function ringEdgeInset(count: number): number {
  const g = GEOMETRY[Math.min(3, Math.max(1, count))][0]
  return (VIEW - (g.r + g.w / 2)) / (2 * VIEW)
}

export function FlowRings({
  rings,
  label,
  active,
  lit,
  bind,
  onOpen,
  interactive = true,
  wireAnchors = false,
  centre,
  className,
}: {
  /** Outermost first; one to three rings. */
  rings: Ring[]
  /** The accessible name of the figure. */
  label: string
  active: string | null
  lit: (key: string) => boolean
  bind: (
    key: string,
    anchorFrom?: string
  ) => Record<string, unknown> & {
    onClick: (e: React.MouseEvent) => void
  }
  /** Opens a segment's list (Enter or click on an interactive segment). */
  onOpen?: (href: string) => void
  /** Segments are links (false: a decorative copy that only lights on tap). */
  interactive?: boolean
  /** Mark the outer edge as the wires' joints (data-wire-in/out="ring"). */
  wireAnchors?: boolean
  centre?: ReactNode
  className?: string
}) {
  const shown = rings.slice(0, 3)
  const geometry = GEOMETRY[Math.max(1, shown.length)]
  const inset = `${(ringEdgeInset(shown.length) * 100).toFixed(2)}%`
  return (
    <div className={cn('@container/ring relative aspect-square', className)} data-k="ring">
      {wireAnchors && (
        <>
          <span
            className="absolute top-1/2 size-px"
            style={{ left: inset }}
            data-wire-in="ring"
            aria-hidden
          />
          <span
            className="absolute top-1/2 size-px"
            style={{ right: inset }}
            data-wire-out="ring"
            aria-hidden
          />
        </>
      )}
      <svg
        viewBox={`${-VIEW} ${-VIEW} ${2 * VIEW} ${2 * VIEW}`}
        className="size-full overflow-visible"
        role={interactive ? 'group' : undefined}
        aria-label={interactive ? label : undefined}
        aria-hidden={interactive ? undefined : true}
        data-testid="flow-rings"
      >
        {shown.map((ring, ri) => {
          const { r, w } = geometry[ri]
          const segments = ringSegments(ring.parts, r, w)
          return (
            <g key={ring.id} data-ring={ring.id}>
              <circle
                r={r}
                fill="none"
                stroke="var(--muted)"
                strokeWidth={w}
                data-testid="ring-track"
              />
              {segments.map((s) => {
                const on = lit(s.key)
                const b = bind(s.key, '[data-k="ring"]')
                const href = s.href ?? null
                return (
                  <g key={s.key} className={dimClass(active, on)}>
                    <path
                      d={s.d}
                      pathLength={1}
                      fill="none"
                      stroke={s.color}
                      strokeWidth={on ? w + LIT_EXTRA : w}
                      strokeLinecap="round"
                      className="animate-ring-draw cursor-pointer outline-none transition-[stroke-width,filter] duration-200 motion-reduce:transition-none"
                      style={{
                        animationDelay: `${ri * 90}ms`,
                        filter: on
                          ? `drop-shadow(0 0 4px color-mix(in oklab, ${s.color} 60%, transparent))`
                          : undefined,
                      }}
                      data-seg={s.key}
                      {...(interactive
                        ? {
                            role: 'link',
                            tabIndex: 0,
                            'aria-label': s.aria,
                            onKeyDown: (e: React.KeyboardEvent) => {
                              if (e.key === 'Enter' && href) onOpen?.(href)
                            },
                          }
                        : {})}
                      {...b}
                      onClick={(e: React.MouseEvent) => {
                        b.onClick(e)
                        if (interactive && !e.defaultPrevented && href) onOpen?.(href)
                      }}
                    />
                  </g>
                )
              })}
            </g>
          )
        })}
      </svg>
      {centre && (
        <div className="pointer-events-none absolute inset-0 grid place-content-center text-center [&_a]:pointer-events-auto [&_[tabindex]]:pointer-events-auto">
          {centre}
        </div>
      )}
    </div>
  )
}

/**
 * A small key glyph for a ring (three circles, the named one drawn): put
 * beside a figure so the reader knows which ring it is.
 */
export function RingKey({ index, count = 3 }: { index: number; count?: number }) {
  const radii = [6.5, 4.5, 2.5].slice(0, count)
  return (
    <svg viewBox="-8 -8 16 16" className="inline size-3.5 shrink-0" aria-hidden>
      {radii.map((r, i) => (
        <circle
          key={r}
          r={r}
          fill="none"
          stroke={i === index ? 'currentColor' : 'var(--border)'}
          strokeWidth={i === index ? 1.6 : 1}
        />
      ))}
    </svg>
  )
}
