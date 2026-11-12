import * as React from 'react'

import { cn } from '@/lib/utils'

/**
 * The one small trend graphic: a line or bars in an inline SVG. It is a single
 * image with a text summary (`summary` is its accessible name, written by the
 * caller in the page's language), so a screen reader gets the sentence and the
 * marks stay decorative. Colour is `currentColor` (neutral by default) and
 * never encodes data on its own: a warning bar is also named in the summary and
 * in its `<title>`. Pure SVG, no chart library, so it renders the same in a
 * table cell, a metric tile and a drawer.
 */
export interface SparklineProps {
  /** One value per point or bar, oldest first. `null` is a gap (no sample), never a 0. */
  values: Array<number | null | undefined>
  /** What the graphic says, as a sentence: the accessible name. */
  summary: string
  variant?: 'line' | 'bars'
  /** Bars only: the bars drawn in the warning colour (a late slot). */
  warn?: boolean[]
  /** Bars only: a hover title per bar, same order as `values`. */
  titles?: string[]
  /** A dashed reference line at this value (a target, an expected interval). */
  reference?: number
  /** Top of the scale. Defaults to the largest value (and the reference). */
  max?: number
  /** Line only: dot on the last point. Default true. */
  endDot?: boolean
  /** Height in SVG units. The width stretches to the element unless `width` is set. */
  height?: number
  /** Width in px; omitted, the graphic fills its container's width. */
  width?: number
  className?: string
}

const VIEW_W = 120

export function Sparkline({
  values,
  summary,
  variant = 'line',
  warn,
  titles,
  reference,
  max,
  endDot = true,
  height = 32,
  width,
  className,
}: SparklineProps) {
  const present = values.filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
  if (present.length === 0) return null
  const common = {
    role: 'img' as const,
    'aria-label': summary,
    focusable: 'false' as const,
    preserveAspectRatio: 'none' as const,
    className: cn('overflow-visible text-muted-foreground', className),
    ...(width ? { width, height } : {}),
  }
  if (variant === 'bars')
    return <Bars {...{ values, warn, titles, reference, max, height, common }} />
  return <Line {...{ values: present, reference, height, endDot, common }} />
}

type Common = React.SVGProps<SVGSVGElement>

function Line({
  values,
  reference,
  height,
  endDot,
  common,
}: {
  values: number[]
  reference?: number
  height: number
  endDot: boolean
  common: Common
}) {
  const pad = 2
  const min = Math.min(...values, reference ?? Infinity)
  const top = Math.max(...values, reference ?? -Infinity)
  const span = top - min || 1
  const step = values.length > 1 ? (VIEW_W - pad * 2) / (values.length - 1) : 0
  const yOf = (v: number) =>
    top === min ? height / 2 : pad + (height - pad * 2) * (1 - (v - min) / span)
  const pts = values.map((v, i) => ({ x: pad + i * step, y: yOf(v) }))
  const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
  const last = pts[pts.length - 1]
  return (
    <svg viewBox={`0 0 ${VIEW_W} ${height}`} {...common}>
      {reference != null && (
        <line
          x1={0}
          x2={VIEW_W}
          y1={yOf(reference)}
          y2={yOf(reference)}
          stroke="currentColor"
          strokeOpacity={0.5}
          strokeDasharray="3 3"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />
      )}
      {pts.length === 1 ? (
        <circle cx={last.x} cy={last.y} r={2.5} fill="currentColor" />
      ) : (
        <path
          d={d}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      )}
      {endDot && pts.length > 1 && <circle cx={last.x} cy={last.y} r={2} fill="currentColor" />}
    </svg>
  )
}

function Bars({
  values,
  warn,
  titles,
  reference,
  max,
  height,
  common,
}: {
  values: Array<number | null | undefined>
  warn?: boolean[]
  titles?: string[]
  reference?: number
  max?: number
  height: number
  common: Common
}) {
  const barW = 3
  const step = 4
  const w = values.length * step
  const nums = values.filter((v): v is number => typeof v === 'number')
  const top = Math.max(max ?? 0, ...nums, reference ?? 0, 1)
  const y = (v: number) => height - Math.max(1, (v / top) * (height - 2))
  return (
    <svg viewBox={`0 0 ${w} ${height}`} {...common}>
      {values.map((v, i) => {
        const title = titles?.[i] ? <title>{titles[i]}</title> : null
        if (typeof v !== 'number') {
          // No sample: a hairline on the baseline, not a zero-height bar.
          return (
            <rect
              key={i}
              x={i * step}
              y={height - 1}
              width={barW}
              height={1}
              fill="currentColor"
              fillOpacity={0.3}
            >
              {title}
            </rect>
          )
        }
        const isWarn = warn?.[i] === true
        return (
          <rect
            key={i}
            x={i * step}
            y={y(v)}
            width={barW}
            height={height - y(v)}
            data-late={isWarn || undefined}
            className={isWarn ? 'fill-warning' : 'fill-viz-ink'}
          >
            {title}
          </rect>
        )
      })}
      {reference != null && reference > 0 && (
        <line
          x1={0}
          x2={w}
          y1={y(reference)}
          y2={y(reference)}
          stroke="currentColor"
          strokeDasharray="3 3"
          strokeWidth={0.75}
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  )
}
