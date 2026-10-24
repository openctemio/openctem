'use client'

import * as React from 'react'
import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * Page anatomy rules for a metric strip: research/244. A number earns a tile
 * only when it opens its list (`href`) or filters the list below (`onClick`);
 * at most `METRIC_STRIP_MAX` tiles; red or amber only for a real problem
 * state and only while the count is positive; a zero is a muted 0, never
 * hidden.
 */
export const METRIC_STRIP_MAX = 5

export interface MetricStripItem {
  key: string
  label: string
  value: number | string
  /** Small caption after the value. */
  hint?: string
  /**
   * `danger` / `warning` colour the value only while it is a positive number
   * (failed, overdue, breached). A zero is good news and stays neutral: a red
   * "0" reads as an alarm that isn't one. Never use them for a plain total.
   */
  tone?: 'default' | 'danger' | 'warning'
  /**
   * Extra content under the value (a one-line explanation, a small
   * breakdown bar). Keep it short: the strip is a summary, not a card.
   */
  detail?: React.ReactNode
  /** What the number counts, shown as the cell's tooltip. */
  description?: string
  /** The list this number counts. The tile becomes a link to it. */
  href?: string
  /** Filter the list below by this metric. The tile becomes a toggle button. */
  onClick?: () => void
  /** The filter this metric applies (or the list it links to) is current. */
  active?: boolean
}

/**
 * Columns for the tablet grid: up to 4 metrics share one row, more split into
 * two rows as evenly as possible (5 → 3+2, 7 → 4+3), never a lone metric.
 */
export function smColumns(count: number): number {
  return count <= 4 ? Math.max(count, 1) : Math.min(Math.ceil(count / 2), 4)
}

/**
 * Phone grid span (out of 6 tracks) of tile `index` in a strip of `count`:
 * every row is full and no tile sits alone.
 */
export function phoneSpan(count: number, index: number): 2 | 3 | 6 {
  if (count <= 1) return 6
  if (count === 3) return 2
  if (count === 5) return index < 3 ? 2 : 3
  if (count === 2 || count === 4) return 3
  // More than five is refused by the anatomy (warned above); keep rows of three.
  return 2
}

const PHONE_SPAN_CLASS = { 2: 'col-span-2', 3: 'col-span-3', 6: 'col-span-6' } as const

/**
 * A page's headline numbers as one divided strip (no corner icons, no card per
 * number); the list below stays the focus.
 *
 * Phone (research/244 mobile decision M2): compact tiles on a six-track
 * grid, at most two rows: 2 and 4 tiles in halves, 3 in thirds, 5 as three
 * thirds over two halves; smaller values; a long label wraps to a second line
 * instead of being cut. Never a sideways scroll.
 * Tablet: balanced rows (`smColumns`). Desktop: one row.
 *
 * States: `loading` shows a skeleton per value; `error` shows "—" per value
 * with the reason as the tooltip, so the strip keeps its place and the page
 * does not jump when the numbers come back.
 */
export function MetricStrip({
  items,
  loading = false,
  error,
  className,
}: {
  items: MetricStripItem[]
  loading?: boolean
  /** The numbers could not be read: the reason, shown as each value's tooltip. */
  error?: string
  className?: string
}) {
  if (process.env.NODE_ENV !== 'production' && items.length > METRIC_STRIP_MAX) {
    console.warn(
      `MetricStrip: ${items.length} tiles; the page anatomy allows ${METRIC_STRIP_MAX} (research/244). Use quick views or filters for the rest.`
    )
  }
  return (
    <dl
      data-slot="metric-strip"
      className={cn(
        'grid grid-cols-6 overflow-hidden rounded-lg border bg-card',
        'sm:grid-cols-[repeat(var(--metric-cols-sm),minmax(0,1fr))] lg:grid-cols-[repeat(var(--metric-cols),minmax(0,1fr))]',
        className
      )}
      style={
        {
          '--metric-cols': items.length,
          '--metric-cols-sm': smColumns(items.length),
        } as React.CSSProperties
      }
    >
      {items.map((item, index) => {
        const numeric = typeof item.value === 'number'
        const zero = numeric && item.value === 0
        const positive = numeric && (item.value as number) > 0
        const alarming = item.tone === 'danger' && positive
        const warning = item.tone === 'warning' && positive
        const body = (
          <>
            <dt className="line-clamp-2 text-xs text-muted-foreground sm:line-clamp-none sm:truncate">
              {item.label}
            </dt>
            <dd className="mt-0.5">
              {loading ? (
                <Skeleton className="h-6 w-12 sm:h-7 sm:w-14" />
              ) : error ? (
                <span
                  className="text-lg font-semibold tabular-nums tracking-tight text-muted-foreground sm:text-kpi"
                  title={error}
                >
                  —
                </span>
              ) : (
                <span
                  className={cn(
                    'text-lg font-semibold tabular-nums tracking-tight sm:text-kpi',
                    zero && 'text-muted-foreground',
                    alarming && 'text-destructive',
                    warning && 'text-warning'
                  )}
                >
                  {numeric ? (item.value as number).toLocaleString() : item.value}
                </span>
              )}
              {item.hint && !loading && !error ? (
                // A compact phone tile has no room for a caption: it moves to
                // the tile's tooltip there.
                <span className="ms-1.5 hidden text-xs text-muted-foreground sm:inline">
                  {item.hint}
                </span>
              ) : null}
            </dd>
            {item.detail && !loading && !error ? (
              <dd className="mt-1 min-w-0 text-xs text-muted-foreground">{item.detail}</dd>
            ) : null}
          </>
        )
        const cellClass = cn(
          'block min-w-0 -ms-px -mt-px border-s border-t px-3 py-2 text-start sm:col-span-1 sm:px-4 sm:py-2.5',
          PHONE_SPAN_CLASS[phoneSpan(items.length, index)],
          item.active && 'bg-accent'
        )
        const interactive =
          'transition-colors hover:bg-accent/60 focus-visible:relative focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring'
        // Pages pass their own routes, but the strip treats the value like any
        // href: an unsafe one renders the tile without a link.
        const href = item.href ? safeHref(item.href) : undefined
        if (href) {
          return (
            <Link
              key={item.key}
              href={href}
              aria-current={item.active ? 'page' : undefined}
              title={item.description ?? item.hint}
              data-slot="metric-tile"
              className={cn(cellClass, interactive)}
            >
              {body}
            </Link>
          )
        }
        if (item.onClick) {
          return (
            <button
              key={item.key}
              type="button"
              onClick={item.onClick}
              aria-pressed={item.active ?? false}
              title={item.description ?? item.hint}
              data-slot="metric-tile"
              className={cn(cellClass, interactive)}
            >
              {body}
            </button>
          )
        }
        return (
          <div
            key={item.key}
            className={cellClass}
            title={item.description ?? item.hint}
            data-slot="metric-tile"
          >
            {body}
          </div>
        )
      })}
    </dl>
  )
}
