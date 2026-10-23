'use client'

import * as React from 'react'
import Link from '@/components/link'
import { Skeleton } from '@/components/ui/skeleton'
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
 * A page's headline numbers as one divided strip (no corner icons, no card per
 * number); the list below stays the focus.
 *
 * Phone: two columns, an odd last tile spans both, never a sideways scroll.
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
        'grid grid-cols-2 overflow-hidden rounded-lg border bg-card',
        // An odd last tile spans the phone row, so no tile sits alone.
        '[&>*:last-child:nth-child(odd)]:col-span-2 sm:[&>*:last-child:nth-child(odd)]:col-span-1',
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
      {items.map((item) => {
        const numeric = typeof item.value === 'number'
        const zero = numeric && item.value === 0
        const positive = numeric && (item.value as number) > 0
        const alarming = item.tone === 'danger' && positive
        const warning = item.tone === 'warning' && positive
        const body = (
          <>
            <dt className="truncate text-xs text-muted-foreground">{item.label}</dt>
            <dd className="mt-0.5">
              {loading ? (
                <Skeleton className="h-7 w-14" />
              ) : error ? (
                <span
                  className="text-kpi tabular-nums tracking-tight text-muted-foreground"
                  title={error}
                >
                  —
                </span>
              ) : (
                <span
                  className={cn(
                    'text-kpi tabular-nums tracking-tight',
                    zero && 'text-muted-foreground',
                    alarming && 'text-destructive',
                    warning && 'text-warning'
                  )}
                >
                  {numeric ? (item.value as number).toLocaleString() : item.value}
                </span>
              )}
              {item.hint && !loading && !error ? (
                <span className="ms-1.5 text-xs text-muted-foreground">{item.hint}</span>
              ) : null}
            </dd>
            {item.detail && !loading && !error ? (
              <dd className="mt-1 min-w-0 text-xs text-muted-foreground">{item.detail}</dd>
            ) : null}
          </>
        )
        const cellClass = cn(
          'block min-w-0 -ms-px -mt-px border-s border-t px-4 py-2.5 text-start',
          item.active && 'bg-accent'
        )
        const interactive =
          'transition-colors hover:bg-accent/60 focus-visible:relative focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring'
        if (item.href) {
          return (
            <Link
              key={item.key}
              href={item.href}
              aria-current={item.active ? 'page' : undefined}
              title={item.description}
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
              title={item.description}
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
            title={item.description}
            data-slot="metric-tile"
          >
            {body}
          </div>
        )
      })}
    </dl>
  )
}
