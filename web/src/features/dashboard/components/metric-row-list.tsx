'use client'

import type * as React from 'react'

import { Info } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'

export interface MetricRow {
  key: string
  /** The figure's name: text, or a chip that names it (a severity, a priority). */
  label: React.ReactNode
  /** The formatted figure, or null when it is not measured. */
  value: string | null
  /** What "not measured" says in place of the figure. */
  notMeasuredLabel: string
  /** Why this row has the figure it has (sample, or the reason it is empty). */
  caption?: string
  /** How the figure is measured, behind an info button. */
  info?: string
  infoLabel?: string
}

/**
 * Columns for `count` rows once the list is wide enough: two from 48rem, then
 * three (for three rows) or four from a wide screen's content width, so a
 * label and its figure never sit a page width apart (web/docs/ui-style-contract.md,
 * "Label and figure rows").
 */
export function metricRowColumns(count: number): string {
  return cn(
    count >= 2 && '@3xl:grid-cols-2',
    count === 3 && '@[75rem]:grid-cols-3',
    count >= 4 && '@[100rem]:grid-cols-4'
  )
}

/**
 * Plain rows for figures that open no list (time to detect, time to validate):
 * label and caption on the left, the figure on the right, no card per figure.
 * Not measured is muted body text, never a dash at figure size.
 *
 * The rows flow into columns as the list widens (`metricRowColumns`): one on a
 * phone, two from 48rem, three or four on a wide screen. `framed={false}` when
 * the list sits inside a card of its own.
 */
export function MetricRowList({
  rows,
  className,
  framed = true,
}: {
  rows: MetricRow[]
  className?: string
  framed?: boolean
}) {
  return (
    <div
      data-slot="metric-row-frame"
      className={cn('@container min-w-0', framed && 'rounded-lg border bg-card', className)}
    >
      {/* Every row draws the rule above it; the first line of rules is pulled
          under the frame's edge, so each column reads as one ruled list. */}
      <ul
        data-slot="metric-row-list"
        className={cn('grid grid-cols-1 overflow-hidden', framed && 'gap-x-2', metricRowColumns(rows.length))}
      >
        {rows.map((row) => (
          <li
            key={row.key}
            data-slot="metric-row"
            data-state={row.value === null ? 'not-measured' : undefined}
            className={cn(
              '-mt-px flex min-w-0 items-baseline justify-between gap-4 border-t py-2.5',
              framed && 'px-4 sm:px-5'
            )}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-sm font-medium">
                <span className="min-w-0">{row.label}</span>
                {row.info ? (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        aria-label={row.infoLabel ?? (typeof row.label === 'string' ? row.label : undefined)}
                        className="shrink-0 rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <Info className="h-3.5 w-3.5" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs text-xs leading-relaxed">
                      {row.info}
                    </TooltipContent>
                  </Tooltip>
                ) : null}
              </div>
              {row.caption ? <p className="text-sm text-muted-foreground">{row.caption}</p> : null}
            </div>
            <span
              data-slot="metric-row-value"
              className={cn(
                'shrink-0 text-sm tabular-nums',
                row.value === null ? 'text-muted-foreground' : 'font-medium'
              )}
            >
              {row.value ?? row.notMeasuredLabel}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
