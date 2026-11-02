'use client'

import { Info } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'

export interface MetricRow {
  key: string
  label: string
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
 * Plain rows for figures that open no list (time to detect, time to validate):
 * label and caption on the left, the figure on the right, no card per figure.
 * Not measured is muted body text, never a dash at figure size.
 */
export function MetricRowList({ rows, className }: { rows: MetricRow[]; className?: string }) {
  return (
    <ul data-slot="metric-row-list" className={cn('divide-y rounded-lg border bg-card', className)}>
      {rows.map((row) => (
        <li
          key={row.key}
          data-slot="metric-row"
          data-state={row.value === null ? 'not-measured' : undefined}
          className="flex min-w-0 items-baseline justify-between gap-4 px-4 py-2.5 sm:px-5"
        >
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 text-sm font-medium">
              <span className="min-w-0">{row.label}</span>
              {row.info ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      aria-label={row.infoLabel ?? row.label}
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
  )
}
