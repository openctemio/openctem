'use client'

/**
 * A mix of outcomes over one whole (checklist results, verified and open
 * items), as one line of facts: what the bar measures ("12 of 38 tested")
 * over a thin segmented bar (`ProgressCell`), then each part's name and
 * count, with a dot that takes its colour only when the count is above zero.
 * The caption says what is measured, so a whole made of one quiet part never
 * reads as done. No percentage: the counts are the facts. `extra` adds facts
 * of the same whole at the end of the line (a standard, a version).
 */

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { formatNumber } from '@/lib/app-locale'
import { ProgressCell, type ProgressTone } from './progress-cell'

const DOT: Record<ProgressTone, string> = {
  success: 'bg-success',
  info: 'bg-info',
  muted: 'bg-muted-foreground/50',
  warning: 'bg-warning',
  destructive: 'bg-destructive',
}

export interface StatusMixPart {
  key: string
  /** The part's name ("Passed"), already translated. */
  label: string
  count: number
  /** Its colour in the bar and on its dot; omit for the part the bar leaves empty (not done yet). */
  tone?: ProgressTone
}

export interface StatusMixProps {
  /** The parts in bar order; a part without a tone is the empty track. */
  parts: StatusMixPart[]
  /** What the bar measures, above it ("12 of 38 tested"). */
  caption: string
  /** The caption's term, for a screen reader ("Progress"). */
  captionLabel: string
  /** More facts of the same whole at the end of the line. */
  extra?: { key: string; label: string; value: ReactNode }[]
  className?: string
}

export function StatusMix({ parts, caption, captionLabel, extra, className }: StatusMixProps) {
  const total = parts.reduce((n, p) => n + p.count, 0)
  const summary = parts.map((p) => `${p.label} ${formatNumber(p.count)}`).join(', ')
  return (
    <dl
      data-slot="status-mix"
      className={cn('flex min-w-0 flex-wrap items-center gap-x-5 gap-y-2 text-xs', className)}
    >
      <div className="w-48 max-w-full">
        <dt className="sr-only">{captionLabel}</dt>
        <dd>
          <ProgressCell
            max={total}
            caption={<span className="text-foreground font-medium">{caption}</span>}
            label={`${caption}: ${summary}`}
            parts={parts.filter((p) => p.tone).map((p) => ({ value: p.count, tone: p.tone! }))}
          />
        </dd>
      </div>
      {parts.map((p) => (
        <div key={p.key} className="flex items-center gap-1.5 whitespace-nowrap">
          <dt className="text-muted-foreground flex items-center gap-1.5">
            <span
              aria-hidden
              className={cn(
                'size-1.5 shrink-0 rounded-full',
                p.count > 0 && p.tone ? DOT[p.tone] : 'bg-border'
              )}
            />
            {p.label}
          </dt>
          <dd
            className={cn(
              'tabular-nums',
              p.count > 0 ? 'text-foreground font-medium' : 'text-muted-foreground'
            )}
          >
            {formatNumber(p.count)}
          </dd>
        </div>
      ))}
      {extra?.map((f) => (
        <div key={f.key} className="flex min-w-0 items-center gap-1.5">
          <dt className="text-muted-foreground">{f.label}</dt>
          <dd className="text-foreground min-w-0 break-words">{f.value}</dd>
        </div>
      ))}
    </dl>
  )
}
