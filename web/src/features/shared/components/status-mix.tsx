'use client'

/**
 * A mix of outcomes over one whole (checklist results, verified and open
 * items): a thin segmented bar with a caption above it (`ProgressCell`), and
 * one line of counts under it, each with a dot that takes its colour only
 * when the count is above zero. The caption says what the bar measures
 * ("12 of 38 tested"), so a whole made of one quiet part never reads as
 * done. No percentage: the counts are the facts.
 */

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
  /** The words after the count ("passed"), already translated. */
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
  className?: string
}

export function StatusMix({ parts, caption, className }: StatusMixProps) {
  const total = parts.reduce((n, p) => n + p.count, 0)
  const summary = parts.map((p) => `${formatNumber(p.count)} ${p.label}`).join(', ')
  return (
    <div data-slot="status-mix" className={cn('min-w-0 space-y-1.5', className)}>
      <ProgressCell
        max={total}
        caption={<span className="text-foreground font-medium">{caption}</span>}
        label={`${caption}: ${summary}`}
        parts={parts.filter((p) => p.tone).map((p) => ({ value: p.count, tone: p.tone! }))}
      />
      <ul className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {parts.map((p) => (
          <li key={p.key} className="flex items-center gap-1.5 whitespace-nowrap">
            <span
              aria-hidden
              className={cn(
                'size-1.5 shrink-0 rounded-full',
                p.count > 0 && p.tone ? DOT[p.tone] : 'bg-border'
              )}
            />
            <span className={cn('tabular-nums', p.count > 0 && 'text-foreground')}>
              {formatNumber(p.count)}
            </span>
            {p.label}
          </li>
        ))}
      </ul>
    </div>
  )
}
