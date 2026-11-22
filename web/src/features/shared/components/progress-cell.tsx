'use client'

/**
 * A list's progress cell: the count on top ("3 of 8 verified") and a thin bar
 * under it, one block centred in the row like the cells beside it. The bar can
 * stack parts (verified, closed, claimed) in theme tones; the count is the
 * plain tabular figure the number columns use. The full summary is the bar's
 * accessible name and tooltip; its value is the first part (the one the
 * caption counts).
 */

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type ProgressTone = 'success' | 'info' | 'muted' | 'warning' | 'destructive'

const TONE: Record<ProgressTone, string> = {
  success: 'bg-success',
  info: 'bg-info',
  muted: 'bg-muted-foreground/50',
  warning: 'bg-warning',
  destructive: 'bg-destructive',
}

export interface ProgressPart {
  value: number
  tone: ProgressTone
}

export interface ProgressCellProps {
  /** Parts drawn in order, each a share of `max`. */
  parts: ProgressPart[]
  max: number
  /** The short count shown above the bar, already translated. */
  caption: ReactNode
  /** What the bar says to a screen reader and in its tooltip. */
  label: string
  className?: string
}

export function ProgressCell({ parts, max, caption, label, className }: ProgressCellProps) {
  const pct = (n: number) => (max > 0 ? `${Math.min(100, Math.max(0, (n / max) * 100))}%` : '0%')
  return (
    <div
      data-slot="progress-cell"
      className={cn('flex w-full min-w-0 flex-col justify-center gap-1', className)}
    >
      <span className="text-muted-foreground truncate text-xs leading-4 tabular-nums">
        {caption}
      </span>
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={Math.min(max, parts[0]?.value ?? 0)}
        title={label}
        className="bg-muted flex h-1 w-full overflow-hidden rounded-full"
      >
        {parts.map((p, i) =>
          p.value > 0 ? (
            <span key={i} className={cn('h-full', TONE[p.tone])} style={{ width: pct(p.value) }} />
          ) : null
        )}
      </div>
    </div>
  )
}
