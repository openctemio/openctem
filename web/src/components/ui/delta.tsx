import * as React from 'react'
import { ArrowDownRight, ArrowRight, ArrowUpRight } from 'lucide-react'

import { cn } from '@/lib/utils'

/**
 * A change against an earlier period: arrow, figure and what it is compared
 * with. The tone says whether the change is good or bad for this figure, not
 * which way it moved (fewer open findings is `better` although the arrow points
 * down), and is never the only signal: the arrow and the figure carry the
 * direction, `verdict` is spoken to screen readers. The caller formats the
 * figure and the words (they depend on the unit and the language).
 */
export type DeltaTone = 'better' | 'worse' | 'flat' | 'neutral'

export const DELTA_TONE_CLASS: Record<DeltaTone, string> = {
  better: 'text-good',
  worse: 'text-bad',
  flat: 'text-muted-foreground',
  neutral: 'text-muted-foreground',
}

export function Delta({
  delta,
  text,
  tone,
  against,
  verdict,
  as: Tag = 'span',
  className,
}: {
  /** The signed change; only its sign picks the arrow. */
  delta: number
  /** The formatted change, e.g. "-12" or "+3.5 pts". */
  text: string
  tone: DeltaTone
  /** What it is compared with, e.g. "vs previous period". */
  against?: string
  /** The tone in words for screen readers ("better", "worse"). */
  verdict?: string | null
  as?: 'span' | 'p'
  className?: string
}) {
  const Icon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : ArrowRight
  return (
    <Tag
      data-slot="delta"
      data-tone={tone}
      className={cn('flex items-center gap-1 text-xs', DELTA_TONE_CLASS[tone], className)}
    >
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span className="tabular-nums">{text}</span>
      {against ? <span className="text-muted-foreground">{against}</span> : null}
      {verdict ? <span className="sr-only">({verdict})</span> : null}
    </Tag>
  )
}
