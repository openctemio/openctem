'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { PRIORITY_BOX_CLASS, type PriorityClass } from '@/lib/priority-colors'
import { PriorityGlyph } from '@/components/ui/priority-glyph'

export interface PriorityBadgeProps {
  /** The class to show: P0 (immediate) to P3 (track); null when not prioritised. */
  priorityClass: PriorityClass | null | undefined
  /** Add the class name ("P0 · Immediate"): detail pages, desktop tables, drawers. */
  showWord?: boolean
  className?: string
}

const BARS: Record<PriorityClass, 0 | 1 | 2 | 3> = { P0: 3, P1: 2, P2: 1, P3: 0 }

/**
 * A priority class as a box with a three-bar glyph (P0 strongest, the one
 * solid label). The one rendering of a class: lists, drawers, dashboards and
 * the finding detail all use it. Order is shown by fill weight, filled bars
 * and the text "P0".."P3", so colour is never the only cue. A finding that is
 * not prioritised shows a dashed "–".
 */
export function PriorityBadge({ priorityClass, showWord = false, className }: PriorityBadgeProps) {
  const { t } = useTranslation()
  if (!priorityClass) {
    const none = t('findings.priorityBadge.none', 'Not prioritised')
    return (
      <span
        data-slot="priority-badge"
        data-priority="none"
        role="img"
        aria-label={none}
        title={none}
        className={cn(
          'inline-flex w-fit shrink-0 items-center justify-center whitespace-nowrap rounded-sm border border-dashed border-border px-1.5 py-0.5 text-xs font-semibold leading-none text-muted-foreground',
          className
        )}
      >
        <span aria-hidden>–</span>
      </span>
    )
  }
  const cls: PriorityClass = priorityClass in PRIORITY_BOX_CLASS ? priorityClass : 'P3'
  const name = t(`findings.priorityBadge.name.${cls}`, DEFAULT_NAMES[cls])
  const aria = t('findings.priorityBadge.aria', 'Priority {class}, {name}', { class: cls, name })
  return (
    <span
      data-slot="priority-badge"
      data-priority={cls}
      role="img"
      aria-label={aria}
      className={cn(
        'inline-flex w-fit shrink-0 items-center justify-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-bold leading-none tabular-nums',
        PRIORITY_BOX_CLASS[cls],
        className
      )}
    >
      <PriorityGlyph filled={BARS[cls]} />
      <span aria-hidden>{showWord ? `${cls} · ${name}` : cls}</span>
    </span>
  )
}

const DEFAULT_NAMES: Record<PriorityClass, string> = {
  P0: 'Immediate',
  P1: 'Urgent',
  P2: 'Scheduled',
  P3: 'Track',
}
