'use client'

import * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { Clock } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export type SignalTone = 'neutral' | 'alert'

export type SignalChipProps = Omit<React.ComponentProps<'span'>, 'children'> & {
  /** A decorative icon. In the alert tone it is red. */
  icon?: LucideIcon
  /** Neutral (default) or alert: red icon, and red text for a state such as overdue. */
  tone?: SignalTone
  /** Red text too (past due, overdue). Only with the alert tone. */
  alertText?: boolean
  /**
   * Qualifiers of the fact ("Past due", "Ransomware"): a second segment of the
   * chip, divided by a CSS border (no glyph). The accessible name joins them:
   * "KEV, past due".
   */
  qualifiers?: string[]
  /** data-slot of the element; presets pass their own. */
  slot?: string
  children: React.ReactNode
}

/**
 * One supporting fact that raises the urgency of something else (known
 * exploited, EPSS, internet-facing, due or overdue, intrusive): a neutral
 * chip. Only the icon may carry colour (red for the alert tone), so a row
 * of chips never out-shouts the priority box. The text is always present.
 */
export const SignalChip = React.forwardRef<HTMLSpanElement, SignalChipProps>(function SignalChip(
  {
    icon: Icon,
    tone = 'neutral',
    alertText,
    qualifiers,
    slot = 'signal-chip',
    className,
    children,
    ...props
  },
  ref
) {
  const quals = (qualifiers ?? []).filter(Boolean)
  const segmented = quals.length > 0
  const aria =
    props['aria-label'] ??
    (segmented && typeof children === 'string'
      ? [children, ...quals.map((q) => q.toLowerCase())].join(', ')
      : undefined)
  return (
    <span
      ref={ref}
      data-tone={tone}
      data-segmented={segmented ? 'true' : undefined}
      className={cn(
        'inline-flex h-[22px] w-fit max-w-[200px] shrink-0 items-center whitespace-nowrap rounded-sm border border-border bg-transparent text-xs font-semibold leading-none text-foreground',
        !segmented && 'gap-1 px-1.5',
        tone === 'alert' && alertText && 'text-destructive',
        className
      )}
      {...props}
      aria-label={aria}
      data-slot={slot}
    >
      <span className={cn('inline-flex items-center gap-1', segmented && 'h-full pl-1.5 pr-1.5')}>
        {Icon && (
          <Icon
            className={cn(
              'size-3 shrink-0',
              tone === 'alert' ? 'text-sig-icon' : 'text-muted-foreground'
            )}
            aria-hidden
          />
        )}
        {children}
      </span>
      {segmented && (
        <span
          data-slot="signal-chip-qualifier"
          className="inline-flex h-full items-center gap-1 border-l border-border px-1.5"
        >
          {quals.map((q) => (
            <span key={q}>{q}</span>
          ))}
        </span>
      )}
    </span>
  )
})

export interface DueChipProps {
  /** The due date, ISO 8601. Nothing renders for a missing or invalid date. */
  dueAt: string | null | undefined
  /** The clock, for tests. */
  now?: Date
  className?: string
}

const DAY_MS = 86_400_000

/**
 * A due date as a chip: "Due in 3 d" (neutral), "Due today", or "Overdue 4 d"
 * (alert icon and red text). Whole days, rounded down; the date itself is the
 * tooltip.
 */
export function DueChip({ dueAt, now, className }: DueChipProps) {
  const { t } = useTranslation()
  if (!dueAt) return null
  const due = new Date(dueAt)
  if (Number.isNaN(due.getTime())) return null
  const diff = due.getTime() - (now ?? new Date()).getTime()
  const days = Math.floor(Math.abs(diff) / DAY_MS)
  const overdue = diff < 0
  let text: string
  if (overdue) text = t('labels.due.overdue', 'Overdue {days} d', { days })
  else if (days === 0) text = t('labels.due.today', 'Due today')
  else text = t('labels.due.in', 'Due in {days} d', { days })
  return (
    <SignalChip
      slot="due-chip"
      icon={Clock}
      tone={overdue ? 'alert' : 'neutral'}
      alertText={overdue}
      data-overdue={overdue ? 'true' : undefined}
      title={due.toISOString().slice(0, 10)}
      className={className}
    >
      {text}
    </SignalChip>
  )
}
