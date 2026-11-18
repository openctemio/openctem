'use client'

import { useTranslation } from '@/context/i18n-provider'
import { formatAbsoluteTime } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { decideByState, formatDecideByDate } from './decide-by'

/**
 * When a queue item must be decided: a calendar date (day and month; the year
 * only when it is not this year; the exact time is the hover text), and "Overdue" in the danger tone with the date once the moment
 * has passed. Nothing to decide (no date, or the item is closed) is a dash.
 */
export function QueueDecideBy({
  value,
  now,
  className,
}: {
  /** ISO time; pass nothing for an item that is no longer waiting. */
  value: string | null | undefined
  now?: Date
  className?: string
}) {
  const { t, locale } = useTranslation()
  const state = decideByState(value, now)
  if (state === 'none' || !value) {
    return <span className={cn('text-sm text-muted-foreground', className)}>-</span>
  }
  const date = formatDecideByDate(value, locale, now)
  return (
    <time
      dateTime={value}
      title={formatAbsoluteTime(value, locale)}
      data-slot="queue-decide-by"
      data-state={state}
      className={cn(
        'text-sm whitespace-nowrap tabular-nums',
        state === 'overdue' ? 'font-medium text-tone-danger-fg' : 'text-muted-foreground',
        className
      )}
    >
      {state === 'overdue' ? t('queue.decideBy.overdue', 'Overdue, {date}', { date }) : date}
    </time>
  )
}
