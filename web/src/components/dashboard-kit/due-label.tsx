'use client'

/**
 * The SLA due text of an items row: relative due time, "Overdue" with an icon
 * once the deadline has passed, "No due date" without one. Shared by the items
 * list and the findings table so both say the same thing.
 */

import { CircleAlert } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { formatRelativeTime } from '@/lib/format-metric'

/** A deadline already behind us. */
export function isPast(iso: string | null | undefined): boolean {
  return !!iso && Date.parse(iso) < Date.now()
}

export function DueLabel({ dueAt }: { dueAt: string | null | undefined }) {
  const { t, locale } = useTranslation()
  const due = dueAt ? formatRelativeTime(dueAt, locale) : null
  if (!due) {
    return (
      <span className="shrink-0 text-xs text-muted-foreground">
        {t('dashboardKit.items.noDue', 'No due date')}
      </span>
    )
  }
  if (isPast(dueAt)) {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-destructive">
        <CircleAlert className="size-3.5" aria-hidden />
        {t('dashboardKit.items.overdue', 'Overdue {time}', { time: due })}
      </span>
    )
  }
  return (
    <span className="shrink-0 text-xs text-muted-foreground">
      {t('dashboardKit.items.due', 'due {time}', { time: due })}
    </span>
  )
}
