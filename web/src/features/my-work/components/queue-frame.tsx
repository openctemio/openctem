'use client'

import type { ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { formatCount } from '@/lib/format-metric'

/**
 * The card every My Work queue sits in: a toolbar line (the queue's locked
 * rule and quick chips at the start; the result count and the queue's
 * actions at the end), the rows, and a footer with the queue's rule and keys.
 */
export function QueueFrame({
  label,
  toolbar,
  primary,
  secondary,
  footer,
  shown,
  total,
  children,
}: {
  label: string
  /** Locked and quick chips (start of the toolbar line). */
  toolbar?: ReactNode
  /** The one primary action of the queue. */
  primary?: ReactNode
  /** Other actions (View all, Triage these). */
  secondary?: ReactNode
  footer?: ReactNode
  /** Rows on screen, and how many the queue holds. */
  shown: number
  total: number
  children: ReactNode
}) {
  const { t, locale } = useTranslation()
  const note =
    total > shown
      ? t('myWork.topOf', 'Top {shown} of {total}', {
          shown,
          total: formatCount(total, locale),
        })
      : t('myWork.results', '{count} results', { count: total })
  return (
    <section aria-label={label} className="min-w-0 overflow-hidden rounded-lg border bg-card">
      <div className="flex min-w-0 flex-wrap items-center gap-2 border-b px-4 py-2.5">
        <div className="flex min-w-0 flex-1 basis-64 flex-wrap items-center gap-1.5">{toolbar}</div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <span className="text-meta text-muted-foreground tabular-nums" aria-live="polite">
            {note}
          </span>
          {secondary}
          {primary}
        </div>
      </div>
      {children}
      {footer && (
        <div className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t px-4 py-2 text-meta text-muted-foreground">
          {footer}
        </div>
      )}
    </section>
  )
}
