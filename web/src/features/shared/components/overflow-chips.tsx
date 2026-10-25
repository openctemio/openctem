'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The active filter chips under a list toolbar (`ListToolbar`'s `below` row),
 * capped at `max`: past it a "+N" button shows the rest, and "Show fewer"
 * folds them again. Keeps the chips row to one or two lines when a link
 * carries many filters, so the table does not drop below the fold. The chip
 * that has focus is never hidden (the row stays expanded once opened).
 */
export function OverflowChips({
  children,
  max = 6,
  className,
  label,
  'data-testid': testId,
}: {
  'data-testid'?: string
  /** One element per chip (each usually an `li`). */
  children: React.ReactNode
  /** Chips shown before "+N". */
  max?: number
  className?: string
  /** Accessible name of the list. */
  label?: string
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = React.useState(false)
  const items = React.Children.toArray(children).filter(Boolean)
  if (items.length === 0) return null
  const hidden = expanded ? 0 : Math.max(0, items.length - max)
  const shown = hidden > 0 ? items.slice(0, max) : items

  return (
    <ul
      aria-label={label}
      data-slot="overflow-chips"
      data-testid={testId}
      className={cn('flex min-w-0 max-w-full flex-wrap items-center gap-1.5', className)}
    >
      {shown}
      {hidden > 0 ? (
        <li>
          <button
            type="button"
            data-slot="overflow-chips-more"
            onClick={() => setExpanded(true)}
            aria-label={t('common.overflowChips.showAll', 'Show {count} more filters', {
              count: hidden,
            })}
            className="inline-flex h-7 items-center rounded-md border border-dashed px-2 text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            +{hidden}
          </button>
        </li>
      ) : null}
      {expanded && items.length > max ? (
        <li>
          <button
            type="button"
            data-slot="overflow-chips-less"
            onClick={() => setExpanded(false)}
            className="inline-flex h-7 items-center rounded-md px-2 text-xs text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {t('common.overflowChips.showFewer', 'Show fewer')}
          </button>
        </li>
      ) : null}
    </ul>
  )
}
