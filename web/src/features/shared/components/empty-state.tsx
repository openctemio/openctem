'use client'

import { SearchX, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { OneFilledAction } from './one-filled-action'

interface EmptyStateProps {
  /** Small muted icon above the title. Optional. */
  icon?: LucideIcon
  /** What is empty, in plain words ("No service accounts yet"). */
  title: string
  /** One line: why it is empty or what to do next. */
  description?: ReactNode
  /**
   * At most one next step (a kit Button or a link). Leave it out when the
   * page header already shows the same action: one button per job.
   */
  action?: ReactNode
  /**
   * Draw a bordered box (default true). Inside another card, table or list
   * frame the box drops its own border and background, so it never nests.
   */
  card?: boolean
  /**
   * The list is empty because of a search or filters: show "No results" and
   * "Clear filters" instead of the first-use text above.
   */
  filtered?: boolean
  /** Clears the search and filters; with `filtered` it adds the "Clear filters" button. */
  onClearFilters?: () => void
  className?: string
}

/** Inside a card, a table cell or a list frame, the box loses its own frame. */
const NESTED =
  'in-data-[slot=card]:rounded-none in-data-[slot=card]:border-0 in-data-[slot=card]:bg-transparent in-data-[slot=card]:shadow-none in-data-[slot=table-empty]:rounded-none in-data-[slot=table-empty]:border-0 in-data-[slot=table-empty]:bg-transparent'

/**
 * The shared empty state: a short block sized to its content (small icon,
 * title, one line, at most one action), never a tall blank box. Three kinds
 * (docs/ui-style-contract.md, "Empty"): no data yet (first use, the setup
 * action), no results (`filtered`, "Clear filters") and not enough data.
 *
 * Its action is filled only when no other filled button is on the screen;
 * beside the page's main action it is an outline button (`OneFilledAction`).
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  card = true,
  filtered = false,
  onClearFilters,
  className,
}: EmptyStateProps) {
  if (filtered) {
    return <NoResultsState card={card} onClearFilters={onClearFilters} className={className} />
  }
  return (
    <EmptyBlock
      icon={icon}
      title={title}
      description={description}
      action={action}
      card={card}
      className={className}
    />
  )
}

interface NoResultsStateProps {
  /** Defaults to "No results". */
  title?: string
  /** Defaults to "Nothing matches the search or filters." */
  hint?: ReactNode
  /** Adds the "Clear filters" button. */
  onClearFilters?: () => void
  card?: boolean
  className?: string
}

/** The "no results" kind: a search or filters left nothing to show. */
export function NoResultsState({
  title,
  hint,
  onClearFilters,
  card = true,
  className,
}: NoResultsStateProps) {
  const { t } = useTranslation()
  return (
    <EmptyBlock
      kind="no-results"
      icon={SearchX}
      title={title ?? t('common.empty.noResults', 'No results')}
      description={
        hint ?? t('common.empty.noResultsHint', 'Nothing matches the search or filters.')
      }
      action={
        onClearFilters ? (
          <Button variant="outline" size="sm" onClick={onClearFilters}>
            {t('common.table.clearFilters', 'Clear filters')}
          </Button>
        ) : undefined
      }
      card={card}
      className={className}
    />
  )
}

function EmptyBlock({
  kind = 'empty',
  icon: Icon,
  title,
  description,
  action,
  card,
  className,
}: {
  kind?: 'empty' | 'no-results'
  icon?: LucideIcon
  title: string
  description?: ReactNode
  action?: ReactNode
  card: boolean
  className?: string
}) {
  return (
    <div
      data-slot="empty-state"
      data-kind={kind}
      className={cn(
        'flex w-full min-w-0 flex-col items-center gap-1 px-4 py-8 text-center',
        card && cn('rounded-lg border bg-card text-card-foreground', NESTED),
        className
      )}
    >
      {Icon && <Icon aria-hidden className="mb-1 size-6 shrink-0 text-muted-foreground" />}
      <p className="max-w-prose text-body font-medium text-balance">{title}</p>
      {description && (
        <p className="max-w-prose text-body text-muted-foreground text-pretty">{description}</p>
      )}
      {action && <OneFilledAction className="mt-3">{action}</OneFilledAction>}
    </div>
  )
}
