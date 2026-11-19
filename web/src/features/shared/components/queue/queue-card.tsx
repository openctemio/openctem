'use client'

import type { ReactNode } from 'react'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'
import type { MobileRowSelection } from '../data-table/data-table'

/**
 * A queue item on a phone: fixed slots, so every card of every queue reads
 * in one order. Title (what the request is about), one line of state marks,
 * one line of who asked and by when, the reason in two lines at most, then
 * the decision controls on their own row. In the list's select mode the
 * card starts with the row's checkbox (`selection`, from `DataTable`).
 */
export function QueueCard({
  title,
  marks,
  meta,
  reason,
  actions,
  className,
  selection,
  selectLabel,
  'data-testid': testId,
}: {
  title: ReactNode
  /** Status and what is asked for: lozenges and badges, one wrapping line. */
  marks?: ReactNode
  /** Requester, decide-by: text items, one wrapping line. */
  meta?: ReactNode
  /** The requester's reason (with its AI mark when an AI wrote it). */
  reason?: ReactNode
  actions?: ReactNode
  className?: string
  /** The row's selection (the second argument of `DataTable`'s `mobileRow`). */
  selection?: MobileRowSelection
  /** The checkbox's accessible name, e.g. "Select {title}". */
  selectLabel?: string
  'data-testid'?: string
}) {
  const selectable = !!selection?.selectable
  return (
    <div
      data-slot="queue-card"
      data-testid={testId}
      data-state={selectable && selection?.selected ? 'selected' : undefined}
      className={cn('grid gap-2 p-3 data-[state=selected]:bg-muted', className)}
    >
      <div data-slot="queue-card-title" className="flex min-w-0 items-start gap-3">
        {selectable && (
          <Checkbox
            className="mt-0.5 shrink-0"
            checked={selection?.selected}
            onCheckedChange={(v) => selection?.onSelectedChange(!!v)}
            aria-label={selectLabel}
          />
        )}
        <div className="min-w-0 flex-1">{title}</div>
      </div>
      {marks ? (
        <div data-slot="queue-card-marks" className="flex flex-wrap items-center gap-1.5">
          {marks}
        </div>
      ) : null}
      {meta ? (
        <div
          data-slot="queue-card-meta"
          className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground"
        >
          {meta}
        </div>
      ) : null}
      {reason ? (
        <div data-slot="queue-card-reason" className="min-w-0">
          {reason}
        </div>
      ) : null}
      {actions ? <div data-slot="queue-card-actions">{actions}</div> : null}
    </div>
  )
}
