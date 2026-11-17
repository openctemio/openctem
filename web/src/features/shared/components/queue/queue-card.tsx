'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/**
 * A queue item on a phone: fixed slots, so every card of every queue reads
 * in one order. Title (what the request is about), one line of state marks,
 * one line of who asked and by when, the reason in two lines at most, then
 * the decision controls on their own row.
 */
export function QueueCard({
  title,
  marks,
  meta,
  reason,
  actions,
  className,
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
  'data-testid'?: string
}) {
  return (
    <div data-slot="queue-card" data-testid={testId} className={cn('grid gap-2 p-3', className)}>
      <div data-slot="queue-card-title" className="min-w-0">
        {title}
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
