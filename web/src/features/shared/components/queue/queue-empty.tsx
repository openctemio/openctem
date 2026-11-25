'use client'

import type { ReactNode } from 'react'
import { CheckCircle2, Inbox, SearchX } from 'lucide-react'
import { EmptyState } from '../empty-state'

/**
 * The three ways a queue is empty, in the table's one frame:
 * - `first-run`: the queue never held a request; says what will appear here.
 * - `nothing-waiting`: decided requests exist, none waits; the queue is done.
 * - `no-match`: the lens left no row; offers the way out as `action`.
 *
 * Drawn by the shared `EmptyState`, so every queue looks like every list.
 */
export type QueueEmptyKind = 'first-run' | 'nothing-waiting' | 'no-match'

const ICON = {
  'first-run': Inbox,
  'nothing-waiting': CheckCircle2,
  'no-match': SearchX,
} as const

export function QueueEmpty({
  kind,
  title,
  hint,
  action,
}: {
  kind: QueueEmptyKind
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div data-slot="queue-empty" data-kind={kind} className="contents">
      <EmptyState card={false} icon={ICON[kind]} title={title} description={hint} action={action} />
    </div>
  )
}
