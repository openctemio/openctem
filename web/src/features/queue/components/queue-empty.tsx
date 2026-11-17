'use client'

import type { ReactNode } from 'react'
import { CheckCircle2, Inbox, SearchX } from 'lucide-react'

/**
 * The three ways a queue is empty, in the table's one frame:
 * - `first-run`: the queue never held a request; says what will appear here.
 * - `nothing-waiting`: decided requests exist, none waits; the queue is done.
 * - `no-match`: the lens left no row; offers the way out as `action`.
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
  const Icon = ICON[kind]
  return (
    <div
      data-slot="queue-empty"
      data-kind={kind}
      className="flex flex-col items-center justify-center gap-2 text-center"
    >
      <Icon className="size-10 text-muted-foreground/50" aria-hidden />
      <p className="text-body font-medium">{title}</p>
      {hint && <p className="text-cap text-muted-foreground">{hint}</p>}
      {action}
    </div>
  )
}
