'use client'

import type { ReactNode } from 'react'
import Link from '@/components/link'
import { ChevronRight } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'
import type { MobileRowSelection } from '../data-table/data-table'
import { MetaLine } from '../text-layout'

/**
 * A queue item on a phone, laid out like every other phone card of a list:
 * the row's name and state on the first line, the end of the card always
 * holding something, never a line of its own for one control.
 *
 *   [ ] Title, up to two lines .......................... [State]
 *       The reason, two lines at most
 *       Key facts on one line ......................... [Approve] [...]
 *
 * - `state`: the state chip at the end of the title line (Pending, the
 *   severity of a finding waiting to close).
 * - `meta`: the key facts (what is asked, who asked, decide by) on ONE line;
 *   the last item gives way with an ellipsis, so put the one that may be cut
 *   last.
 * - `actions`: the decision controls (`QueueDecisionActions layout="card"`:
 *   the main action and More) at the end of the facts line.
 * - `href`: where the item opens. When `actions` draws nothing (no
 *   permission, a decided request) a chevron to it stands in their place, so
 *   the end of the card still says what a tap does. The chevron is a pointer
 *   target only: the title is the item's link for the keyboard and screen
 *   readers.
 * - `selection`: the row's checkbox in the list's select mode (the second
 *   argument of `DataTable`'s `mobileRow`), named by `selectLabel`.
 */
export function QueueCard({
  title,
  state,
  meta,
  reason,
  actions,
  href,
  className,
  selection,
  selectLabel,
  'data-testid': testId,
}: {
  title: ReactNode
  /** The item's state chip, at the end of the title line. */
  state?: ReactNode
  /** The key facts, one line: null and false items are left out. */
  meta?: ReactNode[]
  /** The requester's reason or the evidence (with its AI mark when an AI wrote it). */
  reason?: ReactNode
  /** The decision controls; drawing nothing leaves the place to the chevron. */
  actions?: ReactNode
  /** Where the item opens (the chevron's target). */
  href?: string
  className?: string
  /** The row's selection (the second argument of `DataTable`'s `mobileRow`). */
  selection?: MobileRowSelection
  /** The checkbox's accessible name, e.g. "Select {title}". */
  selectLabel?: string
  'data-testid'?: string
}) {
  const selectable = !!selection?.selectable
  const facts = (meta ?? []).filter((m) => m !== null && m !== undefined && m !== false && m !== '')
  const end = !!actions || !!href
  return (
    <div
      data-slot="queue-card"
      data-testid={testId}
      data-state={selectable && selection?.selected ? 'selected' : undefined}
      className={cn('flex min-w-0 items-start gap-3 p-3 data-[state=selected]:bg-muted', className)}
    >
      {selectable && (
        <Checkbox
          className="mt-0.5 shrink-0"
          checked={selection?.selected}
          onCheckedChange={(v) => selection?.onSelectedChange(!!v)}
          aria-label={selectLabel}
        />
      )}
      <div className="grid min-w-0 flex-1 gap-1.5">
        <div data-slot="queue-card-head" className="flex min-w-0 items-start gap-2">
          <div data-slot="queue-card-title" className="min-w-0 flex-1">
            {title}
          </div>
          {state ? (
            <div data-slot="queue-card-state" className="flex shrink-0 items-center gap-1.5">
              {state}
            </div>
          ) : null}
        </div>
        {reason ? (
          <div data-slot="queue-card-reason" className="min-w-0">
            {reason}
          </div>
        ) : null}
        {facts.length > 0 || end ? (
          <div data-slot="queue-card-line" className="flex min-w-0 items-center gap-2">
            <div data-slot="queue-card-meta" className="min-w-0 flex-1">
              {facts.length > 0 && <MetaLine oneLine className="items-center" items={facts} />}
            </div>
            {actions ? (
              // `peer`: the chevron shows only while this draws nothing.
              <div data-slot="queue-card-actions" className="peer flex shrink-0 empty:hidden">
                {actions}
              </div>
            ) : null}
            {href ? (
              <Link
                href={href}
                data-slot="queue-card-open"
                tabIndex={-1}
                aria-hidden="true"
                className={cn(
                  '-me-2 size-control-touch shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-muted',
                  actions ? 'hidden peer-empty:inline-flex' : 'inline-flex'
                )}
              >
                <ChevronRight className="size-4 rtl:rotate-180" />
              </Link>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  )
}
