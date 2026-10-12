/**
 * DetailChecklist — "Health checks: 7 of 9 passing", folded by default, the
 * failing checks first when opened. From the sensor drawer.
 *
 * Use it only for checks the record really has (the API reports them or the
 * app computes them from real data): never a list of placeholder checks.
 */

'use client'

import * as React from 'react'
import { AlertTriangle, CheckCircle2, ChevronRight, CircleAlert, Info } from 'lucide-react'

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { cn } from '@/lib/utils'

export type DetailCheckStatus = 'ok' | 'warning' | 'critical' | 'info'

export interface DetailCheck {
  key: string
  status: DetailCheckStatus
  /** Short name of the check ("Heartbeat"). */
  label: React.ReactNode
  /** What was found ("Last seen 2 min ago"). */
  text: React.ReactNode
  /** A button that fixes it; shown instead of `aside`. */
  action?: React.ReactNode
  /** A short muted value on the right (a time, a version). */
  aside?: React.ReactNode
}

/** Icon and colour per check status: one vocabulary for every checklist. */
export const DETAIL_CHECK_ICON: Record<
  DetailCheckStatus,
  { icon: typeof CheckCircle2; className: string }
> = {
  ok: { icon: CheckCircle2, className: 'text-success' },
  warning: { icon: AlertTriangle, className: 'text-warning' },
  critical: { icon: CircleAlert, className: 'text-destructive' },
  info: { icon: Info, className: 'text-muted-foreground' },
}

const RANK: Record<DetailCheckStatus, number> = { critical: 0, warning: 1, info: 2, ok: 2 }

/** Failing checks (critical, then warning) first; the rest keep their order. */
export function orderChecks<T extends { status: DetailCheckStatus }>(checks: T[]): T[] {
  return checks
    .map((c, i) => ({ c, i }))
    .sort((a, b) => RANK[a.c.status] - RANK[b.c.status] || a.i - b.i)
    .map(({ c }) => c)
}

export interface DetailChecklistProps {
  checks: DetailCheck[]
  /** Sentence case, plural: "Health checks". */
  title?: string
  /** A green tick before the summary when nothing fails (default: true). */
  passIcon?: boolean
  /** Accessible name of the list. */
  label?: string
  defaultOpen?: boolean
  className?: string
}

export function DetailChecklist({
  checks,
  title = 'Health checks',
  passIcon = true,
  label = 'Health',
  defaultOpen = false,
  className,
}: DetailChecklistProps) {
  const [open, setOpen] = React.useState(defaultOpen)
  if (checks.length === 0) return null
  const passing = checks.filter((c) => c.status === 'ok').length
  const failing = checks.filter((c) => c.status === 'warning' || c.status === 'critical').length
  return (
    <Collapsible open={open} onOpenChange={setOpen} className={className}>
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-2 rounded-md px-1 py-1 text-start text-sm text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          <ChevronRight
            className={cn('h-4 w-4 shrink-0 transition-transform', open && 'rotate-90')}
            aria-hidden
          />
          {failing === 0 && passIcon ? (
            <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden />
          ) : null}
          <span className="min-w-0 flex-1 tabular-nums">
            {failing === 0
              ? `All ${checks.length} ${title.toLowerCase()} passing`
              : `${title}: ${passing} of ${checks.length} passing`}
          </span>
          <span className="shrink-0 text-xs">{open ? 'Hide' : 'Show'}</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="pt-1">
        <ul className="divide-y rounded-lg border" aria-label={label}>
          {orderChecks(checks).map((c) => {
            const { icon: Icon, className: iconClass } = DETAIL_CHECK_ICON[c.status]
            const right =
              c.action ??
              (c.aside ? (
                <span className="text-xs whitespace-nowrap text-muted-foreground tabular-nums">
                  {c.aside}
                </span>
              ) : null)
            return (
              <li
                key={c.key}
                className="flex items-start gap-2.5 px-3 py-2 text-sm"
                data-check={c.key}
                data-status={c.status}
              >
                <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', iconClass)} aria-label={c.status} />
                {/* Phones: the label above the text and the action under it;
                    wider: label | text | action in one row. */}
                <div className="min-w-0 flex-1 sm:grid sm:grid-cols-[5.5rem_minmax(0,1fr)] sm:gap-x-2.5">
                  <span className="block text-muted-foreground">{c.label}</span>
                  <span className="block min-w-0 break-words">{c.text}</span>
                  {right && <div className="mt-1.5 sm:hidden">{right}</div>}
                </div>
                {right && <div className="hidden shrink-0 sm:flex">{right}</div>}
              </li>
            )
          })}
        </ul>
      </CollapsibleContent>
    </Collapsible>
  )
}
