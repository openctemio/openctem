'use client'

import { ShieldAlert } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { slaCountdown } from '../lib/sla'
import { SlaStatusBadge } from './sla-status-badge'
import { slaStateClass } from '@/lib/sla-colors'
import { SLA_STATUS_LABELS, type SLAStatus } from '@/features/repositories/types/repository.types'

/**
 * The SLA cell of a findings row (the findings list, My Work), one line tall:
 * the time left or past due (hours under two days) in the SLA state's colour,
 * as a pill when the finding is at risk or late and as plain text while on
 * track; the state's word when there is no deadline. The state is part of the
 * accessible name and the pointer tooltip. When the policy's known exploited
 * (KEV) cap set the deadline, a focusable marker says so. One component, so
 * every list shows an SLA the same way.
 */
export function SlaDueChip({
  status,
  deadline,
  kevCapped,
  className,
}: {
  status?: string | null
  deadline?: string | null
  /** The SLA policy's known exploited (KEV) cap shortened the deadline. */
  kevCapped?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  if (!status || status === 'not_applicable') {
    return (
      <span className="text-sm text-muted-foreground">{t('findings.slaDue.none', 'No SLA')}</span>
    )
  }
  const key = (SLA_STATUS_LABELS[status as SLAStatus] ? status : 'not_applicable') as SLAStatus
  const stateWord = t(`findings.sla.${key}`, SLA_STATUS_LABELS[key])
  const c = slaCountdown(deadline)
  const unit = c?.unit === 'hours' ? 'h' : 'd'
  const countdown = c
    ? t(
        `findings.slaDue.${c.overdue ? 'overdue' : 'left'}${c.unit === 'hours' ? 'Hours' : 'Days'}`,
        c.overdue ? `{count} ${unit} overdue` : `In {count} ${unit}`,
        { count: c.count }
      )
    : null
  // Late by the clock even before the server's state catches up.
  const tone = c?.overdue && status === 'on_track' ? 'overdue' : status
  const plain = countdown !== null && tone === 'on_track'
  const name = countdown ? `${stateWord}: ${countdown}` : stateWord
  const kevReason = t('findings.properties.slaKevCapped', 'Shortened because it is in CISA KEV')
  return (
    <span
      data-slot="sla-due-chip"
      className={cn(
        'inline-flex max-w-full min-w-0 items-center gap-1 whitespace-nowrap',
        className
      )}
    >
      {countdown === null ? (
        <SlaStatusBadge status={status} className="min-w-0" />
      ) : (
        <span
          data-slot="sla-countdown"
          title={name}
          className={cn(
            'min-w-0 truncate text-xs tabular-nums',
            plain
              ? 'text-foreground'
              : cn('rounded-md border px-2 py-0.5 font-medium', slaStateClass(tone))
          )}
        >
          <span className="sr-only">{`${stateWord}: `}</span>
          {countdown}
        </span>
      )}
      {kevCapped && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              data-slot="sla-kev-capped"
              tabIndex={0}
              role="img"
              aria-label={kevReason}
              className="inline-flex shrink-0 items-center rounded-sm text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              <ShieldAlert className="size-3.5" aria-hidden="true" />
            </span>
          </TooltipTrigger>
          <TooltipContent side="top" className="max-w-xs text-xs">
            {kevReason}
          </TooltipContent>
        </Tooltip>
      )}
    </span>
  )
}
