'use client'

import { ShieldAlert } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { slaCountdown } from '../lib/sla'
import { SlaStatusBadge } from './sla-status-badge'

/**
 * The SLA cell of a findings row (the findings list, My Work): the status
 * pill, the time left or past due under it (hours when under two days), and,
 * when the policy's known exploited (KEV) cap set the deadline, a marker that
 * says so. One component, so every list shows an SLA the same way.
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
  const c = slaCountdown(deadline)
  const countdown = c
    ? t(
        `findings.slaDue.${c.overdue ? 'overdue' : 'left'}${c.unit === 'hours' ? 'Hours' : 'Days'}`,
        c.overdue ? '{count} past due' : '{count} left',
        { count: c.count }
      )
    : null
  const kevReason = t('findings.properties.slaKevCapped', 'Shortened because it is in CISA KEV')
  return (
    <div data-slot="sla-due-chip" className={cn('flex flex-col gap-0.5', className)}>
      <SlaStatusBadge status={status} className="w-fit" />
      {(countdown || kevCapped) && (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground tabular-nums">
          {countdown}
          {kevCapped && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span
                  data-slot="sla-kev-capped"
                  tabIndex={0}
                  role="img"
                  aria-label={kevReason}
                  className="inline-flex items-center gap-0.5 rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                >
                  <ShieldAlert className="size-3.5" aria-hidden="true" />
                  <span>{t('findings.slaDue.kevCap', 'KEV cap')}</span>
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs text-xs">
                {kevReason}
              </TooltipContent>
            </Tooltip>
          )}
        </span>
      )}
    </div>
  )
}
