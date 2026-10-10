'use client'

/**
 * The one way the console shows a scan window decision: a pill (open, waits
 * until, never opens) and, under it, the windows that block or govern the
 * target, each named as a policy or a bug-bounty program. Window names are
 * organization data: rendered as text, never as markup.
 */

import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

import { decisionLabel, decisionState, windowRefLabel, type DecisionState } from '../lib/decision'
import { formatInZone } from '../lib/schedule'
import type { WindowBlock, WindowDecision, WindowRef } from '../types'

const TONE: Record<DecisionState, PillTone> = {
  ungoverned: 'muted',
  open: 'success',
  waits: 'warning',
  never: 'destructive',
}

type DecisionLike = Pick<
  WindowDecision,
  'governed' | 'open' | 'never' | 'next_open_at' | 'closes_at'
>

export function WindowDecisionBadge({
  decision,
  className,
}: {
  decision: DecisionLike
  className?: string
}) {
  const { t } = useTranslation()
  const state = decisionState(decision)
  return (
    <TonePill
      tone={TONE[state]}
      state={state}
      label={decisionLabel(decision, t)}
      className={className}
    />
  )
}

/** The blocking windows, each with when it stops blocking. */
export function WindowBlockingList({
  blocking,
  className,
}: {
  blocking?: WindowBlock[]
  className?: string
}) {
  const { t } = useTranslation()
  if (!blocking || blocking.length === 0) return null
  return (
    <ul
      className={cn('space-y-0.5 text-xs text-muted-foreground', className)}
      data-testid="window-blocking"
    >
      {blocking.map((b, i) => (
        <li key={`${b.source_id ?? i}`} className="break-words">
          {windowRefLabel(b, t)}
          {b.until
            ? ` · ${t('scanWindows.block.until', 'until {at}', { at: formatInZone(b.until) })}`
            : ` · ${t('scanWindows.block.never', 'does not open')}`}
        </li>
      ))}
    </ul>
  )
}

/** The windows that apply to a target. */
export function WindowGoverningList({
  governing,
  className,
}: {
  governing?: WindowRef[]
  className?: string
}) {
  const { t } = useTranslation()
  if (!governing || governing.length === 0) return null
  return (
    <ul
      className={cn('space-y-0.5 text-xs text-muted-foreground', className)}
      data-testid="window-governing"
    >
      {governing.map((g, i) => (
        <li key={`${g.source_id ?? i}`} className="break-words">
          {windowRefLabel(g, t)}
          {' · '}
          {g.kind === 'blackout'
            ? t('scanWindows.kind.blackout', 'Blackout')
            : t('scanWindows.kind.allow', 'Allow')}
        </li>
      ))}
    </ul>
  )
}

/** A decision with its explanation: the pill, the blocking windows, and the governing ones. */
export function WindowExplanation({
  decision,
  showGoverning = false,
  className,
}: {
  decision: WindowDecision
  showGoverning?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <div className={cn('space-y-1.5', className)} data-testid="window-explanation">
      <WindowDecisionBadge decision={decision} />
      {!decision.open && <WindowBlockingList blocking={decision.blocking} />}
      {decision.open && (decision.rate_limit_rps ?? 0) > 0 && (
        <p className="text-xs text-muted-foreground">
          {t('scanWindows.decision.rate', 'Limited to {n} requests per second inside the window.', {
            n: decision.rate_limit_rps ?? 0,
          })}
        </p>
      )}
      {showGoverning && (decision.governing?.length ?? 0) > 0 && (
        <div className="space-y-0.5">
          <p className="text-xs font-medium">
            {t('scanWindows.decision.governing', 'Windows that apply')}
          </p>
          <WindowGoverningList governing={decision.governing} />
        </div>
      )}
    </div>
  )
}
