'use client'

/**
 * The state of a CTEM stage as one icon set and words, shared by every view
 * of the stages (the loop widget, the exposure flow). The icon carries the
 * state's colour and shape together (check = on track, triangle = needs
 * attention, cross = off track, minus = not measured); nothing else may
 * recolour it, so a colour never contradicts its icon. "Act here" is marked
 * apart (ActHere), never by filling the state icon.
 */

import { CheckCircle2, CircleMinus, TriangleAlert, XCircle } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { StageState } from './types'

const ICON: Record<StageState, typeof CheckCircle2> = {
  good: CheckCircle2,
  warn: TriangleAlert,
  crit: XCircle,
  unmeasured: CircleMinus,
}

const TONE: Record<StageState, string> = {
  good: 'text-success',
  warn: 'text-warning',
  crit: 'text-destructive',
  unmeasured: 'text-muted-foreground',
}

/** The state's icon, in its own colour. */
export function StageStateIcon({ state, className }: { state: StageState; className?: string }) {
  const Icon = ICON[state]
  return (
    <Icon
      className={cn('size-3.5 shrink-0', TONE[state], className)}
      aria-hidden
      data-state={state}
    />
  )
}

/** The words of a state ("On track", "Needs attention", ...). */
export function useStageStateText(): (state: StageState) => string {
  const { t } = useTranslation()
  return (state) => {
    switch (state) {
      case 'good':
        return t('dashboardKit.stage.good', 'On track')
      case 'warn':
        return t('dashboardKit.stage.warn', 'Needs attention')
      case 'crit':
        return t('dashboardKit.stage.crit', 'Off track')
      default:
        return t('dashboardKit.stage.unmeasured', 'Not measured')
    }
  }
}

/** "Act here": the stage with the largest gap, a neutral pill with the brand marker dot. */
export function ActHere({ label, className }: { label?: string; className?: string }) {
  const { t } = useTranslation()
  return (
    <span
      className={cn(
        'inline-flex w-fit items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium',
        className
      )}
      data-testid="stage-act-here"
    >
      <span className="size-2 shrink-0 rounded-full bg-signal" aria-hidden />
      {label ?? t('dashboardKit.stage.actHere', 'Act here')}
    </span>
  )
}
