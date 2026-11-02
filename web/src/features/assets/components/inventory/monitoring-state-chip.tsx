'use client'

/** A list row's derived monitoring state, as the shared tone chip. */

import { useTranslation } from '@/context/i18n-provider'
import { ToneChip } from '@/components/ui/tone-chip'
import {
  MONITORING_STATE_FALLBACK,
  MONITORING_STATE_HINT,
  MONITORING_STATE_TONE,
  isMonitoringState,
} from '../../lib/monitoring-state'

export function MonitoringStateChip({ state }: { state: string | undefined }) {
  const { t } = useTranslation()
  if (!isMonitoringState(state)) return <span className="text-muted-foreground">-</span>
  return (
    <ToneChip
      tone={MONITORING_STATE_TONE[state]}
      value={state}
      label={t(`assets.monitoring.state.${state}`, MONITORING_STATE_FALLBACK[state])}
      title={t(`assets.monitoring.hint.${state}`, MONITORING_STATE_HINT[state])}
    />
  )
}
