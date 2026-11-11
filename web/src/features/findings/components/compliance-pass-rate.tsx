'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Meter } from '@/features/shared/components/meter'
import { passRatePercent, passRateTone } from '../lib/compliance-posture'

/** A pass rate as a whole percentage and a thin bar; "Nothing applicable" without one. */
export function PassRate({ rate, label }: { rate: number | null; label: string }) {
  const { t } = useTranslation()
  const pct = passRatePercent(rate)
  if (pct === null) {
    return (
      <span className="text-sm text-muted-foreground">
        {t('findings.complianceView.noApplicable', 'Nothing applicable')}
      </span>
    )
  }
  return (
    <div className="flex min-w-32 items-center gap-2">
      <span className="w-10 text-end text-sm font-medium tabular-nums">{pct}%</span>
      <Meter value={pct} max={100} label={label} tone={passRateTone(rate)} className="flex-1" />
    </div>
  )
}
