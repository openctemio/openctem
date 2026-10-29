'use client'

/**
 * How much a retest check does to the target (design: research/221):
 * T0 passive requests, T1 active payloads, T2 intrusive (state change,
 * out-of-band callbacks, volume) — T2 needs a second person's approval.
 */

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_BADGE_SOFT } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'
import type { RetestCheckTier } from '../../api/use-finding-retest-check'

const TIER_CLASS: Record<RetestCheckTier, string> = {
  T0: SEVERITY_BADGE_SOFT.info,
  T1: SEVERITY_BADGE_SOFT.low,
  T2: SEVERITY_BADGE_SOFT.high,
}

export function RetestCheckTierBadge({ tier }: { tier: RetestCheckTier }) {
  const { t } = useTranslation()
  const label =
    tier === 'T0'
      ? t('findings.retestCheck.tierT0', 'T0, passive')
      : tier === 'T1'
        ? t('findings.retestCheck.tierT1', 'T1, active')
        : t('findings.retestCheck.tierT2', 'T2, intrusive')
  return (
    <Badge variant="outline" className={cn('font-medium', TIER_CLASS[tier])}>
      {label}
    </Badge>
  )
}
