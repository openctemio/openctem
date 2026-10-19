'use client'

/**
 * A suggestion's risk points with what they mean (the legend and this
 * suggestion's parts in the tooltip): the risk accepting it removes.
 */

import { Info } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { RemediationSuggestion } from '../api/types'
import { riskPartsList } from '../lib/hub'

export function RiskPoints({
  suggestion: s,
}: {
  suggestion: Pick<RemediationSuggestion, 'risk_points' | 'risk_parts'>
}) {
  const { t } = useTranslation()
  const parts = riskPartsList(s)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1 underline decoration-dotted underline-offset-2"
          aria-label={t('remediationHub.risk.aria', undefined, { n: s.risk_points })}
        >
          {t('remediationHub.risk.points', undefined, { n: s.risk_points })}
          <Info className="size-3" aria-hidden />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs space-y-1 text-xs">
        <p>{t('remediationHub.risk.explain')}</p>
        {parts.length > 0 && (
          <p>
            {t('remediationHub.risk.parts', undefined, {
              parts: parts.map((p) => `${p.label} ×${p.count}`).join(' · '),
            })}
          </p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}
