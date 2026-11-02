'use client'

/**
 * The one-line description of an exposure, in the viewer's language, and the
 * severity cell that shows when an analyst changed the severity. Both render
 * scan output as text only.
 */

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { SeverityBadge } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_LABELS } from '@/lib/severity'
import type { ExposureEvent } from '@/lib/api/exposure-types'
import { exposureSummaryText } from '../lib/summary'

/** The summary sentence, or the description when the API had no sentence. */
export function ExposureSummaryLine({ exposure }: { exposure: ExposureEvent }) {
  const { t } = useTranslation()
  const text = exposureSummaryText(exposure, t) || exposure.description || ''
  if (!text) return null
  return <p className="line-clamp-1 text-xs text-muted-foreground">{text}</p>
}

/** The effective severity, with a note when it is an analyst's decision. */
export function ExposureSeverityCell({ exposure }: { exposure: ExposureEvent }) {
  const { t } = useTranslation()
  const o = exposure.severity_override
  if (!o) return <SeverityBadge severity={exposure.severity} />
  const reported = t(`severity.${o.reported_severity}`, SEVERITY_LABELS[o.reported_severity])
  return (
    <div className="flex flex-col items-start gap-0.5">
      <SeverityBadge severity={exposure.severity} />
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-help text-xs text-muted-foreground underline decoration-dotted underline-offset-2">
            {t('exposures.severity.changedFrom', 'Changed from {severity}', { severity: reported })}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{o.reason}</TooltipContent>
      </Tooltip>
    </div>
  )
}
