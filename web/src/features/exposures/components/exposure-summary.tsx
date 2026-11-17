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

/**
 * The summary sentence, or the description when the API had no sentence.
 * `inline`: a table cell of its own (one line, the whole sentence as the
 * tooltip, a dash when there is none).
 */
export function ExposureSummaryLine({
  exposure,
  inline = false,
}: {
  exposure: ExposureEvent
  inline?: boolean
}) {
  const { t } = useTranslation()
  const text = exposureSummaryText(exposure, t) || exposure.description || ''
  if (inline) {
    return text ? (
      <span className="block truncate text-muted-foreground" title={text}>
        {text}
      </span>
    ) : (
      <span className="text-muted-foreground">—</span>
    )
  }
  if (!text) return null
  return <p className="line-clamp-1 text-xs text-muted-foreground">{text}</p>
}

/**
 * The effective severity, with a note when it is an analyst's decision.
 * `inline`: the note is a short mark beside the badge (a one-line table row);
 * its tooltip says what it was changed from and why.
 */
export function ExposureSeverityCell({
  exposure,
  inline = false,
}: {
  exposure: ExposureEvent
  inline?: boolean
}) {
  const { t } = useTranslation()
  const o = exposure.severity_override
  if (!o) return <SeverityBadge severity={exposure.severity} />
  const reported = t(`severity.${o.reported_severity}`, SEVERITY_LABELS[o.reported_severity])
  const changed = t('exposures.severity.changedFrom', 'Changed from {severity}', {
    severity: reported,
  })
  if (inline) {
    return (
      <span className="flex items-center gap-1.5 whitespace-nowrap">
        <SeverityBadge severity={exposure.severity} />
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              tabIndex={0}
              className="cursor-help rounded-sm text-xs text-muted-foreground underline decoration-dotted underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={`${changed}. ${o.reason}`}
            >
              {t('exposures.severity.changedShort', 'Changed')}
            </span>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">
            <p className="font-medium">{changed}</p>
            <p>{o.reason}</p>
          </TooltipContent>
        </Tooltip>
      </span>
    )
  }
  return (
    <div className="flex flex-col items-start gap-0.5">
      <SeverityBadge severity={exposure.severity} />
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-help text-xs text-muted-foreground underline decoration-dotted underline-offset-2">
            {changed}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{o.reason}</TooltipContent>
      </Tooltip>
    </div>
  )
}
