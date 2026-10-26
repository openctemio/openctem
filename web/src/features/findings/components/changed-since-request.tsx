'use client'

import { useTranslation } from '@/context/i18n-provider'
import { formatList } from '@/lib/format-list'
import { cn } from '@/lib/utils'

/** English fallbacks; the key is myWork.changed.<reason>. */
export const CHANGE_LABELS: Record<string, string> = {
  kev: 'now in CISA KEV',
  severity_critical: 'severity now critical',
  severity_high: 'severity now high',
  priority_p0: 'priority now P0',
  priority_p1: 'priority now P1',
  exploit_validated: 'exploit validated',
  epss_at_or_above_threshold: 'EPSS now above the threshold',
  crown_jewel: 'asset is a crown jewel',
  internet_exposed: 'asset is internet exposed',
}

/**
 * "Changed since the request: now in CISA KEV, severity now critical": what
 * holds on the finding now that did not when the request was made, in the
 * danger colour, so an approver never decides on the picture the requester
 * saw. One rendering for My Work and the finding page. Nothing when nothing
 * changed.
 */
export function ChangedSinceRequest({
  changes,
  className,
}: {
  changes?: string[] | null
  className?: string
}) {
  const { t, locale } = useTranslation()
  if (!changes || changes.length === 0) return null
  return (
    <span
      data-slot="changed-since-request"
      className={cn('text-meta font-medium text-destructive', className)}
    >
      {t('myWork.changedSince', 'Changed since the request: {changes}', {
        changes: formatList(
          changes.map((c) => t(`myWork.changed.${c}`, CHANGE_LABELS[c] ?? c)),
          locale
        ),
      })}
    </span>
  )
}
