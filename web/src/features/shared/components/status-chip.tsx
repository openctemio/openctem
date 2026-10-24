'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import { useTranslation } from '@/context/i18n-provider'
import { humanizeIdentifier } from '@/lib/humanize-identifier'
import { type StatusDomain, statusEntry } from '@/lib/status-tones'
import { DashedCircleGlyph } from '@/components/ui/status-glyphs'

/**
 * A workflow status as a lozenge, from the one status registry
 * (lib/status-tones.ts). The label and the progression icon carry the
 * meaning, never the colour alone. A value the registry does not know shows
 * humanized, as an untouched (triage) lozenge.
 */
export function StatusChip({
  domain,
  value,
  title,
  className,
}: {
  domain: StatusDomain
  value: string
  /** Tooltip: what the status means. */
  title?: string
  className?: string
}) {
  const { t } = useTranslation()
  const entry = statusEntry(domain, value)
  return (
    <span title={title} className="inline-flex">
      <StatusLozenge
        tone={entry?.tone ?? 'triage'}
        icon={entry?.icon ?? DashedCircleGlyph}
        label={entry ? t(entry.labelKey) : humanizeIdentifier(value)}
        value={value}
        className={className}
      />
    </span>
  )
}
