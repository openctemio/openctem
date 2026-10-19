'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { humanizeIdentifier } from '@/lib/humanize-identifier'
import { STATUS_TONE_CLASS, type StatusDomain, statusEntry } from '@/lib/status-tones'
import { cn } from '@/lib/utils'

/**
 * A status as a dot and its label, from the one status registry
 * (lib/status-tones.ts). The label carries the meaning, never the colour
 * alone. A value the registry does not know shows humanized, in the neutral
 * tone.
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
  const tone = STATUS_TONE_CLASS[entry?.tone ?? 'neutral']
  return (
    <Badge
      variant="outline"
      className={cn('gap-1.5 rounded-full border-transparent', tone.chip, className)}
      title={title}
      data-state={value}
      data-tone={entry?.tone ?? 'neutral'}
    >
      <span aria-hidden className={cn('size-1.5 rounded-full', tone.dot)} />
      {entry ? t(entry.labelKey) : humanizeIdentifier(value)}
    </Badge>
  )
}
