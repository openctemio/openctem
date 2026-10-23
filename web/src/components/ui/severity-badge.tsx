'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { normalizeSeverity, SEVERITY_LABEL_KEYS, SEVERITY_LABELS } from '@/lib/severity'
import { SEVERITY_BADGE_SOFT, SEVERITY_DOT_COLORS } from '@/lib/severity-colors'

export interface SeverityBadgeProps {
  /** A severity value from the API; `none` shows as info, unknown values as neutral. */
  severity: string | null | undefined
  /** Override the label (a count, "Informational"). */
  children?: React.ReactNode
  className?: string
}

/**
 * A severity as a soft pill with a dot (critical..info, CVSS hues). The one
 * rendering of a severity; priority classes use PriorityBadge, a different
 * shape and colour system. The label is always shown.
 */
export function SeverityBadge({ severity, children, className }: SeverityBadgeProps) {
  const { t } = useTranslation()
  const level = severity ? normalizeSeverity(severity) : null
  const label = level
    ? t(SEVERITY_LABEL_KEYS[level], SEVERITY_LABELS[level])
    : t('severity.unknown', 'Unknown')
  return (
    <span
      data-slot="severity-badge"
      data-severity={level ?? 'unknown'}
      className={cn(
        'inline-flex w-fit shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium',
        level ? SEVERITY_BADGE_SOFT[level] : 'border-border bg-muted text-muted-foreground',
        className
      )}
    >
      <span
        aria-hidden
        className={cn(
          'size-1.5 rounded-full',
          level ? SEVERITY_DOT_COLORS[level] : 'bg-muted-foreground'
        )}
      />
      {children ?? label}
    </span>
  )
}
