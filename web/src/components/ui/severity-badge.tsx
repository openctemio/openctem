'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { normalizeSeverity, SEVERITY_LABEL_KEYS, SEVERITY_LABELS } from '@/lib/severity'
import {
  SEVERITY_BADGE_SOFT,
  SEVERITY_DOT_COLORS,
  SEVERITY_TEXT_COLORS,
} from '@/lib/severity-colors'
import { SeverityGlyph } from '@/components/ui/severity-glyph'

export interface SeverityBadgeProps {
  /** A severity value from the API; `none` shows as info, unknown values as neutral. */
  severity: string | null | undefined
  /** Override the label (a count, "Informational"). */
  children?: React.ReactNode
  /**
   * `inline` (default): a shape mark and coloured text, no pill: table and list
   * rows. `soft`: the tinted pill with a dot, for counts and summary tiles.
   */
  variant?: 'inline' | 'soft'
  className?: string
}

/**
 * A severity: the one rendering. Inline (default) is a distinct shape plus the
 * coloured label, so it stays readable without colour; soft is the tinted pill
 * for counts. Priority classes use PriorityBadge, a different shape and colour
 * system. The label is always shown.
 */
export function SeverityBadge({
  severity,
  children,
  variant = 'inline',
  className,
}: SeverityBadgeProps) {
  const { t } = useTranslation()
  const level = severity ? normalizeSeverity(severity) : null
  const label = level
    ? t(SEVERITY_LABEL_KEYS[level], SEVERITY_LABELS[level])
    : t('severity.unknown', 'Unknown')
  if (variant === 'inline') {
    return (
      <span
        data-slot="severity-badge"
        data-severity={level ?? 'unknown'}
        data-variant="inline"
        className={cn(
          'inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap text-xs font-medium',
          level ? SEVERITY_TEXT_COLORS[level] : 'text-muted-foreground',
          className
        )}
      >
        <SeverityGlyph level={level} />
        {children ?? label}
      </span>
    )
  }
  return (
    <span
      data-slot="severity-badge"
      data-severity={level ?? 'unknown'}
      data-variant="soft"
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
