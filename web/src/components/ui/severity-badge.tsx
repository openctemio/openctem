'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import {
  normalizeSeverity,
  SEVERITY_LABEL_KEYS,
  SEVERITY_LABELS,
  type SeverityLevel,
} from '@/lib/severity'
import {
  SEVERITY_BADGE_SOFT,
  SEVERITY_DOT_COLORS,
  SEVERITY_TEXT_COLORS,
} from '@/lib/severity-colors'
import { SeverityGlyph } from '@/components/ui/severity-glyph'
import { useRiskThresholds } from '@/context/risk-scoring-provider'
import { getRiskLevel } from '@/features/shared/types'

export interface SeverityBadgeProps {
  /** A severity value from the API; `none` shows as info, unknown values as neutral. */
  severity?: string | null | undefined
  /**
   * A 0-100 risk score instead of a severity: the glyph of its band (from the
   * organization's thresholds) and the number as the text. The band word is
   * never shown next to the number: "High" is also a criticality word, and two
   * "High" labels on one row read as one dimension (research/271). Risk is
   * rendered through RiskScoreBadge, which names it.
   */
  score?: number | null
  /** Override the label (a count, "Informational"). */
  children?: React.ReactNode
  /** Override the accessible name (RiskScoreBadge names the dimension). */
  'aria-label'?: string
  /** A native tooltip. */
  title?: string
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
  score,
  children,
  variant = 'inline',
  className,
  'aria-label': ariaLabel,
  title,
}: SeverityBadgeProps) {
  const { t } = useTranslation()
  const thresholds = useRiskThresholds()
  const hasScore = typeof score === 'number' && Number.isFinite(score)
  const band = hasScore ? getRiskLevel(score, thresholds) : null
  const level: SeverityLevel | null = band
    ? band.key === 'minimal' || band.key === 'none'
      ? 'info'
      : band.key
    : severity
      ? (normalizeSeverity(severity) ?? null)
      : null
  const bandWord = band ? t(`riskScore.level.${band.key}`, band.label) : null
  const label = hasScore
    ? `${Number.isInteger(score) ? score : score.toFixed(1)}`
    : level
      ? t(SEVERITY_LABEL_KEYS[level], SEVERITY_LABELS[level])
      : t('severity.unknown', 'Unknown')
  const aria =
    ariaLabel ??
    (hasScore ? `${Number.isInteger(score) ? score : score.toFixed(1)}, ${bandWord}` : undefined)
  if (variant === 'inline') {
    return (
      <span
        data-slot="severity-badge"
        data-severity={level ?? 'unknown'}
        data-variant="inline"
        data-score={hasScore ? score : undefined}
        aria-label={aria}
        title={title}
        className={cn(
          'inline-flex w-fit shrink-0 items-center gap-1 whitespace-nowrap text-xs font-medium',
          level ? SEVERITY_TEXT_COLORS[level] : 'text-muted-foreground',
          className
        )}
      >
        <SeverityGlyph level={level ?? null} />
        {children ?? label}
      </span>
    )
  }
  return (
    <span
      data-slot="severity-badge"
      data-severity={level ?? 'unknown'}
      data-variant="soft"
      data-score={hasScore ? score : undefined}
      aria-label={aria}
      title={title}
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
