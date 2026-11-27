'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { SEVERITY_DOT_COLORS, SEVERITY_ORDER, type SeverityLevel } from '@/lib/severity-colors'
import { SEVERITY_LABELS as SHARED_SEVERITY_LABELS } from '@/lib/severity'

export type SeverityCounts = Partial<Record<SeverityLevel, number>>

interface SeverityStripProps {
  counts: SeverityCounts
  className?: string
}

const LABELS: Record<SeverityLevel, string> = SHARED_SEVERITY_LABELS

/**
 * Compact severity breakdown: one stacked bar plus a count per severity.
 * Sized for drawers and cards, where a full chart would be too heavy. Colors
 * come from the single-source severity tokens.
 */
export function SeverityStrip({ counts, className }: SeverityStripProps) {
  const { t } = useTranslation()
  const label = (s: SeverityLevel) => t(`severity.${s}`, LABELS[s])
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0)

  return (
    <div className={cn('space-y-2', className)}>
      <div
        className="flex h-2 w-full overflow-hidden rounded-full bg-muted"
        role="img"
        aria-label={SEVERITY_ORDER.map((s) => `${counts[s] ?? 0} ${label(s)}`).join(', ')}
      >
        {total > 0 &&
          SEVERITY_ORDER.map((s) => {
            const n = counts[s] ?? 0
            if (n === 0) return null
            return (
              <div
                key={s}
                className={SEVERITY_DOT_COLORS[s]}
                style={{ width: `${(n / total) * 100}%` }}
              />
            )
          })}
      </div>
      {/* Wraps instead of cutting: a translated label ("Nghiêm trọng") is wider than a fifth of a phone card. */}
      <dl className="flex flex-wrap gap-x-4 gap-y-2">
        {SEVERITY_ORDER.map((s) => {
          const n = counts[s] ?? 0
          return (
            <div key={s}>
              <dt className="flex items-center gap-1 text-cap text-muted-foreground">
                <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', SEVERITY_DOT_COLORS[s])} />
                <span className="whitespace-nowrap">{label(s)}</span>
              </dt>
              <dd
                className={cn(
                  'text-sm font-semibold tabular-nums',
                  n === 0 && 'font-normal text-muted-foreground'
                )}
              >
                {n}
              </dd>
            </div>
          )
        })}
      </dl>
    </div>
  )
}
