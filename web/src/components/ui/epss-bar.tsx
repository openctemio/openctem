'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { formatEpssScore, EPSS_PLACEHOLDER } from '@/lib/epss'

/** From this probability the bar takes the high-severity colour. */
export const EPSS_BAR_HOT = 0.5

export interface EpssBarProps {
  /** EPSS probability, 0 to 1. Missing shows an empty track and a dash. */
  score: number | null | undefined
  className?: string
}

/**
 * EPSS as a short bar with its percentage: the list cell for "how likely is
 * exploitation". The bar is a neutral grey; from 50% it takes the
 * high-severity colour, and the number always carries the value, so colour
 * is never the only cue. A missing score shows an empty track and a dash.
 */
export function EpssBar({ score, className }: EpssBarProps) {
  const { t } = useTranslation()
  const has = typeof score === 'number' && Number.isFinite(score)
  const value = has ? Math.min(1, Math.max(0, score)) : 0
  const hot = has && value >= EPSS_BAR_HOT
  const pct = has ? (value >= 0.995 ? '99%+' : formatEpssScore(value, 0)) : EPSS_PLACEHOLDER
  const label = has
    ? t('findings.list.epss', 'EPSS {score}', { score: pct })
    : t('findings.list.epssNone', 'No EPSS score')
  return (
    <span
      data-slot="epss-bar"
      data-hot={hot || undefined}
      role="img"
      aria-label={label}
      title={t(
        'findings.list.epssBarHint',
        'EPSS: estimated probability of exploitation in the next 30 days'
      )}
      className={cn('inline-flex items-center gap-2 text-meta tabular-nums', className)}
    >
      <span
        aria-hidden
        className="bg-surface-sunken ring-border/60 h-1 w-11 shrink-0 overflow-hidden rounded-full ring-1 ring-inset"
      >
        <span
          className={cn('block h-full', hot ? 'bg-sev-high' : 'bg-muted-foreground')}
          style={{ width: `${Math.round(value * 100)}%` }}
        />
      </span>
      <span aria-hidden className={cn(has ? 'text-foreground' : 'text-muted-foreground')}>
        {pct}
      </span>
    </span>
  )
}
