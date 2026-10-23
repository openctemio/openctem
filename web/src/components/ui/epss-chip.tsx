'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { formatEpssScore } from '@/lib/epss'
import { SignalChip } from '@/components/ui/signal-chip'

/** Probability from which EPSS is worth a place in a list row. */
export const EPSS_CHIP_THRESHOLD = 0.1

export interface EpssChipProps {
  /** EPSS probability, 0 to 1. */
  score: number | null | undefined
  /** Show only from this probability; the detail page passes 0 to always show it. */
  threshold?: number
  /** Decimals of the percentage (default 0; the detail page uses 1 or 2). */
  digits?: number
  className?: string
}

/**
 * EPSS as a neutral SignalChip preset: muted label, the number in the foreground colour, no
 * hue (EPSS is a probability, not a severity). Renders nothing below the
 * threshold, so a row only carries it when it matters.
 */
export function EpssChip({
  score,
  threshold = EPSS_CHIP_THRESHOLD,
  digits = 0,
  className,
}: EpssChipProps) {
  const { t } = useTranslation()
  if (typeof score !== 'number' || !Number.isFinite(score) || score < threshold) return null
  const pct = formatEpssScore(score, digits)
  const text = t('findings.list.epss', 'EPSS {score}', { score: pct })
  return (
    <SignalChip
      slot="epss-chip"
      data-epss={score.toFixed(3)}
      title={t(
        'findings.list.epssHint',
        'Exploit Prediction Scoring System — estimated probability of exploitation in the next 30 days'
      )}
      aria-label={text}
      className={cn('font-normal tabular-nums', className)}
    >
      <span aria-hidden className="text-muted-foreground">
        {t('findings.epss.label', 'EPSS')}
      </span>
      <span aria-hidden className="font-semibold text-foreground">
        {pct}
      </span>
    </SignalChip>
  )
}
