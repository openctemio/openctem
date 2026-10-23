'use client'

import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import {
  epssScoreToPercent,
  formatEpssPercentile,
  formatEpssScore,
  formatEpssTopPercent,
} from '@/lib/epss'
import { TrendingUp } from 'lucide-react'

/**
 * EPSS is a probability, not a severity, so it has no hue of its own: the band
 * (FIRST.org guidance: above 70%, 40-70%, 10-40%, up to 10%) is spoken in the
 * tooltip text and shown by the meter's length, never by a severity colour.
 */
type EpssBand = 'veryHigh' | 'high' | 'moderate' | 'low'

const BAND_TEXT: Record<EpssBand, { label: string; hint: string }> = {
  veryHigh: { label: 'Very high likelihood', hint: 'Above 70%. Prioritise immediately.' },
  high: { label: 'High likelihood', hint: '40% to 70%. Address soon.' },
  moderate: { label: 'Moderate likelihood', hint: '10% to 40%.' },
  low: { label: 'Lower likelihood', hint: 'Up to 10%.' },
}

function getEPSSBand(score: number): EpssBand {
  if (score > 0.7) return 'veryHigh'
  if (score > 0.4) return 'high'
  if (score > 0.1) return 'moderate'
  return 'low'
}

function useBandText(score: number) {
  const { t } = useTranslation()
  const band = getEPSSBand(score)
  return {
    label: t(`findings.epss.band.${band}`, BAND_TEXT[band].label),
    hint: t(`findings.epss.bandHint.${band}`, BAND_TEXT[band].hint),
  }
}

interface EPSSScoreBadgeProps {
  score: number | null | undefined
  /** EPSS percentile rank, 0–100 (the API's canonical scale). */
  percentile?: number | null
  showPercentile?: boolean
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

/**
 * EPSS Score Badge - Displays Exploit Prediction Scoring System score
 * Score is 0-1 representing probability of exploitation in the next 30 days
 */
export function EPSSScoreBadge({
  score,
  percentile,
  showPercentile = false,
  size = 'md',
  className,
}: EPSSScoreBadgeProps) {
  const { t } = useTranslation()
  const { label: bandLabel, hint } = useBandText(score ?? 0)
  if (score === null || score === undefined) {
    return (
      <Badge variant="outline" className={cn('text-muted-foreground', className)}>
        {t('findings.epss.none', 'No EPSS')}
      </Badge>
    )
  }

  const displayScore = formatEpssScore(score)

  const sizeClasses = {
    sm: 'text-xs px-1.5 py-0.5',
    md: 'text-sm px-2 py-0.5',
    lg: 'text-base px-2.5 py-1',
  }

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>
          <Badge variant="outline" className={cn('tabular-nums', sizeClasses[size], className)}>
            <TrendingUp className="me-1 h-3 w-3" />
            {displayScore}
            {showPercentile && percentile !== null && percentile !== undefined && (
              <span className="ms-1 opacity-80">({formatEpssPercentile(percentile, 0)})</span>
            )}
          </Badge>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <div className="space-y-1">
            <p className="font-semibold">
              {t('findings.epss.score', 'EPSS score: {score}', { score: displayScore })}
            </p>
            <p className="text-sm">{bandLabel}</p>
            {percentile !== null && percentile !== undefined && (
              <p className="text-sm">
                {t('findings.epss.percentile', 'Percentile: {percentile} ({top})', {
                  percentile: formatEpssPercentile(percentile),
                  top: formatEpssTopPercent(percentile),
                })}
              </p>
            )}
            <p className="text-xs text-muted-foreground">{hint}</p>
            <p className="text-xs text-muted-foreground">
              {t('findings.epss.window', 'Probability of exploitation in the next 30 days')}
            </p>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

interface EPSSScoreMeterProps {
  score: number | null | undefined
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  className?: string
}

/**
 * EPSS Score Meter - Visual progress bar for EPSS score
 */
export function EPSSScoreMeter({
  score,
  size = 'md',
  showLabel = true,
  className,
}: EPSSScoreMeterProps) {
  if (score === null || score === undefined) {
    return <span className="text-muted-foreground text-sm">-</span>
  }

  const percentage = epssScoreToPercent(score)

  const sizeConfig = {
    sm: { height: 'h-1.5', text: 'text-xs', width: 'w-16' },
    md: { height: 'h-2', text: 'text-sm', width: 'w-20' },
    lg: { height: 'h-2.5', text: 'text-base', width: 'w-24' },
  }

  const { height, text, width } = sizeConfig[size]

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div className={cn('relative rounded-full bg-muted overflow-hidden', height, width)}>
        <div
          className="absolute left-0 top-0 h-full rounded-full bg-foreground/70 transition-all"
          style={{ width: `${Math.min(100, Math.max(0, percentage))}%` }}
        />
      </div>
      {showLabel && (
        <span className={cn('font-medium tabular-nums', text)}>{formatEpssScore(score)}</span>
      )}
    </div>
  )
}

interface EPSSIndicatorProps {
  score: number | null | undefined
  compact?: boolean
  className?: string
}

/**
 * EPSS Indicator - Compact icon-based indicator for EPSS risk level
 */
export function EPSSIndicator({ score, compact = false, className }: EPSSIndicatorProps) {
  const { t } = useTranslation()
  const { label } = useBandText(score ?? 0)
  if (score === null || score === undefined) {
    return null
  }

  if (compact) {
    return (
      <TooltipProvider>
        <Tooltip delayDuration={200}>
          <TooltipTrigger asChild>
            <div className={cn('rounded border border-border p-1', className)}>
              <TrendingUp className="h-4 w-4" aria-hidden />
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <p>
              {t('findings.epss.compact', 'EPSS: {score} ({band})', {
                score: formatEpssScore(score),
                band: label,
              })}
            </p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
  }

  return (
    <div
      className={cn(
        'flex items-center gap-1 rounded border border-border px-2 py-1 text-sm tabular-nums',
        className
      )}
    >
      <TrendingUp className="h-4 w-4" aria-hidden />
      <span>{formatEpssScore(score)}</span>
    </div>
  )
}
