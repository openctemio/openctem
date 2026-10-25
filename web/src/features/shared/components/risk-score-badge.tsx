'use client'

import { SeverityBadge } from '@/components/ui/severity-badge'
import { HealthStatus } from '@/components/ui/health-status'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import { Clock } from 'lucide-react'
import { getRiskLevel } from '../types'
import { useRiskThresholds } from '@/context/risk-scoring-provider'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Freshness of a stored risk score (from the asset API's risk_scored_at and
 * risk_score_pending): `unscored` = never computed, so the score is not a
 * real 0; `calculating` = never computed and the first score is queued;
 * `pending` = scored, and a rescore is queued.
 */
export type RiskScoreState = 'scored' | 'pending' | 'calculating' | 'unscored'

/** The freshness state of an asset's stored score; undefined fields = scored. */
export function riskScoreState(a: {
  riskScored?: boolean
  riskScorePending?: boolean
}): RiskScoreState {
  if (a.riskScored === false) return a.riskScorePending ? 'calculating' : 'unscored'
  return a.riskScorePending ? 'pending' : 'scored'
}

interface RiskScoreBadgeProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  className?: string
  /**
   * Name the dimension in the visible text ("Risk: 73"). Use it wherever no
   * column header or field label already says "Risk": phone cards, headers,
   * chip rows. The tooltip and the accessible name always carry it.
   */
  labelled?: boolean
  /**
   * Freshness of the score. A never-scored asset shows "Not yet scored" and a
   * queued first score "Calculating…", never a fake "0". A queued rescore of
   * a scored asset keeps the score with a spinner.
   */
  state?: RiskScoreState
}

const badgeSizeClasses = {
  sm: 'text-xs',
  md: 'text-sm',
  lg: 'text-base',
}

/**
 * A risk score: the glyph and colour of its band (SeverityBadge score) and the
 * number, never a solid fill. The band word ("High") is in the tooltip and the
 * accessible name, never next to the number: criticality uses the same words,
 * and a row showing "High" twice reads as one dimension (research/271).
 * Freshness states are machine states: a never-scored asset is "unknown", a
 * queued first score is "running", a queued rescore keeps the score with a
 * clock and a hint.
 */
export function RiskScoreBadge({
  score,
  size = 'md',
  className,
  labelled = false,
  state = 'scored',
}: RiskScoreBadgeProps) {
  const { t } = useTranslation()
  const thresholds = useRiskThresholds()
  const level = getRiskLevel(score, thresholds)
  const band = t(`riskScore.level.${level.key}`, level.label)
  const value = !Number.isFinite(score)
    ? '0'
    : Number.isInteger(score)
      ? String(score)
      : score.toFixed(1)

  if (state === 'calculating') {
    return (
      <HealthStatus
        state="run"
        value="calculating"
        label={t('riskScore.calculating', 'Calculating…')}
        title={t(
          'riskScore.calculatingHint',
          'Its inputs changed; the new score is being computed.'
        )}
        className={cn(badgeSizeClasses[size], className)}
      />
    )
  }

  if (state === 'unscored') {
    return (
      <HealthStatus
        state="unknown"
        value="unscored"
        label={t('riskScore.notScored', 'Not yet scored')}
        title={t('riskScore.notScoredHint', "This asset's risk score has not been computed yet.")}
        className={cn(badgeSizeClasses[size], className)}
      />
    )
  }

  // A zero is no open risk, not a low score: say so instead of "0".
  const none = level.key === 'none'
  const text = none
    ? band
    : labelled
      ? t('riskScore.labelled', 'Risk: {score}', { score: value })
      : value
  const scoreName = none
    ? t('riskScore.nameNone', 'Risk: {band}', { band })
    : t('riskScore.name', 'Risk {score} of 100, {band}', { score: value, band })
  // A queued rescore keeps the score and adds a clock; the badge's own name
  // says what the clock means, so hovering either part explains it.
  const name =
    state === 'pending'
      ? t('riskScore.namePending', '{name}. Its inputs changed; the new score is being computed.', {
          name: scoreName,
        })
      : scoreName
  const badge = (
    <SeverityBadge
      score={score}
      aria-label={name}
      title={name}
      className={cn(badgeSizeClasses[size], className)}
    >
      {text}
    </SeverityBadge>
  )
  if (state !== 'pending') return badge
  return (
    <span className="inline-flex items-center gap-1" title={name} data-state="pending">
      {badge}
      <Clock className="size-3 text-muted-foreground" aria-hidden />
    </span>
  )
}

interface RiskScoreMeterProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  showTooltip?: boolean
  className?: string
}

/**
 * Risk Score Meter - Visual representation of risk score (0-100)
 * Shows a progress bar with color coding based on risk level
 */
export function RiskScoreMeter({
  score,
  size = 'md',
  showLabel = true,
  showTooltip = true,
  className,
}: RiskScoreMeterProps) {
  const { t } = useTranslation()
  const thresholds = useRiskThresholds()
  const level = getRiskLevel(score, thresholds)
  const { color } = level
  const label = t(`riskScore.level.${level.key}`, level.label)

  const sizeConfig = {
    sm: { height: 'h-1.5', text: 'text-xs', width: 'w-16' },
    md: { height: 'h-2', text: 'text-sm', width: 'w-20' },
    lg: { height: 'h-2.5', text: 'text-base', width: 'w-24' },
  }

  const { height, text, width } = sizeConfig[size]

  const meter = (
    <div className={cn('flex items-center gap-2', className)}>
      <div className={cn('relative rounded-full bg-muted overflow-hidden', height, width)}>
        <div
          className={cn('absolute left-0 top-0 h-full rounded-full transition-all', color)}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>
      {showLabel && <span className={cn('font-medium tabular-nums', text)}>{score}</span>}
    </div>
  )

  if (!showTooltip) return meter

  return (
    <TooltipProvider>
      <Tooltip delayDuration={200}>
        <TooltipTrigger asChild>{meter}</TooltipTrigger>
        <TooltipContent side="top">
          <p className="font-medium">
            {t('riskScore.meterTooltip', 'Risk score: {score}/100', { score })}
          </p>
          <p className="text-xs text-muted-foreground">
            {t('riskScore.levelTooltip', 'Level: {level}', { level: label })}
          </p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

interface RiskScoreGaugeProps {
  score: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  className?: string
}

/**
 * Risk Score Gauge - Circular visual representation of risk score
 * Great for dashboard cards and summary views
 */
export function RiskScoreGauge({
  score,
  size = 'md',
  showLabel = true,
  className,
}: RiskScoreGaugeProps) {
  const { t } = useTranslation()
  const thresholds = useRiskThresholds()
  const level = getRiskLevel(score, thresholds)
  const label = t(`riskScore.level.${level.key}`, level.label)

  const sizeConfig = {
    sm: { diameter: 40, strokeWidth: 4, fontSize: 'text-xs' },
    md: { diameter: 60, strokeWidth: 5, fontSize: 'text-sm' },
    lg: { diameter: 80, strokeWidth: 6, fontSize: 'text-base' },
  }

  const { diameter, strokeWidth, fontSize } = sizeConfig[size]
  const radius = (diameter - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const progress = Math.min(100, Math.max(0, score)) / 100
  const strokeDashoffset = circumference * (1 - progress)

  // Extract color name for stroke
  const strokeColor = level.stroke

  return (
    <div className={cn('relative inline-flex items-center justify-center', className)}>
      <svg
        width={diameter}
        height={diameter}
        viewBox={`0 0 ${diameter} ${diameter}`}
        className="transform -rotate-90"
      >
        {/* Background circle */}
        <circle
          cx={diameter / 2}
          cy={diameter / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-muted"
        />
        {/* Progress circle */}
        <circle
          cx={diameter / 2}
          cy={diameter / 2}
          r={radius}
          fill="none"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className={cn('transition-all duration-500', strokeColor)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn('font-bold tabular-nums', fontSize)}>{score}</span>
        {showLabel && size !== 'sm' && (
          <span className="text-[8px] text-muted-foreground uppercase">{label}</span>
        )}
      </div>
    </div>
  )
}
