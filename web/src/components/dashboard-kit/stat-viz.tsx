'use client'

/**
 * Single-figure visualizations: Stat (value, change, sparkline, target) and
 * Progress (a share against its target). Null figures render "—": the frame's
 * not_measured state explains why.
 */

import { useTranslation } from '@/context/i18n-provider'
import { formatCount, formatMetric, type MetricUnit } from '@/lib/format-metric'
import { cn } from '@/lib/utils'
import { changeOf, targetStatus } from './compare'
import { DeltaText, DrillLink, Sparkline, TargetChip } from './viz-parts'
import type { DurationResult, Polarity, RatioResult, ScalarResult } from './types'

export interface StatVizProps {
  result: ScalarResult | RatioResult | DurationResult
  /** Unit of a scalar (counts by default). Ratios are percentages, durations hours. */
  unit?: MetricUnit
  polarity?: Polarity
  /** A short line under the value ("P0 + P1 open"). */
  caption?: string
  /** The list the value opens (same-origin path). */
  href?: string
  comparedTo?: string
}

interface StatParts {
  value: number | null
  previous: number | null | undefined
  delta: number | null
  unit: MetricUnit
  detail?: string
  /** The list the detail's population opens ("of 40 open"). */
  detailHref?: string
}

function useParts(result: StatVizProps['result'], unit: MetricUnit): StatParts {
  const { t, locale } = useTranslation()
  switch (result.shape) {
    case 'ratio':
      return {
        value: result.value_pct,
        previous: result.previous_pct,
        delta: changeOf(result.value_pct, result.previous_pct),
        unit: 'percent',
        detail: t('dashboardKit.stat.ofTotal', '{num} of {den}', {
          num: formatCount(result.num, locale),
          den: formatCount(result.den, locale),
        }),
      }
    case 'duration':
      return {
        value: result.median,
        previous: result.previous_median,
        delta: changeOf(result.median, result.previous_median),
        unit: 'hours',
        detail: t('dashboardKit.stat.durationDetail', 'median, p90 {p90}, {n} fixed', {
          p90: formatMetric(result.p90, 'hours', locale),
          n: formatCount(result.n, locale),
        }),
      }
    default:
      return {
        value: result.value,
        previous: result.previous,
        delta: result.delta ?? changeOf(result.value, result.previous),
        unit,
        detail:
          result.of != null
            ? t('dashboardKit.stat.ofOpen', 'of {den} open', {
                den: formatCount(result.of, locale),
              })
            : undefined,
        detailHref: result.of_href ?? undefined,
      }
  }
}

export function StatViz({
  result,
  unit = 'count',
  polarity = 'neutral',
  caption,
  href,
  comparedTo,
}: StatVizProps) {
  const { locale } = useTranslation()
  const parts = useParts(result, unit)
  const target = result.target ?? null
  const series = result.shape === 'duration' ? undefined : result.series
  const valueText = formatMetric(parts.value, parts.unit, locale)
  const value = (
    <span
      className={cn(
        'text-3xl font-semibold tabular-nums leading-none',
        parts.value == null && 'text-muted-foreground'
      )}
    >
      {valueText}
    </span>
  )
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-1.5">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <DrillLink to={href} className="hover:underline">
          {value}
        </DrillLink>
        {caption && <span className="text-xs text-muted-foreground">{caption}</span>}
      </div>
      {parts.detail && (
        <p className="text-xs text-muted-foreground">
          {parts.detailHref ? (
            <DrillLink to={parts.detailHref} className="hover:underline">
              {parts.detail}
            </DrillLink>
          ) : (
            parts.detail
          )}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <DeltaText
          delta={parts.delta}
          unit={parts.unit}
          polarity={polarity}
          comparedTo={comparedTo}
          previous={parts.previous}
        />
        <TargetChip value={parts.value} target={target} unit={parts.unit} />
      </div>
      <Sparkline points={series} unit={parts.unit} className="mt-auto" />
    </div>
  )
}

const FILL_BY_STATUS = {
  met: 'bg-success',
  near: 'bg-warning',
  missed: 'bg-destructive',
  unmeasured: 'bg-muted-foreground',
} as const

/** A share as a bar against its target, with the value, change and target chip. */
export function ProgressViz({
  result,
  polarity = 'up_good',
  href,
  comparedTo,
}: {
  result: RatioResult
  polarity?: Polarity
  href?: string
  comparedTo?: string
}) {
  const { t, locale } = useTranslation()
  const pct = result.value_pct
  const status = targetStatus(pct, result.target)
  const fill = status ? FILL_BY_STATUS[status] : 'bg-primary'
  const width = pct == null ? 0 : Math.max(0, Math.min(100, pct))
  const valueText = formatMetric(pct, 'percent', locale)
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <DrillLink to={href} className="text-3xl font-semibold tabular-nums hover:underline">
          {valueText}
        </DrillLink>
        <TargetChip value={pct} target={result.target} unit="percent" />
      </div>
      <div
        className="relative h-2.5 w-full rounded-full bg-muted"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct ?? undefined}
        aria-valuetext={valueText}
        aria-label={t('dashboardKit.stat.ofTotal', '{num} of {den}', {
          num: formatCount(result.num, locale),
          den: formatCount(result.den, locale),
        })}
      >
        <div className={cn('h-full rounded-full', fill)} style={{ width: `${width}%` }} />
        {result.target && result.target.value >= 0 && result.target.value <= 100 && (
          <div
            className="absolute -top-1 h-4.5 w-0.5 bg-foreground"
            style={{ left: `calc(${result.target.value}% - 1px)` }}
            aria-hidden
          />
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        {t('dashboardKit.stat.ofTotal', '{num} of {den}', {
          num: formatCount(result.num, locale),
          den: formatCount(result.den, locale),
        })}
      </p>
      <DeltaText
        delta={changeOf(pct, result.previous_pct)}
        unit="percent"
        polarity={polarity}
        comparedTo={comparedTo}
        previous={result.previous_pct}
      />
    </div>
  )
}
