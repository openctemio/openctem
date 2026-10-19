'use client'

import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { formatRiskScore } from '@/features/shared'
import { TrendingUp, TrendingDown } from 'lucide-react'
import dynamic from 'next/dynamic'
import { useTranslation } from '@/context/i18n-provider'
import {
  scoringChangeDates,
  type ExecutiveSummary,
  type RiskTrendPoint,
} from '../../hooks/use-ctem-dashboard'
import { STATE_TEXT } from '../../lib/ctem-colors'
import { WidgetError } from '../widget-error'

// recharts loads after the card's numbers (see trend-charts.tsx).
const P0TrendLine = dynamic(() => import('./trend-charts').then((m) => m.P0TrendLine), {
  ssr: false,
  loading: () => <Skeleton className="h-full min-h-16 w-full" />,
})

interface ExposureHeroProps {
  summary?: ExecutiveSummary
  trend?: RiskTrendPoint[]
  /** Number of exposure chains that traverse a KEV vulnerability. */
  kevChainCount: number
  isLoading?: boolean
  /** The summary read failed: the card shows an error, never zeros. */
  error?: unknown
  onRetry?: () => void
}

/**
 * The P0 line: the stored daily history, ending at today's live count so the
 * line and the big number agree. The last stored point is replaced when it is
 * today's, otherwise today is appended.
 */
export function p0Series(
  trend: RiskTrendPoint[] | undefined,
  liveP0: number | undefined,
  today: string = new Date().toISOString().slice(0, 10)
): { date: string; p0: number }[] {
  const series = (trend ?? []).map((p) => ({ date: p.date, p0: p.p0_open }))
  if (liveP0 === undefined) return series
  const last = series[series.length - 1]
  if (last && last.date.slice(0, 10) >= today) {
    return [...series.slice(0, -1), { date: last.date, p0: liveP0 }]
  }
  return [...series, { date: today, p0: liveP0 }]
}

/** Card header, kept local so the "big number + tiny label" rhythm is consistent. */
function Head({ title, desc }: { title: string; desc: string }) {
  return (
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <span className="text-sm font-semibold tracking-tight">{title}</span>
      <span className="text-[11px] text-muted-foreground">{desc}</span>
    </CardHeader>
  )
}

export function ExposureHero({
  summary,
  trend,
  kevChainCount,
  isLoading,
  error,
  onRetry,
}: ExposureHeroProps) {
  const { t } = useTranslation()
  if (isLoading) {
    return (
      <Card className="gap-4">
        <Head
          title={t('dashboardMetrics.hero.activeExposure')}
          desc={t('dashboardMetrics.hero.exploitableNow')}
        />
        <CardContent className="space-y-4">
          <Skeleton className="h-14 w-40" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-16 w-full" />
        </CardContent>
      </Card>
    )
  }

  if (!summary && error) {
    return (
      <Card className="gap-4">
        <Head
          title={t('dashboardMetrics.hero.activeExposure')}
          desc={t('dashboardMetrics.hero.exploitableNow')}
        />
        <CardContent className="flex flex-1 flex-col">
          <WidgetError onRetry={onRetry} />
        </CardContent>
      </Card>
    )
  }

  const p0 = summary?.p0_open ?? 0
  const resolved = summary?.p0_resolved_period ?? 0
  // Null: no open finding has an SLA, so the share is not measured.
  const slaPct = summary?.sla_compliance_pct ?? null
  const crownJewels = summary?.crown_jewels_at_risk ?? 0

  // Burn-down: P0 open across the window, ending at the live count. Rising =
  // losing ground. The stored history is organization-wide: a scoped viewer
  // gets no line.
  const scoped = summary?.scoped === true
  const series = scoped ? [] : p0Series(trend, summary?.p0_open)
  const first = series[0]?.p0 ?? 0
  const last = series[series.length - 1]?.p0 ?? 0
  const hasTrend = series.length > 1
  const delta = last - first
  const losing = delta > 0
  const TrendIcon = losing ? TrendingUp : TrendingDown

  return (
    <Card className="gap-4">
      <Head
        title={t('dashboardMetrics.hero.activeExposure')}
        desc={t('dashboardMetrics.hero.exploitableNow')}
      />
      <CardContent className="flex flex-1 flex-col">
        {/* Hero number + tiny label */}
        <div className="flex items-center gap-4">
          <span
            className={cn(
              'text-5xl font-semibold leading-none tracking-tight tabular-nums',
              p0 > 0 ? STATE_TEXT.crit : 'text-foreground'
            )}
          >
            {p0}
          </span>
          <div className="flex flex-col leading-tight">
            <span
              className={cn(
                'text-sm font-bold',
                p0 > 0 ? STATE_TEXT.crit : 'text-muted-foreground'
              )}
            >
              P0
            </span>
            <span className="text-xs text-muted-foreground">
              {t('dashboardMetrics.hero.exploitableNow')}
            </span>
          </div>
        </div>

        {/* Compact sub-stats */}
        <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground">
          <span>
            {t('dashboardMetrics.hero.risk')}{' '}
            <span className="font-semibold text-foreground">
              {summary ? formatRiskScore(summary.risk_score_current) : '—'}
            </span>
          </span>
          <span>
            {t('dashboardMetrics.hero.kevChains')}{' '}
            <span className="font-semibold text-foreground">{kevChainCount}</span>
          </span>
          <span>
            {t('dashboardMetrics.hero.crownJewels')}{' '}
            <span
              className={cn('font-semibold', crownJewels > 0 ? STATE_TEXT.crit : 'text-foreground')}
            >
              {crownJewels}
            </span>
          </span>
          <span>
            {t('dashboardMetrics.hero.sla')}{' '}
            <span
              className={cn(
                'font-semibold',
                slaPct !== null && slaPct >= 90 ? STATE_TEXT.good : 'text-foreground'
              )}
            >
              {slaPct === null ? '—' : `${slaPct.toFixed(0)}%`}
            </span>
          </span>
        </div>

        {/* Burn-down */}
        <div className="mt-4 flex flex-1 flex-col">
          <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>
              {t('dashboardMetrics.hero.p0Window', 'P0 open · 90d · {n} resolved this period', {
                n: resolved,
              })}
            </span>
            {hasTrend && delta !== 0 && (
              <span
                className={cn(
                  'flex items-center gap-1',
                  losing ? STATE_TEXT.crit : STATE_TEXT.good
                )}
              >
                <TrendIcon className="h-3 w-3" />
                {losing
                  ? t('dashboardMetrics.hero.losing', 'losing ground')
                  : t('dashboardMetrics.hero.gaining', 'gaining ground')}
              </span>
            )}
          </div>
          {scoped ? (
            <div className="flex flex-1 min-h-16 items-center justify-center text-center text-xs text-muted-foreground">
              {t(
                'dashboardMetrics.priority.trendNotForScope',
                'Trend not available for your scope'
              )}
            </div>
          ) : series.length > 1 ? (
            <div className="w-full flex-1 min-h-16">
              <P0TrendLine
                series={series}
                markers={scoringChangeDates(trend ?? [], 'finding_priority')}
              />
            </div>
          ) : (
            <div className="flex flex-1 min-h-16 items-center justify-center text-xs text-muted-foreground">
              {t('dashboardMetrics.priority.noTrend', 'No trend data yet')}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
