'use client'

import { TrendingUp } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { Sparkline } from './sparkline'
import { METRIC_KEYS, type CtemMaturityTrend, type MetricKey } from '../api/use-ctem-maturity'

const METRIC_FALLBACK: Record<MetricKey, string> = {
  mttr_hours: 'MTTR (hours)',
  findings_opened: 'Findings opened',
  findings_resolved: 'Findings resolved',
  p_class_churn: 'Priority churn',
  validation_coverage: 'Validation coverage (%)',
  scope_drift_size: 'Scope drift',
}

function formatValue(v: number, locale: string): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(v)
}

/**
 * MaturityTrendCard plots each of the six persisted metrics across the
 * tenant's closed cycles (ascending). One compact sparkline per metric
 * with its latest value — enough to read direction at a glance.
 */
export function MaturityTrendCard({
  trend,
  className,
}: {
  trend: CtemMaturityTrend
  className?: string
}) {
  const { t, locale } = useTranslation()
  const cycleCount = trend.cycles_analyzed

  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <TrendingUp className="text-muted-foreground h-4 w-4" />
          {t('insights.maturity.trends.title', 'Metric trends')}
        </CardTitle>
        <CardDescription>
          {t(
            cycleCount === 1
              ? 'insights.maturity.trends.description.one'
              : 'insights.maturity.trends.description.other',
            undefined,
            { count: cycleCount }
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="divide-y">
          {METRIC_KEYS.map((key) => {
            const series = trend.series[key] ?? []
            // A cycle without a sample (null) is a gap, not a 0.
            const values = series.map((p) => p.value).filter((v): v is number => v !== null)
            const last = series.length > 0 ? series[series.length - 1].value : null
            const latest = last === null ? undefined : last
            return (
              <li key={key} className="flex items-center justify-between gap-4 py-2.5">
                <span className="text-sm">
                  {t(`insights.maturity.metric.${key}`, METRIC_FALLBACK[key])}
                </span>
                <div className="flex items-center gap-3">
                  <Sparkline
                    values={values}
                    ariaLabel={t('insights.maturity.trends.sparkline', '{metric} trend', {
                      metric: t(`insights.maturity.metric.${key}`, METRIC_FALLBACK[key]),
                    })}
                  />
                  <span className="text-muted-foreground w-12 text-end text-sm font-medium tabular-nums">
                    {latest === undefined ? '—' : formatValue(latest, locale)}
                  </span>
                </div>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
