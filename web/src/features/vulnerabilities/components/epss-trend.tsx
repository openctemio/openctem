'use client'

/**
 * EPSS trend (api/docs/architecture/vulnerability-page.md, "EPSS trend"):
 * the daily exploit-prediction score of a CVE over the last 30 feed days.
 * The list shows a small line beside the score, the vulnerability page a
 * chart with the dashboard kit's tooltip and table view. The API sends the
 * history only for CVEs the caller has a finding of.
 */

import { useMemo } from 'react'
import { AreaLineViz, Sparkline, type TimeSeriesResult } from '@/components/dashboard-kit'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { formatDelta } from '@/lib/format-metric'
import { epssChange, epssSeries } from '../lib/epss-trend'
import type { EpssPoint } from '../types/list'

/** The list cell's line (nothing with fewer than two points). */
export function EpssSparkline({ points }: { points: EpssPoint[] | undefined }) {
  const series = useMemo(() => epssSeries(points), [points])
  if (series.length < 2) return null
  return <Sparkline points={series} unit="percent" ends={false} className="w-16" height={16} />
}

/** The vulnerability page's card: the chart, or why there is none. */
export function EpssTrendCard({ points }: { points: EpssPoint[] | undefined }) {
  const { t, locale } = useTranslation()
  const series = useMemo(() => epssSeries(points), [points])
  const change = epssChange(points)
  const result = useMemo<TimeSeriesResult>(
    () => ({
      shape: 'time_series',
      bucket: 'day',
      kind: 'stock',
      series: [{ key: 'epss', label: t('vulnPage.epssTrend.series', 'EPSS'), points: series }],
    }),
    [series, t]
  )
  return (
    <Card data-slot="epss-trend-card" className="min-w-0">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          {t('vulnPage.epssTrend.title', 'Exploit prediction over 30 days')}
        </CardTitle>
        {change != null && (
          <CardAction className="self-center">
            <span className="text-xs tabular-nums text-muted-foreground">
              {t('vulnPage.epssTrend.change', '{delta} in 30 days', {
                delta: formatDelta(change, 'percent', locale),
              })}
            </span>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="text-sm">
        {series.length < 2 ? (
          <p className="text-muted-foreground" data-testid="epss-trend-empty">
            {t(
              'vulnPage.epssTrend.empty',
              'No trend yet: the history fills with each daily EPSS update while you have a finding of this CVE.'
            )}
          </p>
        ) : (
          <AreaLineViz result={result} unit="percent" polarity="down_good" mode="line" />
        )}
      </CardContent>
    </Card>
  )
}
