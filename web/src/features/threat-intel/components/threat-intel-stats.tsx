'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { MetricStrip, type MetricStripItem } from '@/features/shared/components/metric-strip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import type { EPSSStats, KEVStats } from '@/lib/api/threatintel-types'

/** Value colour for a problem count: red only while it is above zero. */
const alarm = (n: number) => (n > 0 ? 'text-destructive' : undefined)

interface ThreatIntelStripProps {
  epssStats?: EPSSStats
  kevStats?: KEVStats
  isLoading?: boolean
  className?: string
}

/**
 * The exploitation headline numbers as one strip. Each tile opens the findings
 * list it filters: EPSS above 30%, EPSS above 10%, and findings on the CISA
 * KEV catalogue. Figures with no list behind them (catalogue size, rates) are
 * not tiles.
 */
export function ThreatIntelStrip({
  epssStats,
  kevStats,
  isLoading,
  className,
}: ThreatIntelStripProps) {
  const { t } = useTranslation()
  const items: MetricStripItem[] = [
    {
      key: 'epss-critical',
      label: t('threatIntel.stats.criticalRisk'),
      hint: t('threatIntel.stats.epssAbove30'),
      value: epssStats?.critical_risk_count ?? 0,
      href: '/findings?epss_score_gte=0.3',
    },
    {
      key: 'epss-high',
      label: t('threatIntel.stats.highRisk'),
      hint: t('threatIntel.stats.epssAbove10'),
      value: epssStats?.high_risk_count ?? 0,
      href: '/findings?epss_score_gte=0.1',
    },
    {
      key: 'kev',
      label: t('threatIntel.stats.kevEntries'),
      value: kevStats?.total_entries ?? 0,
      href: '/findings?is_in_kev=true',
    },
  ]
  return (
    <MetricStrip
      items={items}
      loading={Boolean(isLoading) || !epssStats || !kevStats}
      className={className}
    />
  )
}

interface ThreatIntelOverviewProps {
  epssStats: EPSSStats
  kevStats: KEVStats
  /** Kept for callers; the page header already shows sync freshness. */
  lastSyncAt?: string
  isLoading?: boolean
  className?: string
}

/**
 * The threat landscape: the strip of headline numbers, then how EPSS and CISA
 * KEV break down. Renders several blocks, so the caller's `PageStack` places them.
 */
export function ThreatIntelOverview({ epssStats, kevStats, isLoading }: ThreatIntelOverviewProps) {
  const { t } = useTranslation()
  return (
    <>
      <ThreatIntelStrip epssStats={epssStats} kevStats={kevStats} isLoading={isLoading} />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('threatIntel.overview.epssDistribution')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <EPSSRiskDistribution stats={epssStats} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('threatIntel.overview.kevStatus')}</CardTitle>
          </CardHeader>
          <CardContent>
            <KEVRemediationStatus stats={kevStats} />
          </CardContent>
        </Card>
      </div>
    </>
  )
}

function EPSSRiskDistribution({ stats }: { stats: EPSSStats }) {
  const { t } = useTranslation()
  if (!stats) {
    return (
      <div className="space-y-3">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="space-y-1">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-2 w-full" />
          </div>
        ))}
      </div>
    )
  }

  const total = stats.total_scores || 1
  const lowRisk = total - (stats.high_risk_count ?? 0)
  // Bars take the severity scale's colours, the one shared source for them.
  const distribution = [
    {
      label: t('threatIntel.distribution.critical'),
      count: stats.critical_risk_count ?? 0,
      bar: SEVERITY_DOT_COLORS.critical,
    },
    {
      label: t('threatIntel.distribution.high'),
      count: stats.high_risk_count ?? 0,
      bar: SEVERITY_DOT_COLORS.high,
    },
    {
      label: t('threatIntel.distribution.low'),
      count: Math.max(0, lowRisk),
      bar: SEVERITY_DOT_COLORS.info,
    },
  ]

  return (
    <div className="space-y-3">
      {distribution.map(({ label, count, bar }) => {
        const percentage = ((count / total) * 100).toFixed(1)
        return (
          <div key={label} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{label}</span>
              <span className="font-medium tabular-nums">
                {count.toLocaleString()} ({percentage}%)
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-muted">
              <div
                className={cn('h-full rounded-full transition-all', bar)}
                style={{ width: `${Math.min(parseFloat(percentage), 100)}%` }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

function KEVRemediationStatus({ stats }: { stats: KEVStats }) {
  const { t } = useTranslation()
  if (!stats) {
    return (
      <div className="grid grid-cols-3 divide-x">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="space-y-2 px-4 first:ps-0">
            <Skeleton className="h-3 w-16" />
            <Skeleton className="h-7 w-12" />
          </div>
        ))}
      </div>
    )
  }

  const total = stats.total_entries || 1
  const overdue = stats.past_due_count ?? 0
  const recentlyAdded = stats.recently_added_last_30_days ?? 0
  const onTrack = Math.max(0, total - overdue)

  const statuses = [
    { label: t('threatIntel.stats.pastDue'), count: overdue, tone: alarm(overdue) },
    { label: t('threatIntel.kevStatus.new30'), count: recentlyAdded, tone: undefined },
    { label: t('threatIntel.kevStatus.onTrack'), count: onTrack, tone: undefined },
  ]

  return (
    <dl className="grid grid-cols-3 divide-x">
      {statuses.map(({ label, count, tone }) => (
        <div key={label} className="px-4 first:ps-0">
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className={cn('text-2xl font-semibold tabular-nums', tone)}>
            {count.toLocaleString()}
          </dd>
        </div>
      ))}
    </dl>
  )
}
