'use client'

import Link from '@/components/link'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import type { PriorityClass } from '@/features/findings/types/finding.types'
import { formatChartDate } from '@/lib/format-chart-date'
import dynamic from 'next/dynamic'
import { PRIORITY_CHART_COLORS, PRIORITY_ORDER } from '../../lib/ctem-colors'
import {
  scoringChangeDates,
  type ExecutiveSummary,
  type RiskTrendPoint,
} from '../../hooks/use-ctem-dashboard'
import { ScoringChangeNote } from './scoring-change-note'
import { WidgetError } from '../widget-error'

// recharts loads after the card's numbers (see trend-charts.tsx).
const PriorityAreaChart = dynamic(() => import('./trend-charts').then((m) => m.PriorityAreaChart), {
  ssr: false,
  loading: () => <Skeleton className="h-full min-h-28 w-full" />,
})

interface PriorityOverTimeProps {
  /** Live open counts in the viewer's scope: the current distribution. */
  summary?: ExecutiveSummary
  summaryError?: unknown
  onRetrySummary?: () => void
  /** Stored daily snapshots (organization-wide): the history only. */
  trend?: RiskTrendPoint[]
  trendError?: unknown
  onRetryTrend?: () => void
  isLoading?: boolean
}

/**
 * The live open count of each priority class, or null when the summary did
 * not load (shown as an error, never as zeros).
 */
export function currentPriorityCounts(
  summary?: ExecutiveSummary
): Record<PriorityClass, number> | null {
  if (!summary) return null
  return {
    P0: summary.p0_open,
    P1: summary.p1_open,
    P2: summary.p2_open ?? 0,
    P3: summary.p3_open ?? 0,
  }
}

export function PriorityOverTime({
  summary,
  summaryError,
  onRetrySummary,
  trend,
  trendError,
  onRetryTrend,
  isLoading,
}: PriorityOverTimeProps) {
  const { t } = useTranslation()
  const points = trend ?? []
  const latest = points[points.length - 1]
  const current = currentPriorityCounts(summary)
  const max = current ? Math.max(1, ...PRIORITY_ORDER.map((p) => current[p])) : 1
  // The stored history is organization-wide: a viewer whose figures are
  // counted over their own scope has no trend to compare with.
  const scoped = summary?.scoped === true

  return (
    <Card className="gap-4">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <span className="text-sm font-semibold tracking-tight">
          {t('dashboardMetrics.priority.title', 'Priority classes over time')}
        </span>
        <span className="text-[11px] text-muted-foreground">
          {t('dashboardMetrics.priority.window', 'P0–P3 open · 90d')}
        </span>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col">
        {isLoading ? (
          <Skeleton className="h-28 w-full" />
        ) : scoped ? (
          <div className="flex flex-1 min-h-28 items-center justify-center text-center text-xs text-muted-foreground">
            {t('dashboardMetrics.priority.trendNotForScope', 'Trend not available for your scope')}
          </div>
        ) : trendError ? (
          <WidgetError onRetry={onRetryTrend} className="min-h-28" />
        ) : points.length > 1 ? (
          <div className="w-full flex-1 min-h-28">
            <PriorityAreaChart
              points={points}
              markers={scoringChangeDates(points, 'finding_priority')}
            />
          </div>
        ) : (
          <div className="flex flex-1 min-h-28 items-center justify-center text-xs text-muted-foreground">
            {t('dashboardMetrics.priority.noTrend', 'No trend data yet')}
          </div>
        )}
        {!isLoading && !scoped && latest && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            {t(
              'dashboardMetrics.priority.snapshotAsOf',
              'History from daily snapshots, last {date}',
              {
                date: formatChartDate(latest.date),
              }
            )}
          </p>
        )}
        {!isLoading && !scoped && <ScoringChangeNote points={points} kind="finding_priority" />}

        {/* Current distribution: live counts, each opening the list it counts. */}
        {isLoading ? (
          <div className="mt-3 flex flex-col gap-1.5">
            {PRIORITY_ORDER.map((p) => (
              <Skeleton key={p} className="h-5 w-full" />
            ))}
          </div>
        ) : !current ? (
          summaryError ? (
            <WidgetError onRetry={onRetrySummary} className="mt-3" />
          ) : null
        ) : (
          <div className="mt-3 flex flex-col gap-1.5">
            <span className="text-[11px] text-muted-foreground">
              {t('dashboardMetrics.priority.openNow', 'Open now')}
            </span>
            {PRIORITY_ORDER.map((p) => (
              <Link
                key={p}
                href={`/findings?state=open&priority_class=${p}`}
                aria-label={t('dashboardMetrics.priority.openLink', 'Open {cls} findings: {n}', {
                  cls: p,
                  n: current[p],
                })}
                className="grid grid-cols-[2rem_1fr_2rem] items-center gap-2.5 rounded hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <PriorityClassBadge priorityClass={p} showTooltip={false} />
                <div className="h-2 overflow-hidden rounded bg-muted">
                  <div
                    className="h-full rounded"
                    style={{
                      width: `${(current[p] / max) * 100}%`,
                      backgroundColor: PRIORITY_CHART_COLORS[p],
                    }}
                  />
                </div>
                <span className="text-right text-[13px] tabular-nums">{current[p]}</span>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
