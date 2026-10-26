/**
 * Program Health — CTEM-playbook OUTCOME scorecard.
 *
 * Reports the metrics the ctem.org getting-started guide tells a program to
 * lead with (did exposure go down, did the urgent things get fixed in time, is
 * the inventory owned) — deliberately separated from the activity/volume
 * numbers (total findings / scans / tickets) that measure motion, not value.
 *
 * Every metric is grounded in a real endpoint — including the confirm-or-
 * downgrade outcome (validation downgrade %), wired to validation/coverage
 * (RFC-011.2 Phase 2a). A metric only renders "Not measured" when its source
 * genuinely has no data yet, never a fabricated number.
 *
 * P0 ↔ P1 note: the guide numbers priority P1–P4; OpenCTEM numbers P0–P3. The
 * guide's most-urgent class ("P1") maps onto OpenCTEM's **P0** here.
 */

'use client'

import { useMemo, useState } from 'react'
import { Main } from '@/components/layout'
import { PageHeader, PageStack, EmptyState } from '@/features/shared'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { AreaChart, Area, ResponsiveContainer, XAxis, YAxis, Tooltip } from '@/components/charts'
import { CHART_TOOLTIP_PROPS, STATE_BADGE_SOFT, type CtemState } from '../lib/ctem-colors'
import {
  useExecutiveSummary,
  useMttrAnalytics,
  useDataQuality,
  useRiskTrend,
  useValidationCoverage,
} from '../hooks/use-ctem-dashboard'
import { WidgetError } from './widget-error'
import { PERIOD_OPTIONS, formatPct, formatTickDate, formatCount, type Period } from '../lib/format'
import { OWNER_COVERAGE_TARGET_PCT } from '../lib/data-quality'
import { ProgramMetricsSection } from './program-metrics-section'
import {
  type MetricStatus,
  remediationCompletionPct,
  remediationCompletionState,
  hoursToDays,
  remediationTimeState,
  ownerCoverageState,
  reopenRateState,
  slaComplianceState,
  exposureTrendDelta,
  exposureTrendState,
  downgradeState,
} from '../lib/program-health'
import {
  Target,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  MinusCircle,
  Lock,
  type LucideIcon,
} from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'

// ============================================
// TYPES / CONSTANTS
// ============================================

interface OutcomeMetric {
  id: string
  label: string
  /** What the metric actually measures (one line). */
  measures: string
  /** Formatted current value, or null for "not yet measured". */
  display: string | null
  /** The guide's target. */
  target: string
  status: MetricStatus
  /** Optional extra context (e.g. the P0↔P1 mapping). */
  hint?: string
}

const STATUS_META: Record<MetricStatus, { labelKey: string; fallback: string; icon: LucideIcon }> =
  {
    good: { labelKey: 'insights.status.good', fallback: 'On track', icon: CheckCircle2 },
    warn: { labelKey: 'insights.status.warn', fallback: 'Watch', icon: AlertTriangle },
    crit: { labelKey: 'insights.status.crit', fallback: 'Off track', icon: XCircle },
    pending: { labelKey: 'insights.status.pending', fallback: 'Not measured', icon: MinusCircle },
  }

// ============================================
// HELPERS
// ============================================

function fmtPct(v: number | null | undefined, locale: string, n?: number): string | null {
  if (v === null || v === undefined || Number.isNaN(v)) return null
  return formatPct(v, { locale, n })
}

// A value is coloured only when it is a problem; the status pill carries the
// rest of the state (on track / watch / not measured).
function stateTextClass(status: MetricStatus): string {
  if (status === 'pending') return 'text-muted-foreground'
  return status === 'crit' ? 'text-destructive' : ''
}

function statusBadgeClass(status: MetricStatus): string {
  return status === 'pending'
    ? 'bg-muted text-muted-foreground border-border'
    : STATE_BADGE_SOFT[status as CtemState]
}

// ============================================
// SUB-COMPONENTS
// ============================================

function StatusPill({ status }: { status: MetricStatus }) {
  const { t } = useTranslation()
  const meta = STATUS_META[status]
  const Icon = meta.icon
  return (
    <Badge
      variant="outline"
      className={cn('shrink-0 gap-1 whitespace-nowrap', statusBadgeClass(status))}
    >
      <Icon className="h-3 w-3" />
      {t(meta.labelKey, meta.fallback)}
    </Badge>
  )
}

function MetricCard({ metric }: { metric: OutcomeMetric }) {
  const { t } = useTranslation()
  return (
    <Card className="flex flex-col">
      <CardHeader className="space-y-1 pb-2">
        <CardTitle className="text-sm font-medium">{metric.label}</CardTitle>
        <CardDescription className="text-xs">{metric.measures}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-end">
        {/* Value and status share a row that wraps, so the pill never squeezes
            (or clips, e.g. "Not measured") the title at narrow widths. */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className={cn('text-2xl font-bold tabular-nums', stateTextClass(metric.status))}>
            {metric.display ?? '—'}
          </span>
          <StatusPill status={metric.status} />
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {t('insights.target', 'Target:')}{' '}
          <span className="font-medium text-foreground">{metric.target}</span>
        </p>
        {/* Where each figure comes from: program-health lib and the API handlers
            (executive-summary, mttr-analytics, data-quality, risk-trend,
            validation/coverage); it is not shown to users. */}
        {metric.hint && <p className="mt-2 text-xs text-muted-foreground">{metric.hint}</p>}
      </CardContent>
    </Card>
  )
}

function ScorecardSkeleton() {
  return (
    <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: 8 }).map((_, i) => (
        <Card key={i}>
          <CardHeader className="pb-2">
            <Skeleton className="h-4 w-28" />
            <Skeleton className="mt-2 h-3 w-40" />
          </CardHeader>
          <CardContent>
            <Skeleton className="mb-2 h-8 w-20" />
            <Skeleton className="h-3 w-24" />
          </CardContent>
        </Card>
      ))}
    </section>
  )
}

// ============================================
// PAGE
// ============================================

export function ProgramHealthView() {
  const { t, locale } = useTranslation()
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const [period, setPeriod] = useState<Period>('90')

  const tenantId = currentTenant?.id ?? null
  const canRead = can(Permission.DashboardRead)

  const {
    data: summary,
    isLoading: summaryLoading,
    error: summaryError,
    mutate: retrySummary,
  } = useExecutiveSummary(tenantId, Number(period))
  const {
    data: mttr,
    isLoading: mttrLoading,
    error: mttrError,
    mutate: retryMttr,
  } = useMttrAnalytics(tenantId)
  const {
    data: quality,
    isLoading: qualityLoading,
    error: qualityError,
    mutate: retryQuality,
  } = useDataQuality(tenantId)
  const { data: riskTrend, isLoading: trendLoading } = useRiskTrend(tenantId, Number(period))
  const {
    data: validation,
    isLoading: validationLoading,
    error: validationError,
    mutate: retryValidation,
  } = useValidationCoverage(tenantId)

  const loading = summaryLoading || mttrLoading || qualityLoading || validationLoading

  // The stored history, ending at today's live open count (the same figure
  // as the rest of the page), so the trend never ends on yesterday's snapshot.
  // The chart plots this same series, so its last point is the "+N open" figure.
  const openPoints = useMemo(() => {
    const points = (riskTrend ?? []).map((p) => ({ date: p.date, open: p.findings_open }))
    if (!summary || summary.scoped) return summary?.scoped ? [] : points
    return points.length > 0
      ? [...points.slice(0, -1), { ...points[points.length - 1], open: summary.findings_total }]
      : points
  }, [riskTrend, summary])
  const openSeries = useMemo(() => openPoints.map((p) => p.open), [openPoints])
  const trendDelta = exposureTrendDelta(openSeries)

  const metrics = useMemo<OutcomeMetric[]>(() => {
    // 1. P0 fixed in the period, of P0 open + fixed.
    const completion = summary
      ? remediationCompletionPct(summary.p0_open, summary.p0_resolved_period)
      : null
    // 2. Mean time from discovery to fix for P0 (the API has no P0 median).
    const p0Days = mttr ? hoursToDays(mttr.by_priority_class?.P0) : null
    // 4/5. Regression (re-open / rediscovery).
    const reopenPct = summary?.regression_rate_pct
    const rediscovered = summary?.regression_count
    // 8. Confirm-or-downgrade outcome. `dgValidated` is the denominator
    // (distinct findings with validation evidence): undefined = API predates the
    // metric, so "not measured"; 0 = wired but empty until validations run, so
    // "0% (no validations yet)", never "not measured".
    const dgValidated = validation?.downgrade_validated
    const dgDowngraded = validation?.downgraded
    const dgPct = validation?.downgrade_pct
    const dgDisplay =
      dgValidated === undefined
        ? null
        : dgValidated <= 0
          ? t('insights.programHealth.downgradeNone', '0% (no validations yet)')
          : fmtPct(dgPct, locale)
    const dgHint =
      dgValidated && dgValidated > 0
        ? t(
            dgValidated === 1
              ? 'insights.programHealth.downgradeHint.one'
              : 'insights.programHealth.downgradeHint.other',
            undefined,
            { downgraded: dgDowngraded ?? 0, count: dgValidated }
          )
        : undefined
    const windowLabel = t(`insights.period.window.d${period}`, `${period} days`)

    return [
      {
        id: 'remediation-completion',
        label: t('dashboardMetrics.program.p0Fixed', 'P0 fixed in period'),
        measures: t(
          'dashboardMetrics.program.p0FixedMeasures',
          'P0 findings fixed in the period ÷ (P0 open + P0 fixed)'
        ),
        display: fmtPct(completion, locale),
        target: '> 90%',
        status: remediationCompletionState(completion),
      },
      {
        id: 'remediation-time',
        label: t('dashboardMetrics.program.p0MeanTime', 'Mean time to fix · P0'),
        measures: t(
          'dashboardMetrics.program.p0MeanTimeMeasures',
          'Mean time from discovery to fix for P0 findings fixed in the last 90 days'
        ),
        display:
          p0Days === null
            ? null
            : t('insights.programHealth.days', '{value}d', { value: p0Days.toFixed(1) }),
        target: t('insights.programHealth.targetDays', '< {value} days', { value: 14 }),
        status: remediationTimeState(p0Days),
      },
      {
        id: 'owner-coverage',
        label: t('insights.ownerCoverage.label', 'Asset owner coverage'),
        measures: t(
          'insights.ownerCoverage.measures',
          'Assets in inventory with an assigned owner'
        ),
        display: fmtPct(quality?.asset_ownership_pct, locale),
        target: t('insights.ownerCoverage.target', '≥ {pct}%', { pct: OWNER_COVERAGE_TARGET_PCT }),
        status: ownerCoverageState(quality?.asset_ownership_pct),
      },
      {
        id: 'reopen-rate',
        label: t('insights.programHealth.reopen', 'Remediation re-open rate'),
        measures: t(
          'insights.programHealth.reopenMeasures',
          'Resolved findings that regressed or reopened'
        ),
        display: fmtPct(reopenPct, locale),
        target: '< 20%',
        status: reopenRateState(reopenPct),
      },
      {
        id: 'rediscovered',
        label: t('dashboardMetrics.program.rediscovered', 'Findings back after a fix'),
        measures: t(
          'dashboardMetrics.program.rediscoveredMeasures',
          'Findings that came back after being fixed, in the period'
        ),
        display: rediscovered === undefined ? null : formatCount(rediscovered, locale),
        target: '→ 0',
        status:
          rediscovered === undefined
            ? 'pending'
            : rediscovered >= 4
              ? 'crit'
              : rediscovered >= 1
                ? 'warn'
                : 'good',
      },
      {
        id: 'sla-compliance',
        label: t('dashboardMetrics.executive.sla'),
        measures: t(
          'dashboardMetrics.program.slaMeasures',
          'Open findings with an SLA that are not past it'
        ),
        display: fmtPct(summary?.sla_compliance_pct, locale, summary?.findings_total),
        target: '≥ 90%',
        status: slaComplianceState(summary?.sla_compliance_pct),
      },
      {
        id: 'exposure-trend',
        label: t('dashboardMetrics.program.exposureTrend', 'Open findings trend'),
        measures: t(
          'dashboardMetrics.program.exposureTrendMeasures',
          'Open findings now vs {window} ago, which should fall after ramp-up',
          { window: windowLabel }
        ),
        display:
          trendDelta === null
            ? null
            : t('insights.programHealth.openDelta', '{delta} open', {
                delta: `${trendDelta > 0 ? '+' : ''}${formatCount(trendDelta, locale)}`,
              }),
        target: t('insights.programHealth.trendingDown', 'Trending down'),
        status: exposureTrendState(trendDelta),
      },
      {
        id: 'validation-downgrade',
        label: t('insights.programHealth.downgrade', 'Validation downgrade %'),
        measures: t(
          'insights.programHealth.downgradeMeasures',
          'Findings de-prioritised after validation proved them non-exploitable'
        ),
        display: dgDisplay,
        target: '25–40%',
        status: downgradeState(dgPct, dgValidated),
        hint: dgHint,
      },
    ]
  }, [summary, mttr, quality, period, trendDelta, validation, t, locale])

  if (!canRead) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={t('insights.programHealth.title', 'Program health')} />
          <EmptyState
            icon={Lock}
            title={t(
              'insights.programHealth.noAccessTitle',
              'You don’t have access to program metrics.'
            )}
            description={t(
              'insights.programHealth.noAccessDescription',
              'Dashboard read permission is required to view program health.'
            )}
          />
        </PageStack>
      </Main>
    )
  }

  const hasAnyData = !!summary || !!mttr || !!quality
  // Every source failed: say so, rather than "no data yet".
  const allFailed = !hasAnyData && !!(summaryError || mttrError || qualityError || validationError)
  const retryAll = () => {
    void retrySummary()
    void retryMttr()
    void retryQuality()
    void retryValidation()
  }

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('insights.programHealth.title', 'Program health')}
          description={t(
            'insights.programHealth.description',
            'Whether risk is being retired: urgent fixes on time, inventory owned, exposure falling.'
          )}
        >
          <Select value={period} onValueChange={(v) => setPeriod(v as Period)}>
            <SelectTrigger
              className="h-9 w-[150px]"
              aria-label={t('insights.period.label', 'Period')}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PERIOD_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {t(opt.labelKey, opt.fallback)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </PageHeader>

        {loading ? (
          <ScorecardSkeleton />
        ) : allFailed ? (
          <WidgetError onRetry={retryAll} className="rounded-lg border py-8" />
        ) : !hasAnyData ? (
          <EmptyState
            icon={ShieldCheck}
            title={t('insights.programHealth.emptyTitle', 'No program data yet')}
            description={t(
              'insights.programHealth.emptyDescription',
              'Once findings are ingested and remediation begins, outcome metrics populate here.'
            )}
          />
        ) : (
          <>
            <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {metrics.map((m) => (
                <MetricCard key={m.id} metric={m} />
              ))}
            </section>

            <ProgramMetricsSection tenantId={tenantId} days={Number(period)} />

            {/* Exposure-count trend chart (the guide's day-60 down-slope). */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">
                  {t('insights.programHealth.chartTitle', 'Exposure over time')}
                </CardTitle>
                <CardDescription className="text-xs">
                  {t(
                    'insights.programHealth.chartDescription',
                    'Open findings across the selected window. A healthy program bends this down.'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {trendLoading ? (
                  <Skeleton className="h-48 w-full" />
                ) : openPoints.length > 1 ? (
                  <>
                    <div className="h-48 w-full" aria-hidden>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart
                          data={openPoints}
                          margin={{ top: 4, right: 8, bottom: 0, left: 0 }}
                        >
                          <XAxis
                            dataKey="date"
                            tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }}
                            tickLine={false}
                            axisLine={false}
                            minTickGap={24}
                            tickFormatter={(d: string) => formatTickDate(d, locale)}
                          />
                          <YAxis
                            tick={{ fontSize: 11, fill: 'var(--muted-foreground)' }}
                            tickLine={false}
                            axisLine={false}
                            width={36}
                            allowDecimals={false}
                          />
                          <Tooltip
                            {...CHART_TOOLTIP_PROPS}
                            labelFormatter={(d) => formatTickDate(String(d), locale)}
                          />
                          <Area
                            type="monotone"
                            dataKey="open"
                            name={t('insights.programHealth.chartSeries', 'Open findings')}
                            stroke="var(--viz-cat-1)"
                            strokeWidth={2}
                            fill="var(--viz-cat-1)"
                            fillOpacity={0.15}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                    <table className="sr-only">
                      <caption>
                        {t('insights.programHealth.chartTitle', 'Exposure over time')}
                      </caption>
                      <thead>
                        <tr>
                          <th scope="col">{t('insights.programHealth.colDate', 'Date')}</th>
                          <th scope="col">
                            {t('insights.programHealth.chartSeries', 'Open findings')}
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {openPoints.map((p) => (
                          <tr key={p.date}>
                            <td>{formatTickDate(p.date, locale)}</td>
                            <td>{formatCount(p.open, locale)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                ) : (
                  <EmptyState
                    card={false}
                    className="py-10"
                    icon={Target}
                    title={t(
                      'insights.programHealth.chartEmptyTitle',
                      'Not enough trend history yet'
                    )}
                    description={t(
                      'insights.programHealth.chartEmptyDescription',
                      'The chart needs at least two risk snapshots.'
                    )}
                  />
                )}
              </CardContent>
            </Card>
          </>
        )}
      </PageStack>
    </Main>
  )
}
