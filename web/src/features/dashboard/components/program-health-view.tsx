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
import {
  PageHeader,
  PageStack,
  EmptyState,
  MetricStrip,
  OverviewAnswer,
  OverviewActList,
  type MetricStripItem,
  type OverviewActItem,
} from '@/features/shared'
import { useTenant } from '@/context/tenant-provider'
import { usePermissions, Permission } from '@/lib/permissions'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { AreaChart, Area, ResponsiveContainer, XAxis, YAxis, Tooltip } from '@/components/charts'
import { CHART_TOOLTIP_PROPS } from '../lib/ctem-colors'
import {
  useExecutiveSummary,
  useMttrAnalytics,
  useDataQuality,
  useRiskTrend,
  useValidationCoverage,
} from '../hooks/use-ctem-dashboard'
import { WidgetError } from './widget-error'
import { MetricRowList, type MetricRow } from './metric-row-list'
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
  slaComplianceState,
  exposureTrendDelta,
  exposureTrendState,
  downgradeState,
} from '../lib/program-health'
import { ShieldCheck, Lock } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'

// ============================================
// LINKS
// ============================================

// The lists behind each figure. Every one is an existing filter of the findings
// list (state lens, priority_class, sla_status) or the asset attention queue;
// the list applies the viewer's data scope, like the counts above it.
export const PROGRAM_HEALTH_LINKS = {
  p0Open: '/findings?state=open&priority_class=P0',
  p0Fixed: '/findings?state=fixed&priority_class=P0',
  pastSla: '/findings?state=open&sla_status=overdue,exceeded',
  open: '/findings?state=open',
  noOwner: '/assets/attention/no-owner',
  validation: '/validation',
} as const

/** Problem rows first (off track before watch); a good or unmeasured figure is not listed. */
const ACT_ORDER: Record<MetricStatus, number> = { crit: 0, warn: 1, good: 2, pending: 3 }

// ============================================
// HELPERS
// ============================================

function fmtPct(v: number | null | undefined, locale: string, n?: number): string | null {
  if (v === null || v === undefined || Number.isNaN(v)) return null
  return formatPct(v, { locale, n })
}

// ============================================
// SUB-COMPONENTS
// ============================================

function OverviewSkeleton() {
  return (
    <div className="flex flex-col gap-page" aria-hidden>
      <div className="grid gap-page lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="rounded-lg border bg-card p-4 sm:p-5">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="mt-3 h-11 w-28" />
          <Skeleton className="mt-3 h-4 w-72 max-w-full" />
        </div>
        <div className="rounded-lg border bg-card p-4 sm:p-5">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="mt-3 h-4 w-full" />
          <Skeleton className="mt-3 h-4 w-full" />
        </div>
      </div>
      <MetricStrip
        loading
        items={Array.from({ length: 5 }, (_, i) => ({ key: String(i), label: '', value: 0 }))}
      />
    </div>
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
  const openPoints = useMemo(() => {
    const points = (riskTrend ?? []).map((p) => ({ date: p.date, open: p.findings_open }))
    if (!summary || summary.scoped) return summary?.scoped ? [] : points
    return points.length > 0
      ? [...points.slice(0, -1), { ...points[points.length - 1], open: summary.findings_total }]
      : points
  }, [riskTrend, summary])
  const openSeries = useMemo(() => openPoints.map((p) => p.open), [openPoints])
  const trendDelta = exposureTrendDelta(openSeries)

  const windowLabel = t(`insights.period.window.d${period}`, `${period} days`)

  const view = useMemo(() => {
    const p0Open = summary?.p0_open ?? 0
    const p0Fixed = summary?.p0_resolved_period ?? 0
    const completion = summary ? remediationCompletionPct(p0Open, p0Fixed) : null
    const completionStatus = remediationCompletionState(completion)

    const p0Days = mttr ? hoursToDays(mttr.by_priority_class?.P0) : null
    const p0TimeStatus = remediationTimeState(p0Days)

    const ownerPct = quality?.asset_ownership_pct
    const ownerStatus = ownerCoverageState(ownerPct)

    const slaPct = summary?.sla_compliance_pct
    const slaStatus = slaComplianceState(slaPct)
    const pastSla = summary?.sla_breached ?? 0

    const trendStatus = exposureTrendState(trendDelta)
    const trendDisplay =
      trendDelta === null
        ? null
        : t('insights.programHealth.openDelta', '{delta} open', {
            delta: `${trendDelta > 0 ? '+' : ''}${formatCount(trendDelta, locale)}`,
          })

    const dgValidated = validation?.downgrade_validated
    const dgPct = validation?.downgrade_pct
    const dgStatus = downgradeState(dgPct, dgValidated)
    const dgDisplay =
      dgValidated === undefined
        ? null
        : dgValidated <= 0
          ? t('insights.programHealth.downgradeNone', '0% (no validations yet)')
          : fmtPct(dgPct, locale)

    const reopenPct = summary?.regression_rate_pct
    const rediscovered = summary?.regression_count

    const statusWord = (s: MetricStatus) =>
      s === 'crit' ? t('insights.status.crit', 'Off track') : t('insights.status.warn', 'Watch')

    // Where to act: only figures that are off track or on watch AND open a
    // list that already exists.
    const candidates: (OverviewActItem & { status: 'crit' | 'warn'; rank: MetricStatus })[] = []
    const addAct = (
      status: MetricStatus,
      key: string,
      label: string,
      detail: string | undefined,
      href: string
    ) => {
      if (status !== 'crit' && status !== 'warn') return
      candidates.push({
        key,
        label,
        detail,
        href,
        status,
        statusLabel: statusWord(status),
        rank: status,
      })
    }
    addAct(
      completionStatus,
      'p0-open',
      t('insights.programHealth.act.p0Open', 'P0 findings still open'),
      t('insights.programHealth.act.p0OpenDetail', '{count} open, {fixed} fixed in the period', {
        count: formatCount(p0Open, locale),
        fixed: formatCount(p0Fixed, locale),
      }),
      PROGRAM_HEALTH_LINKS.p0Open
    )
    addAct(
      pastSla > 0 && slaStatus === 'good' ? 'warn' : slaStatus,
      'past-sla',
      t('insights.programHealth.act.pastSla', 'Findings past their SLA'),
      t('insights.programHealth.act.pastSlaDetail', '{count} open and past the deadline', {
        count: formatCount(pastSla, locale),
      }),
      PROGRAM_HEALTH_LINKS.pastSla
    )
    addAct(
      ownerStatus,
      'no-owner',
      t('insights.programHealth.act.noOwner', 'Assets without an owner'),
      ownerPct === undefined || ownerPct === null
        ? undefined
        : t('insights.programHealth.act.noOwnerDetail', '{pct} of assets have an owner', {
            pct: fmtPct(ownerPct, locale) ?? '',
          }),
      PROGRAM_HEALTH_LINKS.noOwner
    )
    addAct(
      p0TimeStatus,
      'p0-time',
      t('insights.programHealth.act.p0Time', 'P0 fixes take too long'),
      p0Days === null
        ? undefined
        : t('insights.programHealth.act.p0TimeDetail', 'Mean {value} days to fix', {
            value: p0Days.toFixed(1),
          }),
      PROGRAM_HEALTH_LINKS.p0Fixed
    )
    addAct(
      trendStatus,
      'open-trend',
      t('insights.programHealth.act.openTrend', 'Open findings are not falling'),
      trendDisplay ?? undefined,
      PROGRAM_HEALTH_LINKS.open
    )
    addAct(
      dgStatus,
      'downgrade',
      t('insights.programHealth.act.downgrade', 'Validation downgrades are out of range'),
      dgDisplay ?? undefined,
      PROGRAM_HEALTH_LINKS.validation
    )
    const actItems: OverviewActItem[] = candidates
      .sort((a, b) => ACT_ORDER[a.rank] - ACT_ORDER[b.rank])
      .map(({ rank: _rank, ...item }) => item)
      .slice(0, 5)

    // One strip, at most five tiles; a tile opens its list. A figure with no
    // measurement says so and opens nothing.
    const notMeasuredNode = (
      <span className="text-sm font-normal text-muted-foreground">
        {t('insights.status.pending', 'Not measured')}
      </span>
    )
    const strip: MetricStripItem[] = []
    const target = (text: string) => `${t('insights.target', 'Target:')} ${text}`
    strip.push(
      p0Days === null
        ? {
            key: 'p0-time',
            label: t('dashboardMetrics.program.p0MeanTime', 'Mean time to fix, P0'),
            value: notMeasuredNode,
            notMeasured: true,
          }
        : {
            key: 'p0-time',
            label: t('dashboardMetrics.program.p0MeanTime', 'Mean time to fix, P0'),
            value: t('insights.programHealth.days', '{value}d', { value: p0Days.toFixed(1) }),
            hint: target(t('insights.programHealth.targetDays', '< {value} days', { value: 14 })),
            description: t(
              'dashboardMetrics.program.p0MeanTimeMeasures',
              'Mean time from discovery to fix for P0 findings fixed in the last 90 days'
            ),
            href: PROGRAM_HEALTH_LINKS.p0Fixed,
          }
    )
    const slaDisplay = fmtPct(slaPct, locale, summary?.findings_total)
    strip.push(
      slaDisplay === null
        ? {
            key: 'sla',
            label: t('dashboardMetrics.executive.sla', 'SLA compliance'),
            value: notMeasuredNode,
            notMeasured: true,
          }
        : {
            key: 'sla',
            label: t('dashboardMetrics.executive.sla', 'SLA compliance'),
            value: slaDisplay,
            hint: target('≥ 90%'),
            description: t(
              'dashboardMetrics.program.slaMeasures',
              'Open findings with an SLA that are not past it'
            ),
            href: PROGRAM_HEALTH_LINKS.pastSla,
          }
    )
    const ownerDisplay = fmtPct(ownerPct, locale)
    strip.push(
      ownerDisplay === null
        ? {
            key: 'owner',
            label: t('insights.ownerCoverage.label', 'Asset owner coverage'),
            value: notMeasuredNode,
            notMeasured: true,
          }
        : {
            key: 'owner',
            label: t('insights.ownerCoverage.label', 'Asset owner coverage'),
            value: ownerDisplay,
            hint: target(
              t('insights.ownerCoverage.target', '≥ {pct}%', { pct: OWNER_COVERAGE_TARGET_PCT })
            ),
            description: t(
              'insights.ownerCoverage.measures',
              'Assets in inventory with an assigned owner'
            ),
            href: PROGRAM_HEALTH_LINKS.noOwner,
          }
    )
    strip.push(
      trendDisplay === null
        ? {
            key: 'trend',
            label: t('dashboardMetrics.program.exposureTrend', 'Open findings trend'),
            value: notMeasuredNode,
            notMeasured: true,
          }
        : {
            key: 'trend',
            label: t('dashboardMetrics.program.exposureTrend', 'Open findings trend'),
            value: trendDisplay,
            hint: target(t('insights.programHealth.trendingDown', 'Trending down')),
            description: t(
              'dashboardMetrics.program.exposureTrendMeasures',
              'Open findings now vs {window} ago, which should fall after ramp-up',
              { window: windowLabel }
            ),
            href: PROGRAM_HEALTH_LINKS.open,
          }
    )
    strip.push(
      dgDisplay === null
        ? {
            key: 'downgrade',
            label: t('insights.programHealth.downgrade', 'Validation downgrade %'),
            value: notMeasuredNode,
            notMeasured: true,
          }
        : {
            key: 'downgrade',
            label: t('insights.programHealth.downgrade', 'Validation downgrade %'),
            value: dgDisplay,
            hint: target('25–40%'),
            description: t(
              'insights.programHealth.downgradeMeasures',
              'Findings de-prioritised after validation proved them non-exploitable'
            ),
            href: PROGRAM_HEALTH_LINKS.validation,
          }
    )

    // Figures that open no list: how well fixes hold.
    const notMeasuredLabel = t('insights.status.pending', 'Not measured')
    const fixRows: MetricRow[] = [
      {
        key: 'reopen',
        label: t('insights.programHealth.reopen', 'Remediation re-open rate'),
        value: fmtPct(reopenPct, locale),
        notMeasuredLabel,
        caption: t(
          'insights.programHealth.reopenCaption',
          'Resolved findings that regressed or reopened. Target: under 20%.'
        ),
      },
      {
        key: 'rediscovered',
        label: t('dashboardMetrics.program.rediscovered', 'Findings back after a fix'),
        value: rediscovered === undefined ? null : formatCount(rediscovered, locale),
        notMeasuredLabel,
        caption: t(
          'dashboardMetrics.program.rediscoveredMeasures',
          'Findings that came back after being fixed, in the period'
        ),
      },
    ]

    return {
      completion,
      completionStatus,
      p0Open,
      p0Fixed,
      actItems,
      strip,
      fixRows,
    }
  }, [summary, mttr, quality, trendDelta, validation, t, locale, windowLabel])

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

  const answerTone =
    view.completionStatus === 'crit'
      ? 'danger'
      : view.completionStatus === 'warn'
        ? 'warning'
        : 'default'

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
          <OverviewSkeleton />
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
            <div className="grid gap-page lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
              {view.completion === null ? (
                <OverviewAnswer
                  question={t('insights.programHealth.answer.question', 'P0 fixed within target')}
                  notMeasured={{
                    label: t('insights.status.pending', 'Not measured'),
                    reason: t(
                      'insights.programHealth.answer.reason',
                      'No P0 findings were open or fixed in the last {window}, so there is nothing to divide.',
                      { window: windowLabel }
                    ),
                  }}
                >
                  <ExposureTrend
                    points={openPoints}
                    loading={trendLoading}
                    locale={locale}
                    t={t}
                    windowLabel={windowLabel}
                  />
                </OverviewAnswer>
              ) : (
                <OverviewAnswer
                  question={t('insights.programHealth.answer.question', 'P0 fixed within target')}
                  value={fmtPct(view.completion, locale) ?? ''}
                  tone={answerTone}
                  sentence={t(
                    'insights.programHealth.answer.sentence',
                    '{fixed} of {total} P0 findings were fixed in the last {window}. The target is more than 90%.',
                    {
                      fixed: formatCount(view.p0Fixed, locale),
                      total: formatCount(view.p0Open + view.p0Fixed, locale),
                      window: windowLabel,
                    }
                  )}
                >
                  <ExposureTrend
                    points={openPoints}
                    loading={trendLoading}
                    locale={locale}
                    t={t}
                    windowLabel={windowLabel}
                  />
                </OverviewAnswer>
              )}
              <OverviewActList
                title={t('insights.programHealth.act.title', 'Where to act')}
                items={view.actItems}
                empty={t(
                  'insights.programHealth.act.empty',
                  'Nothing is off track in this period.'
                )}
              />
            </div>

            <MetricStrip items={view.strip} />

            <section className="space-y-3">
              <h2 className="text-base font-semibold">
                {t('insights.programHealth.fixQuality', 'How well fixes hold')}
              </h2>
              <MetricRowList rows={view.fixRows} />
            </section>

            <ProgramMetricsSection tenantId={tenantId} days={Number(period)} />
          </>
        )}
      </PageStack>
    </Main>
  )
}

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * Open findings over the selected window, inside the answer panel. It is the
 * stored risk-trend series the page already reads; with fewer than two points
 * there is nothing to draw, so the block is left out.
 */
function ExposureTrend({
  points,
  loading,
  locale,
  t,
  windowLabel,
}: {
  points: { date: string; open: number }[]
  loading: boolean
  locale: string
  t: Translate
  windowLabel: string
}) {
  if (loading) return <Skeleton className="mt-2 h-32 w-full" />
  if (points.length < 2) return null
  const title = t('insights.programHealth.chartTitle', 'Exposure over time')
  return (
    <div className="mt-2 min-w-0">
      <p className="text-sm text-muted-foreground">
        {t('insights.programHealth.trendCaption', 'Open findings over the last {window}', {
          window: windowLabel,
        })}
      </p>
      <div className="mt-1 h-32 w-full" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <XAxis
              dataKey="date"
              tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }}
              tickLine={false}
              axisLine={false}
              minTickGap={24}
              tickFormatter={(d: string) => formatTickDate(d, locale)}
            />
            <YAxis
              tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }}
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
        <caption>{title}</caption>
        <thead>
          <tr>
            <th scope="col">{t('insights.programHealth.colDate', 'Date')}</th>
            <th scope="col">{t('insights.programHealth.chartSeries', 'Open findings')}</th>
          </tr>
        </thead>
        <tbody>
          {points.map((p) => (
            <tr key={p.date}>
              <td>{formatTickDate(p.date, locale)}</td>
              <td>{formatCount(p.open, locale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
