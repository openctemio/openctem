'use client'

import { KevBadge } from '@/components/ui/kev-badge'
import { formatEpssScore } from '@/lib/epss'
import { useMemo, useState } from 'react'
import Link from '@/components/link'
import { DRILL } from '@/features/dashboard/lib/drill'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  MetricStrip,
  PageStack,
  EmptyState,
  DataTable,
  SeverityBadge,
  formatRiskScore,
} from '@/features/shared'
import { PriorityClassBadge } from '@/features/findings/components/priority-class-badge'
import type { PriorityClass } from '@/features/findings/types/finding.types'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
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
import type { Severity } from '@/features/shared/types'
import { ShieldCheck, Timer, Users } from 'lucide-react'
import { compareSeverity } from '@/lib/severity'
import { WidgetError } from '@/features/dashboard/components/widget-error'
import {
  MTTR_WINDOW_DAYS,
  useExecutiveSummary,
  useMttrAnalytics,
  useProcessMetrics,
  type ExecTopRisk,
} from '@/features/dashboard/hooks/use-ctem-dashboard'
import { formatHours } from '@/features/dashboard/lib/format-hours'
import {
  PERIOD_OPTIONS,
  formatPct,
  formatCount,
  type Period,
} from '@/features/dashboard/lib/format'

type TopRiskRow = ExecTopRisk & { rowId: string }

const PRIORITY_CLASSES = ['P0', 'P1', 'P2', 'P3']

function PriorityChip({ value }: { value: string }) {
  const pc = value.toUpperCase()
  if (!PRIORITY_CLASSES.includes(pc)) return <Badge variant="outline">{value}</Badge>
  return <PriorityClassBadge priorityClass={pc as PriorityClass} />
}

function StripSkeleton() {
  return <Skeleton className="h-20 w-full rounded-lg" />
}

function useTopRiskColumns(): ColumnDef<TopRiskRow>[] {
  const { t } = useTranslation()
  return useMemo(
    () => [
      {
        accessorKey: 'title',
        enableSorting: false,
        header: t('insights.executive.colTitle', 'Title'),
        // A top risk opens its finding.
        cell: ({ row }) =>
          row.original.finding_id ? (
            <Link
              href={`/findings/${encodeURIComponent(row.original.finding_id)}`}
              className="block max-w-md truncate text-sm font-medium hover:underline focus-visible:underline"
            >
              {row.original.title}
            </Link>
          ) : (
            <span className="block max-w-md truncate text-sm font-medium">
              {row.original.title}
            </span>
          ),
      },
      {
        accessorKey: 'severity',
        enableSorting: false,
        header: t('insights.executive.colSeverity', 'Severity'),
        cell: ({ row }) => (
          <SeverityBadge severity={row.original.severity.toLowerCase() as Severity} />
        ),
      },
      {
        accessorKey: 'priority_class',
        enableSorting: false,
        header: t('insights.executive.colPriority', 'Priority'),
        cell: ({ row }) => <PriorityChip value={row.original.priority_class} />,
      },
      {
        accessorKey: 'asset_name',
        enableSorting: false,
        header: t('insights.executive.colAsset', 'Asset'),
        cell: ({ row }) => (
          <span className="block max-w-xs truncate text-sm text-muted-foreground">
            {row.original.asset_name}
          </span>
        ),
      },
      {
        accessorKey: 'epss_score',
        enableSorting: false,
        header: t('insights.executive.colEpss', 'EPSS'),
        cell: ({ row }) => (
          <span className="text-sm tabular-nums">
            {formatEpssScore(row.original.epss_score, 2, t('insights.executive.na', 'N/A'))}
          </span>
        ),
      },
      {
        accessorKey: 'is_in_kev',
        enableSorting: false,
        header: t('insights.executive.colKev', 'KEV'),
        cell: ({ row }) =>
          row.original.is_in_kev ? (
            <KevBadge />
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
    ],
    [t]
  )
}

export default function ExecutiveSummaryPage() {
  const { t, locale } = useTranslation()
  const { currentTenant } = useTenant()
  const [period, setPeriod] = useState<Period>('30')
  const tenantId = currentTenant?.id ?? null
  const columns = useTopRiskColumns()

  // The period reaches the summary. Time to fix and process health are measured
  // over a fixed 90 days (a stable trend) and say so in their headers.
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
    data: processMetrics,
    isLoading: processLoading,
    error: processError,
    mutate: retryProcess,
  } = useProcessMetrics(tenantId)

  const topRisks = useMemo<TopRiskRow[]>(
    () =>
      (summary?.top_risks ?? []).map((r, i) => ({
        ...r,
        // The same CVE on several assets shares a title: key by the finding.
        rowId: r.finding_id ?? `${r.title}-${r.asset_name}-${i}`,
      })),
    [summary]
  )

  const window90 = t('insights.executive.last90', 'Last {days} days', { days: MTTR_WINDOW_DAYS })
  const riskChange = summary?.risk_score_change ?? 0
  const headline = summary
    ? [
        {
          key: 'risk',
          label: t('insights.executive.risk', 'Risk score'),
          value: formatRiskScore(summary.risk_score_current),
          hint:
            riskChange !== 0
              ? t('insights.executive.vsPrevious', '{change} vs previous period', {
                  change: `${riskChange > 0 ? '+' : ''}${riskChange.toFixed(1)}`,
                })
              : undefined,
          href: DRILL.open,
        },
        {
          key: 'sla',
          label: t('dashboardMetrics.executive.sla'),
          value: formatPct(summary.sla_compliance_pct, { n: summary.findings_total, locale }),
          hint: t('insights.executive.breached', '{count} breached', {
            count: formatCount(summary.sla_breached, locale),
          }),
          href: DRILL.slaBreached,
        },
        {
          key: 'p0',
          label: t('insights.executive.p0', 'P0 open'),
          value: summary.p0_open,
          tone: 'danger' as const,
          hint: t('insights.executive.resolvedThisPeriod', '{count} resolved this period', {
            count: formatCount(summary.p0_resolved_period, locale),
          }),
          href: DRILL.p0Open,
        },
        {
          key: 'p1',
          label: t('insights.executive.p1', 'P1 open'),
          value: summary.p1_open,
          hint: t('insights.executive.resolvedThisPeriod', '{count} resolved this period', {
            count: formatCount(summary.p1_resolved_period ?? 0, locale),
          }),
          href: DRILL.p1Open,
        },
        {
          key: 'crown',
          label: t('dashboardMetrics.hero.crownJewels'),
          value: summary.crown_jewels_at_risk,
          tone: 'danger' as const,
          hint: t('insights.executive.crownHint', 'High-value assets exposed'),
          href: '/crown-jewels',
        },
      ]
    : []

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('insights.executive.title', 'Executive summary')}
          description={t(
            'insights.executive.description',
            'Risk posture, remediation performance and process health at a glance.'
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

        {/* Headline numbers */}
        {summaryLoading ? (
          <StripSkeleton />
        ) : !summary && summaryError ? (
          <WidgetError onRetry={() => void retrySummary()} className="rounded-lg border py-8" />
        ) : (
          <MetricStrip items={headline} />
        )}

        {/* Top risks */}
        <section className="space-y-3">
          <div>
            <h2 className="text-base font-semibold">
              {t('insights.executive.topRisks', 'Top risks')}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t(
                'insights.executive.topRisksHint',
                'Highest-priority findings that need executive attention.'
              )}
            </p>
          </div>
          {summaryLoading ? (
            <div className="space-y-px overflow-hidden rounded-lg border">
              {[1, 2, 3, 4, 5].map((i) => (
                <Skeleton key={i} className="h-11 w-full rounded-none" />
              ))}
            </div>
          ) : topRisks.length > 0 ? (
            <DataTable
              columns={columns}
              data={topRisks}
              error={summaryError}
              onRetry={() => void retrySummary()}
              errorTitle={t('insights.executive.topRisksTitle', 'top risks')}
              showSearch={false}
              showColumnToggle={false}
              showPagination={false}
              pageSize={topRisks.length}
              getRowId={(r) => r.rowId}
            />
          ) : !summary && summaryError ? null : (
            <EmptyState
              icon={ShieldCheck}
              title={t('insights.executive.noTopRisks', 'No top risks for the selected period')}
            />
          )}
        </section>

        {/* MTTR breakdown: a fixed 90-day window */}
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>{t('insights.executive.mttrSeverity', 'MTTR by severity')}</CardTitle>
              <CardDescription>
                {t('insights.executive.mttrSeverityHint', 'Average remediation time, {window}', {
                  window: window90.toLowerCase(),
                })}
                {mttr?.sample_size ? ` (n=${formatCount(mttr.sample_size, locale)})` : ''}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {mttrLoading ? (
                <Skeleton className="h-40 w-full" />
              ) : !mttr && mttrError ? (
                <WidgetError onRetry={() => void retryMttr()} className="h-40" />
              ) : mttr && Object.keys(mttr.by_severity).length > 0 ? (
                <div className="divide-y">
                  {Object.entries(mttr.by_severity)
                    .sort(([a], [b]) => compareSeverity(a, b))
                    .map(([severity, hours]) => (
                      <div key={severity} className="flex items-center justify-between py-2.5">
                        <SeverityBadge severity={severity.toLowerCase() as Severity} />
                        <span className="text-sm font-medium tabular-nums">
                          {formatHours(hours)}
                        </span>
                      </div>
                    ))}
                  <div className="flex items-center justify-between py-2.5">
                    <span className="text-sm font-medium">
                      {t('insights.executive.overall', 'Overall')}
                    </span>
                    <span className="text-sm font-semibold tabular-nums">
                      {formatHours(mttr.overall_hours)}
                    </span>
                  </div>
                </div>
              ) : (
                <EmptyState
                  card={false}
                  className="py-8"
                  icon={Timer}
                  title={t('insights.executive.mttrEmptyTitle', 'Not enough data yet')}
                  description={t(
                    'insights.executive.mttrEmptyDescription',
                    'MTTR appears once enough findings have been resolved.'
                  )}
                />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>
                {t('insights.executive.mttrPriority', 'MTTR by priority class')}
              </CardTitle>
              <CardDescription>
                {t(
                  'insights.executive.mttrPriorityHint',
                  'Average remediation time per priority class (P0 to P3), {window}',
                  { window: window90.toLowerCase() }
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {mttrLoading ? (
                <Skeleton className="h-40 w-full" />
              ) : !mttr && mttrError ? (
                <WidgetError onRetry={() => void retryMttr()} className="h-40" />
              ) : mttr && Object.keys(mttr.by_priority_class).length > 0 ? (
                <div className="divide-y">
                  {Object.entries(mttr.by_priority_class)
                    .sort(([a], [b]) => PRIORITY_CLASSES.indexOf(a) - PRIORITY_CLASSES.indexOf(b))
                    .map(([priority, hours]) => (
                      <div key={priority} className="flex items-center justify-between py-2.5">
                        <PriorityChip value={priority} />
                        <span className="text-sm font-medium tabular-nums">
                          {formatHours(hours)}
                        </span>
                      </div>
                    ))}
                </div>
              ) : (
                <EmptyState
                  card={false}
                  className="py-8"
                  icon={Timer}
                  title={t('insights.executive.priorityEmpty', 'No priority class data yet')}
                />
              )}
            </CardContent>
          </Card>
        </div>

        {/* Process metrics: a fixed 90-day window */}
        <section className="space-y-3">
          <h2 className="text-base font-semibold">
            {t('insights.executive.process', 'Process health')}
            <span className="ms-2 text-sm font-normal text-muted-foreground">{window90}</span>
          </h2>
          {processLoading ? (
            <StripSkeleton />
          ) : !processMetrics && processError ? (
            <WidgetError onRetry={() => void retryProcess()} className="rounded-lg border py-8" />
          ) : processMetrics ? (
            <Card>
              <CardContent className="py-0">
                <dl className="divide-y">
                  {[
                    {
                      key: 'approval',
                      label: t('insights.executive.approvalAvg', 'Approval avg time'),
                      value:
                        processMetrics.approval_count > 0
                          ? formatHours(processMetrics.approval_avg_hours)
                          : '—',
                      hint:
                        processMetrics.approval_count > 0
                          ? t('insights.executive.approvalsTracked', '{count} approvals tracked', {
                              count: formatCount(processMetrics.approval_count, locale),
                            })
                          : t('dashboardMetrics.executive.noApprovals', 'No approvals decided yet'),
                    },
                    {
                      key: 'stale',
                      label: t('insights.executive.stale', 'Stale assets'),
                      value: formatCount(processMetrics.stale_assets, locale),
                      hint: t('insights.executive.ofInventory', '{pct} of inventory', {
                        pct: formatPct(processMetrics.stale_assets_pct, { locale }),
                      }),
                    },
                    {
                      key: 'no-owner',
                      label: t('insights.executive.noOwner', 'Findings without owner'),
                      value: formatCount(processMetrics.findings_without_owner, locale),
                      hint: t('insights.executive.needTriage', 'Need triage assignment'),
                    },
                    {
                      key: 'assign',
                      label: t('insights.executive.timeToAssign', 'Avg time to assign'),
                      value: formatHours(processMetrics.avg_time_to_assign_hours),
                      hint: t(
                        'insights.executive.timeToAssignHint',
                        'From finding creation to owner assignment'
                      ),
                    },
                  ].map((row) => (
                    <div key={row.key} className="flex items-baseline justify-between gap-4 py-2.5">
                      <div className="min-w-0">
                        <dt className="text-sm font-medium">{row.label}</dt>
                        <dd className="text-xs text-muted-foreground">{row.hint}</dd>
                      </div>
                      <span className="text-sm font-semibold tabular-nums">{row.value}</span>
                    </div>
                  ))}
                </dl>
              </CardContent>
            </Card>
          ) : (
            <EmptyState
              icon={Users}
              title={t('insights.executive.processEmpty', 'No process metrics yet')}
            />
          )}
        </section>
      </PageStack>
    </Main>
  )
}
