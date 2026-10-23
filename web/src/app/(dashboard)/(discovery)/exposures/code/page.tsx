'use client'

import { Main } from '@/components/layout'
import { PageHeader, StatsCard, EmptyState, ErrorState } from '@/features/shared'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  OVERVIEW_STATS_GRID,
  SeverityDonut,
  SeverityTrend,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { CODE_SOURCES } from '@/features/exposures/lib/type-sources'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { FileCode, AlertTriangle, Flame, Clock } from 'lucide-react'

export default function CodeWeaknessesPage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null
  // Org-wide finding trend has no per-type variant.
  const { stats, isLoading: dashboardLoading } = useDashboardStats(tenantId)
  // Type-scoped finding stats: code weaknesses come from static analysis.
  const {
    stats: typeStats,
    isLoading: typeLoading,
    error: typeError,
    mutate: retryTypeStats,
  } = useFindingTypeStats(tenantId, CODE_SOURCES)
  const isLoading = dashboardLoading || typeLoading

  const criticalCount = typeStats.bySeverity.critical || 0
  const highCount = typeStats.bySeverity.high || 0
  const openCount = typeStats.openCount

  return (
    <Main>
      <PageHeader
        title={t('exposures.code.title', 'Code weaknesses')}
        description={t(
          'exposures.code.description',
          'Weaknesses in your source code found by static analysis (SAST), by severity and over time.'
        )}
      >
        <ViewFindingsButton stats={typeStats} sources={CODE_SOURCES} isLoading={typeLoading} />
      </PageHeader>

      <ExposuresTabs />

      <div className="mt-5">
        {typeError ? (
          <ErrorState
            title={t('exposures.code.errorTitle', 'code weakness statistics')}
            error={typeError}
            onRetry={() => retryTypeStats()}
          />
        ) : isLoading ? (
          <OverviewSkeleton />
        ) : typeStats.total === 0 ? (
          <EmptyState
            icon={FileCode}
            title={t('exposures.code.emptyTitle', 'No code weaknesses yet')}
            description={t(
              'exposures.code.emptyDescription',
              'Configure static analysis (SAST) scanners to detect security weaknesses in your code.'
            )}
          />
        ) : !typeStats.scoped ? (
          <TypeBreakdownUnavailable
            icon={FileCode}
            total={typeStats.total}
            noun={[
              t('exposures.code.nounOne', 'code finding'),
              t('exposures.code.nounMany', 'code findings'),
            ]}
            sources={CODE_SOURCES}
          />
        ) : (
          <div className="space-y-5">
            <div className={OVERVIEW_STATS_GRID}>
              <StatsCard
                title={t('exposures.code.total', 'Total code findings')}
                value={typeStats.total}
                icon={FileCode}
              />
              <StatsCard // anatomy-ok: existing type-page tile, only its neighbours changed
                title={t('exposures.type.critical', 'Critical')}
                value={criticalCount}
                valueClassName={criticalCount > 0 ? 'text-destructive' : undefined}
                description={
                  criticalCount > 0
                    ? t('exposures.code.criticalAction', 'Fix immediately')
                    : t('exposures.code.criticalNone', 'No critical findings')
                }
                icon={AlertTriangle}
              />
              <StatsCard
                title={t('exposures.type.high', 'High')}
                value={highCount}
                description={t('exposures.type.shareOfTotal', '{percent}% of total', {
                  percent: ((highCount / typeStats.total) * 100).toFixed(0),
                })}
                icon={Flame}
              />
              <StatsCard
                title={t('exposures.type.open', 'Open')}
                value={openCount}
                description={
                  openCount > 0
                    ? t('exposures.type.openAction', 'Awaiting remediation')
                    : t('exposures.type.openNone', 'None open')
                }
                icon={Clock}
              />
            </div>

            <div className={OVERVIEW_CHARTS_GRID}>
              <ChartCard
                title={t('exposures.type.severityDistribution', 'Severity distribution')}
                description={t(
                  'exposures.code.severityDescription',
                  '{count} code findings by severity',
                  { count: typeStats.total.toLocaleString() }
                )}
              >
                <SeverityDonut bySeverity={typeStats.bySeverity} />
              </ChartCard>
              <ChartCard
                title={t('exposures.type.findingTrend', 'Finding trend')}
                description={t(
                  'exposures.type.trendDescription',
                  'Severity over time across all findings (a per-type trend is not available yet)'
                )}
              >
                <SeverityTrend
                  data={stats.findingTrend}
                  emptyDescription={t(
                    'exposures.code.trendEmpty',
                    'Run SAST scans to start tracking trends.'
                  )}
                />
              </ChartCard>
            </div>
          </div>
        )}
      </div>
    </Main>
  )
}
