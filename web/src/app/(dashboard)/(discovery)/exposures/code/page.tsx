'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack, EmptyState, ErrorState } from '@/features/shared'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  SeverityDonut,
  SeverityTrend,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { CODE_SOURCES } from '@/features/exposures/lib/type-sources'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { FileCode } from 'lucide-react'

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

  return (
    <Main>
      <PageStack>
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

        {/* The list is the findings page; this one is the charts. */}
        {typeError ? (
          <ErrorState
            title={t('exposures.code.errorTitle', 'code weakness statistics')}
            error={typeError}
            onRetry={() => retryTypeStats()}
          />
        ) : isLoading ? (
          <OverviewSkeleton stats={false} />
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
          <PageStack>
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
          </PageStack>
        )}
      </PageStack>
    </Main>
  )
}
