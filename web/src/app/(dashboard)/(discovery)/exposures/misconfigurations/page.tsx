'use client'

import { useMemo } from 'react'
import dynamic from 'next/dynamic'
import { Main } from '@/components/layout'
import {
  PageHeader,
  StatsCard,
  EmptyState,
  ErrorState,
  formatRiskScore,
  getRiskLevel,
} from '@/features/shared'
import { Skeleton } from '@/components/ui/skeleton'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  CATEGORY_CHART_COLORS,
  ChartCard,
  ChartEmpty,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  OVERVIEW_STATS_GRID,
  SeverityBars,
  humanize,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { MISCONFIG_SOURCES } from '@/features/exposures/lib/type-sources'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Settings2, AlertTriangle, Clock, Shield } from 'lucide-react'

const AssetTypePie = dynamic(() => import('@/features/exposures/components/asset-type-pie'), {
  ssr: false,
  loading: () => <Skeleton className="h-[300px] w-full" />,
})

export default function MisconfigurationsPage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null
  // Org-wide asset-type mix has no per-type variant.
  const { stats, isLoading: dashboardLoading } = useDashboardStats(tenantId)
  // Type-scoped finding stats: misconfigurations come from IaC and cloud posture scanning.
  const {
    stats: typeStats,
    isLoading: typeLoading,
    error: typeError,
    mutate: retryTypeStats,
  } = useFindingTypeStats(tenantId, MISCONFIG_SOURCES)
  const isLoading = dashboardLoading || typeLoading

  const criticalCount = typeStats.bySeverity.critical || 0
  const openCount = typeStats.openCount

  const assetTypeData = useMemo(
    () =>
      Object.entries(stats.assets.byType || {})
        .map(([type, count], index) => ({
          name: humanize(type),
          value: count,
          color: CATEGORY_CHART_COLORS[index % CATEGORY_CHART_COLORS.length],
        }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 8),
    [stats.assets.byType]
  )

  return (
    <Main>
      <PageHeader
        title={t('exposures.misconfigurations.title', 'Misconfigurations')}
        description={t(
          'exposures.misconfigurations.description',
          'Infrastructure and cloud misconfigurations found by IaC and cloud posture scanning, by severity.'
        )}
      >
        <ViewFindingsButton stats={typeStats} sources={MISCONFIG_SOURCES} isLoading={typeLoading} />
      </PageHeader>

      <ExposuresTabs />

      <div className="mt-5">
        {typeError ? (
          <ErrorState
            title={t('exposures.misconfigurations.errorTitle', 'misconfiguration statistics')}
            error={typeError}
            onRetry={() => retryTypeStats()}
          />
        ) : isLoading ? (
          <OverviewSkeleton />
        ) : typeStats.total === 0 ? (
          <EmptyState
            icon={Settings2}
            title={t('exposures.misconfigurations.emptyTitle', 'No misconfigurations yet')}
            description={t(
              'exposures.misconfigurations.emptyDescription',
              'Run IaC or cloud posture scans to identify infrastructure and cloud misconfigurations.'
            )}
          />
        ) : !typeStats.scoped ? (
          <TypeBreakdownUnavailable
            icon={Settings2}
            total={typeStats.total}
            noun={[
              t('exposures.misconfigurations.nounOne', 'misconfiguration'),
              t('exposures.misconfigurations.nounMany', 'misconfigurations'),
            ]}
            sources={MISCONFIG_SOURCES}
          />
        ) : (
          <div className="space-y-5">
            <div className={OVERVIEW_STATS_GRID}>
              <StatsCard
                title={t('exposures.type.totalFindings', 'Total findings')}
                value={typeStats.total}
                icon={Settings2}
              />
              <StatsCard
                title={t('exposures.misconfigurations.critical', 'Critical misconfigurations')}
                value={criticalCount}
                valueClassName={criticalCount > 0 ? 'text-destructive' : undefined}
                description={
                  criticalCount > 0
                    ? t(
                        'exposures.misconfigurations.criticalAction',
                        'Immediate remediation needed'
                      )
                    : t('exposures.misconfigurations.criticalNone', 'No critical issues')
                }
                icon={AlertTriangle}
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
              <StatsCard
                title={t('exposures.type.riskScore', 'Risk score')}
                value={formatRiskScore(typeStats.riskScore)}
                description={getRiskLevel(typeStats.riskScore).label}
                icon={Shield}
              />
            </div>

            <div className={OVERVIEW_CHARTS_GRID}>
              <ChartCard
                title={t('exposures.type.findingsBySeverity', 'Findings by severity')}
                description={t(
                  'exposures.misconfigurations.severityDescription',
                  '{count} misconfigurations by severity',
                  { count: typeStats.total.toLocaleString() }
                )}
              >
                <SeverityBars bySeverity={typeStats.bySeverity} />
              </ChartCard>
              <ChartCard
                title={t('exposures.misconfigurations.assetsByType', 'Assets by type')}
                description={t(
                  'exposures.misconfigurations.assetsDescription',
                  'Your asset mix across {count} assets',
                  { count: stats.assets.total.toLocaleString() }
                )}
              >
                {assetTypeData.length > 0 ? (
                  <AssetTypePie data={assetTypeData} />
                ) : (
                  <ChartEmpty
                    title={t('exposures.misconfigurations.assetsEmpty', 'No asset type data yet')}
                  />
                )}
              </ChartCard>
            </div>
          </div>
        )}
      </div>
    </Main>
  )
}
