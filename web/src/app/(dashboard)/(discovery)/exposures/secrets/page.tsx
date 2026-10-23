'use client'

import { Main } from '@/components/layout'
import {
  PageHeader,
  StatsCard,
  EmptyState,
  ErrorState,
  formatRiskScore,
  getRiskLevel,
} from '@/features/shared'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  OVERVIEW_STATS_GRID,
  SeverityDonut,
  StatusBars,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { SECRET_SOURCES } from '@/features/exposures/lib/type-sources'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Lock, AlertTriangle, Clock, Shield } from 'lucide-react'

export default function SecretsExposurePage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null
  // Type-scoped finding stats: exposed secrets/credentials.
  const {
    stats: typeStats,
    isLoading,
    error: typeError,
    mutate: retryTypeStats,
  } = useFindingTypeStats(tenantId, SECRET_SOURCES)

  const criticalCount = typeStats.bySeverity.critical || 0
  const openCount = typeStats.openCount

  return (
    <Main>
      <PageHeader
        title={t('exposures.secrets.title', 'Secrets')}
        description={t(
          'exposures.secrets.description',
          'Secrets committed to your code (API keys, tokens, passwords), by severity and remediation status.'
        )}
      >
        <ViewFindingsButton stats={typeStats} sources={SECRET_SOURCES} isLoading={isLoading} />
      </PageHeader>

      <ExposuresTabs />

      <div className="mt-5">
        {typeError ? (
          <ErrorState
            title={t('exposures.secrets.errorTitle', 'secret statistics')}
            error={typeError}
            onRetry={() => retryTypeStats()}
          />
        ) : isLoading ? (
          <OverviewSkeleton />
        ) : typeStats.total === 0 ? (
          <EmptyState
            icon={Lock}
            title={t('exposures.secrets.emptyTitle', 'No secret exposures yet')}
            description={t(
              'exposures.secrets.emptyDescription',
              'Configure secret scanning to detect exposed credentials in your codebase.'
            )}
          />
        ) : !typeStats.scoped ? (
          <TypeBreakdownUnavailable
            icon={Lock}
            total={typeStats.total}
            noun={[
              t('exposures.secrets.nounOne', 'secret'),
              t('exposures.secrets.nounMany', 'secrets'),
            ]}
            sources={SECRET_SOURCES}
          />
        ) : (
          <div className="space-y-5">
            <div className={OVERVIEW_STATS_GRID}>
              <StatsCard
                title={t('exposures.type.totalFindings', 'Total findings')}
                value={typeStats.total}
                icon={Lock}
              />
              <StatsCard
                title={t('exposures.secrets.critical', 'Critical secrets')}
                value={criticalCount}
                valueClassName={criticalCount > 0 ? 'text-destructive' : undefined}
                description={
                  criticalCount > 0
                    ? t('exposures.secrets.criticalAction', 'Rotate immediately')
                    : t('exposures.secrets.criticalNone', 'No critical secrets')
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
                title={t('exposures.type.severityDistribution', 'Severity distribution')}
                description={t(
                  'exposures.secrets.severityDescription',
                  '{count} secret findings by severity',
                  { count: typeStats.total.toLocaleString() }
                )}
              >
                <SeverityDonut bySeverity={typeStats.bySeverity} />
              </ChartCard>
              <ChartCard
                title={t('exposures.type.status', 'Status')}
                description={t(
                  'exposures.secrets.statusDescription',
                  'Where each exposed secret is in remediation'
                )}
              >
                <StatusBars byStatus={typeStats.byStatus} />
              </ChartCard>
            </div>
          </div>
        )}
      </div>
    </Main>
  )
}
