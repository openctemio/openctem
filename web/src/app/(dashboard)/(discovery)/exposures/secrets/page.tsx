'use client'

import { Main } from '@/components/layout'
import { PageHeader, PageStack, EmptyState, ErrorState } from '@/features/shared'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  SeverityDonut,
  StatusBars,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { SECRET_SOURCES } from '@/features/exposures/lib/type-sources'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Lock } from 'lucide-react'

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

  return (
    <Main>
      <PageStack>
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

        {/* The list is the findings page; this one is the charts. */}
        {typeError ? (
          <ErrorState
            title={t('exposures.secrets.errorTitle', 'secret statistics')}
            error={typeError}
            onRetry={() => retryTypeStats()}
          />
        ) : isLoading ? (
          <OverviewSkeleton stats={false} />
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
          <PageStack>
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
          </PageStack>
        )}
      </PageStack>
    </Main>
  )
}
