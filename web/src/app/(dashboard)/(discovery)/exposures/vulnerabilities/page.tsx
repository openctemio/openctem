'use client'

import { Main } from '@/components/layout'
import {
  PageHeader,
  PageStack,
  EmptyState,
  ErrorState,
  FilterSelect,
  ViewSwitcher,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  SeverityDonut,
  SeverityTrend,
  StatusBars,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { useTenant } from '@/context/tenant-provider'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Bug, LayoutGrid, List } from 'lucide-react'
import { ActiveCVEsTab, VulnerabilityCatalogTab } from '@/features/vulnerabilities'
import { usePermissions, Permission } from '@/lib/permissions'
import { VULNERABILITY_SOURCES } from '@/features/exposures/lib/type-sources'

const TABS = ['overview', 'active', 'catalog'] as const

function OverviewTab() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null
  // Org-wide finding trend has no per-type variant.
  const { stats, isLoading: dashboardLoading } = useDashboardStats(tenantId)
  const {
    stats: typeStats,
    isLoading: typeLoading,
    error: typeError,
    mutate: retryTypeStats,
  } = useFindingTypeStats(tenantId, VULNERABILITY_SOURCES)

  if (typeError)
    return (
      <ErrorState
        title={t('exposures.vulnerabilities.errorTitle', 'vulnerability statistics')}
        error={typeError}
        onRetry={() => retryTypeStats()}
      />
    )

  if (dashboardLoading || typeLoading) return <OverviewSkeleton />

  if (typeStats.total === 0)
    return (
      <EmptyState
        icon={Bug}
        title={t('exposures.vulnerabilities.emptyTitle', 'No vulnerability data yet')}
        description={t(
          'exposures.vulnerabilities.emptyDescription',
          'Run vulnerability scans to discover exposures across your attack surface.'
        )}
      />
    )

  if (!typeStats.scoped)
    return (
      <TypeBreakdownUnavailable
        icon={Bug}
        total={typeStats.total}
        noun={[
          t('exposures.vulnerabilities.nounOne', 'vulnerability'),
          t('exposures.vulnerabilities.nounMany', 'vulnerabilities'),
        ]}
        sources={VULNERABILITY_SOURCES}
      />
    )

  return (
    <PageStack>
      <div className={OVERVIEW_CHARTS_GRID}>
        <ChartCard
          title={t('exposures.type.severityDistribution', 'Severity distribution')}
          description={t(
            'exposures.vulnerabilities.severityDescription',
            '{count} vulnerabilities by severity',
            { count: typeStats.total.toLocaleString() }
          )}
        >
          <SeverityDonut bySeverity={typeStats.bySeverity} />
        </ChartCard>
        <ChartCard
          title={t('exposures.type.status', 'Status')}
          description={t(
            'exposures.vulnerabilities.statusDescription',
            'Where each vulnerability is in remediation'
          )}
        >
          <StatusBars byStatus={typeStats.byStatus} />
        </ChartCard>
      </div>

      <ChartCard
        title={t('exposures.type.findingTrend', 'Finding trend')}
        description={t(
          'exposures.type.trendDescription',
          'Severity over time across all findings (a per-type trend is not available yet)'
        )}
      >
        <SeverityTrend
          data={stats.findingTrend}
          height={350}
          emptyDescription={t(
            'exposures.vulnerabilities.trendEmpty',
            'Run scans to start tracking vulnerability trends.'
          )}
        />
      </ChartCard>
    </PageStack>
  )
}

export default function VulnerabilitiesPage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  // Same SWR key as OverviewTab's call, so this is one request, not two.
  const { stats: typeStats, isLoading: typeLoading } = useFindingTypeStats(
    currentTenant?.id || null,
    VULNERABILITY_SOURCES
  )
  const { can } = usePermissions()
  const canReadCatalog = can(Permission.VulnerabilitiesRead)
  // Summary (?tab=overview) is the dashboard landing — visible to everyone with findings:read.
  // Active CVEs and CVE catalog are deeper exploration tabs to its right. The
  // tab lives in the URL so a view can be linked to.
  const [tabParam, setTab] = useUrlFilter('tab', 'overview')
  const tab =
    (TABS as readonly string[]).includes(tabParam) && (tabParam === 'overview' || canReadCatalog)
      ? tabParam
      : 'overview'

  // Summary and the CVE lists are two views of one subject: a view switch in
  // the header. Which CVEs the list shows (those affecting my assets, or the
  // whole catalog) is a token first in the list's toolbar. No second tab row
  // under the Exposures tabs (research/249 R21).
  const showsCves = tab === 'active' || tab === 'catalog'
  const cveList = (
    <FilterSelect<'active' | 'catalog'>
      label={t('exposures.vulnerabilities.cvesLabel', 'CVEs')}
      value={tab === 'catalog' ? 'catalog' : 'active'}
      clearable={false}
      options={[
        {
          value: 'active',
          label: t('exposures.vulnerabilities.cvesActive', 'Affecting my assets'),
        },
        { value: 'catalog', label: t('exposures.vulnerabilities.cvesCatalog', 'Whole catalog') },
      ]}
      onChange={(v) => setTab(v === 'catalog' ? 'catalog' : 'active')}
    />
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('exposures.vulnerabilities.title', 'Vulnerabilities')}
          description={t(
            'exposures.vulnerabilities.description',
            'Vulnerability findings across your assets, the CVEs behind them, and the CVE catalog.'
          )}
          viewSwitcher={
            canReadCatalog ? (
              <ViewSwitcher
                options={[
                  {
                    value: 'summary',
                    label: t('exposures.vulnerabilities.summaryView', 'Summary'),
                    icon: LayoutGrid,
                  },
                  {
                    value: 'cves',
                    label: t('exposures.vulnerabilities.cvesView', 'CVE list'),
                    icon: List,
                  },
                ]}
                value={showsCves ? 'cves' : 'summary'}
                onChange={(v) => setTab(v === 'cves' ? 'active' : '')}
              />
            ) : undefined
          }
        >
          <ViewFindingsButton
            stats={typeStats}
            sources={VULNERABILITY_SOURCES}
            isLoading={typeLoading}
          />
        </PageHeader>

        <ExposuresTabs />

        {tab === 'catalog' ? (
          <VulnerabilityCatalogTab leading={cveList} />
        ) : tab === 'active' ? (
          <ActiveCVEsTab leading={cveList} />
        ) : (
          <OverviewTab />
        )}
      </PageStack>
    </Main>
  )
}
