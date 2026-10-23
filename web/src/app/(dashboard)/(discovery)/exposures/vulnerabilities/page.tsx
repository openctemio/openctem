'use client'

import { Main } from '@/components/layout'
import { PageHeader, StatsCard, EmptyState, ErrorState } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useDashboardStats } from '@/features/dashboard/hooks/use-dashboard-stats'
import { useFindingTypeStats } from '@/features/exposures/hooks'
import {
  ChartCard,
  OverviewSkeleton,
  OVERVIEW_CHARTS_GRID,
  OVERVIEW_STATS_GRID,
  SeverityDonut,
  SeverityTrend,
  StatusBars,
  TypeBreakdownUnavailable,
  ExposuresTabs,
  ViewFindingsButton,
} from '@/features/exposures/components'
import { useTenant } from '@/context/tenant-provider'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Bug, AlertTriangle, Clock, Shield, LayoutGrid, Database, ShieldAlert } from 'lucide-react'
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

  const criticalCount = typeStats.bySeverity.critical || 0
  const highCount = typeStats.bySeverity.high || 0
  const openCount = typeStats.openCount

  return (
    <div className="space-y-5">
      <div className={OVERVIEW_STATS_GRID}>
        <StatsCard
          title={t('exposures.vulnerabilities.total', 'Total vulnerabilities')}
          value={typeStats.total}
          icon={Bug}
        />
        <StatsCard
          title={t('exposures.type.critical', 'Critical')}
          value={criticalCount}
          valueClassName={criticalCount > 0 ? 'text-destructive' : undefined}
          description={
            criticalCount > 0
              ? t('exposures.vulnerabilities.criticalAction', 'Immediate action required')
              : t('exposures.vulnerabilities.criticalNone', 'No critical issues')
          }
          icon={AlertTriangle}
        />
        <StatsCard
          title={t('exposures.type.high', 'High')}
          value={highCount}
          description={t('exposures.type.shareOfTotal', '{percent}% of total', {
            percent: ((highCount / typeStats.total) * 100).toFixed(0),
          })}
          icon={Shield}
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
    </div>
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

  return (
    <Main>
      <PageHeader
        title={t('exposures.vulnerabilities.title', 'Vulnerabilities')}
        description={t(
          'exposures.vulnerabilities.description',
          'Vulnerability findings across your assets, the CVEs behind them, and the CVE catalog.'
        )}
      >
        <ViewFindingsButton
          stats={typeStats}
          sources={VULNERABILITY_SOURCES}
          isLoading={typeLoading}
        />
      </PageHeader>

      <ExposuresTabs />

      <Tabs value={tab} onValueChange={setTab} className="mt-4">
        <TabsList>
          <TabsTrigger value="overview" className="gap-2">
            <LayoutGrid className="h-4 w-4" />
            {/* "Summary", not "Overview": the Exposures section tabs above
                already have an Overview (/exposures). */}
            {t('exposures.vulnerabilities.summaryTab', 'Summary')}
          </TabsTrigger>
          {canReadCatalog && (
            <TabsTrigger value="active" className="gap-2">
              <ShieldAlert className="h-4 w-4" />
              {t('exposures.vulnerabilities.activeTab', 'Active CVEs')}
            </TabsTrigger>
          )}
          {canReadCatalog && (
            <TabsTrigger value="catalog" className="gap-2">
              <Database className="h-4 w-4" />
              {t('exposures.vulnerabilities.catalogTab', 'CVE catalog')}
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="overview" className="mt-5">
          <OverviewTab />
        </TabsContent>

        {canReadCatalog && (
          <TabsContent value="active" className="mt-5">
            <ActiveCVEsTab />
          </TabsContent>
        )}

        {canReadCatalog && (
          <TabsContent value="catalog" className="mt-5">
            <VulnerabilityCatalogTab />
          </TabsContent>
        )}
      </Tabs>
    </Main>
  )
}
