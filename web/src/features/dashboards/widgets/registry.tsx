/**
 * Widget registry for customizable dashboards (RFC-021 Phase-1b).
 *
 * Every widget renders REAL data from an existing hook — no placeholders. A
 * dashboard's layout references these by `widget_type`; the catalog is built
 * from this map, permission-filtered per viewer.
 */

'use client'

import { findingStatusesInCategory } from '@/features/findings/types/finding.types'
import Link from '@/components/link'
import type { ReactNode } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Permission } from '@/lib/permissions'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { useDashboardStats } from '@/features/dashboard'
import { useFindingsApi } from '@/features/findings/api/use-findings-api'
import { DRILL } from '@/features/dashboard/lib/drill'
import {
  useExecutiveSummary,
  useThreatIntelStats,
  useScanCoverage,
  useAttackPaths,
} from '@/features/dashboard/hooks/use-ctem-dashboard'
import {
  INFORMATIONAL_LABEL,
  SEVERITY_LABELS,
  SEVERITY_LEVELS,
  severityCounts,
} from '@/lib/severity'

function useStats() {
  const { currentTenant } = useTenant()
  return useDashboardStats(currentTenant?.id ?? null)
}
function useSummary() {
  const { currentTenant } = useTenant()
  return useExecutiveSummary(currentTenant?.id ?? null)
}
function useThreatIntel() {
  const { currentTenant } = useTenant()
  return useThreatIntelStats(currentTenant?.id ?? null)
}
function useCoverage() {
  const { currentTenant } = useTenant()
  return useScanCoverage(currentTenant?.id ?? null)
}
function useAttack() {
  const { currentTenant } = useTenant()
  return useAttackPaths(currentTenant?.id ?? null)
}

const OPEN_EXCLUDE = findingStatusesInCategory('closed')

type WidgetSize = { w: number; h: number }

export interface WidgetDef {
  title: string
  description: string
  /** Message keys that replace title / description (the catalog shows them translated). */
  titleKey?: string
  descriptionKey?: string
  component: () => ReactNode
  defaultSize: WidgetSize
  requiredPermission?: string
  /** Module the widget's data belongs to: not offered, and shown as off, when it is off. */
  requiredModule?: string
}

// ── shared shells ───────────────────────────────────────────────────────────

/** A widget whose module is switched off for the organization. */
function ModuleOffShell({ title }: { title: string }) {
  const { t } = useTranslation()
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        {t('dashboardMetrics.state.moduleOff')}
      </CardContent>
    </Card>
  )
}

function StatShell({
  title,
  value,
  loading,
  href,
  tone = 'default',
  sub,
  error,
}: {
  title: string
  value: number | string
  /** A small line under the value. */
  sub?: string
  loading?: boolean
  /** The read failed: show "—" and say so, never a confident 0. */
  error?: unknown
  href?: string
  tone?: 'default' | 'danger'
}) {
  const { t } = useTranslation()
  const failed = !!error && !loading
  const shown = failed ? '—' : value
  const line = failed ? t('dashboardMetrics.state.loadFailed', "Couldn't load these figures") : sub
  const body = (
    <Card className={href ? 'h-full transition-colors hover:border-primary/50' : 'h-full'}>
      <CardContent className="p-5">
        <p className="text-sm text-muted-foreground">{title}</p>
        {loading ? (
          <Skeleton className="mt-2 h-8 w-16" />
        ) : (
          <p
            className={
              'mt-1 text-3xl font-semibold ' +
              (tone === 'danger' && typeof shown === 'number' && shown > 0
                ? 'text-destructive'
                : '')
            }
          >
            {shown}
          </p>
        )}
        {line && !loading && <p className="mt-1 text-xs text-muted-foreground">{line}</p>}
      </CardContent>
    </Card>
  )
  return href ? <Link href={href}>{body}</Link> : body
}

// ── tenant-wide widgets (useDashboardStats) ──────────────────────────────────

function SeverityBreakdownWidget() {
  const { t } = useTranslation()
  const { stats, isLoading } = useStats()
  // Every severity, Informational included (none folds into it).
  const by = severityCounts(stats.findings.bySeverity)
  // Each row opens the open findings of that severity: the list it counts.
  const rows: Array<[string, string, number]> = SEVERITY_LEVELS.map((s) => [
    s,
    s === 'info' ? INFORMATIONAL_LABEL : SEVERITY_LABELS[s],
    by[s],
  ])
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{t('dashboardMetrics.widget.severity.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : (
          <ul className="space-y-1.5">
            {rows.map(([sev, label, n]) => (
              <li key={sev}>
                <Link
                  href={`/findings?state=open&severity=${sev}`}
                  className="flex items-center justify-between rounded-sm text-sm hover:underline focus-visible:underline"
                >
                  <span className="text-muted-foreground">{label}</span>
                  <span className="font-medium tabular-nums">{n.toLocaleString()}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function OpenFindingsWidget() {
  const { t } = useTranslation()
  const { stats, isLoading, error } = useStats()
  return (
    <StatShell
      title={t('dashboardMetrics.widget.openFindings.title')}
      value={stats.findings.total}
      loading={isLoading}
      error={error}
      // The count is the open lens: open the same list.
      href="/findings?state=open"
    />
  )
}

function OverdueSlaWidget() {
  const { t } = useTranslation()
  const { stats, isLoading, error } = useStats()
  return (
    <StatShell
      title={t('dashboardMetrics.widget.overdue.title')}
      value={stats.findings.overdue}
      loading={isLoading}
      error={error}
      tone="danger"
      // The count is open findings overdue or exceeded: open the same list.
      href={DRILL.slaBreached}
    />
  )
}

function AssetsWidget() {
  const { t } = useTranslation()
  const { stats, isLoading, error } = useStats()
  return (
    <StatShell
      title={t('dashboardMetrics.widget.assets.title')}
      value={stats.assets.total}
      loading={isLoading}
      error={error}
      href="/assets"
    />
  )
}

// ── personal widgets (assigned to me) ────────────────────────────────────────

function AssignedToMeWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    per_page: 1,
  })
  return (
    <StatShell
      title={t('dashboardMetrics.widget.assigned.title')}
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      // The count is open findings related to me: open the same list (it
      // used to open every state).
      href={DRILL.mineOpen}
    />
  )
}

function MyCriticalHighWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    severities: ['critical', 'high'],
    per_page: 1,
  })
  return (
    <StatShell
      title={t('dashboardMetrics.widget.myCriticalHigh.title')}
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href={`${DRILL.mineOpen}&severity=critical,high`}
    />
  )
}

function MyOverdueSlaWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    sla_statuses: ['overdue', 'exceeded'],
    per_page: 1,
  })
  return (
    <StatShell
      title={t('dashboardMetrics.widget.myOverdue.title')}
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href={`${DRILL.mineOpen}&sla_status=overdue,exceeded`}
    />
  )
}

// ── program widgets (executive summary / threat intel / coverage) ────────────

function RiskScoreWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useSummary()
  // Average asset risk on a 0-100 scale; no summary means no figure, not 0.
  const risk = data?.risk_score_current
  return (
    <StatShell
      title={t('dashboardMetrics.widget.risk.title')}
      value={risk == null ? '—' : `${Math.round(risk)}/100`}
      sub={t('dashboardMetrics.widget.risk.sub')}
      loading={isLoading}
      error={error}
    />
  )
}

function SlaComplianceWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useSummary()
  // Null: no open finding has an SLA, so the share is not measured.
  const pct = data?.sla_compliance_pct
  return (
    <StatShell
      title={t('dashboardMetrics.widget.sla.title')}
      value={pct == null ? '—' : `${Math.round(pct)}%`}
      loading={isLoading}
      error={error}
    />
  )
}

function MttrWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useSummary()
  // Null: nothing critical was fixed in the period, so there is no time to report.
  const median = data?.mttr_critical_median_hours
  const p90 = data?.mttr_critical_p90_hours
  return (
    <StatShell
      title={t('dashboardMetrics.widget.mttr.title')}
      value={median == null ? '—' : `${Math.round(median)}h`}
      sub={
        median == null
          ? undefined
          : t('dashboardMetrics.widget.mttr.sub', undefined, {
              p90: p90 == null ? '—' : `${Math.round(p90)}h`,
              n: data?.mttr_critical_sample ?? 0,
            })
      }
      loading={isLoading}
      error={error}
    />
  )
}

function P0OpenWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useSummary()
  return (
    <StatShell
      title={t('dashboardMetrics.widget.p0.title')}
      value={data?.p0_open ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href={DRILL.p0Open}
    />
  )
}

function ScanCoverageWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useCoverage()
  return (
    <StatShell
      title={t('dashboardMetrics.widget.scanCoverage.title')}
      value={!data || data.total_scannable === 0 ? '—' : `${Math.round(data.coverage_percent)}%`}
      loading={isLoading}
      error={error}
      href="/scans"
    />
  )
}

function ReachableAssetsWidget() {
  const { t } = useTranslation()
  const on = useModuleEnabled('attack_surface')
  const { data, isLoading, error } = useAttack()
  const title = t('dashboardMetrics.widget.reachable.title')
  if (!on) return <ModuleOffShell title={title} />
  return (
    <StatShell
      title={title}
      value={data?.summary?.reachable_assets ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href="/attack-paths"
    />
  )
}

/**
 * The tenant's exposure to known-exploited vulnerabilities: open findings in
 * the KEV catalog (and how many are past the KEV due date), and open findings
 * with EPSS of at least 50 %. It used to show the size of the global KEV
 * catalog, which is the same for every organization.
 */
function ThreatIntelWidget() {
  const { t } = useTranslation()
  const { data, isLoading, error } = useThreatIntel()
  const kevOpen = data?.kev?.tenant_open_count
  const pastDue = data?.kev?.past_due_count
  const epss = data?.epss?.critical_risk_count
  const failed = !!error && !data
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{t('dashboardMetrics.widget.threatIntel.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : failed ? (
          <p className="text-xs text-muted-foreground">
            {t('dashboardMetrics.state.loadFailed', "Couldn't load these figures")}
          </p>
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <Link
              href={DRILL.kevOpen}
              className="rounded-sm hover:underline focus-visible:underline"
            >
              <p className="text-2xl font-semibold tabular-nums">
                {kevOpen == null ? '—' : kevOpen.toLocaleString()}
              </p>
              <p className="text-xs text-muted-foreground">
                {t('dashboardMetrics.threatIntel.kevOpen')}
              </p>
              {pastDue != null && pastDue > 0 && (
                <p className="text-xs text-muted-foreground">
                  {t('dashboardMetrics.threatIntel.pastDueSub', undefined, { n: pastDue })}
                </p>
              )}
            </Link>
            <div>
              <p className="text-2xl font-semibold tabular-nums">
                {epss == null ? '—' : epss.toLocaleString()}
              </p>
              <p className="text-xs text-muted-foreground">
                {t('dashboardMetrics.threatIntel.epssHot')}
              </p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── the registry ─────────────────────────────────────────────────────────────

export const WIDGET_REGISTRY: Record<string, WidgetDef> = {
  findings_by_severity: {
    title: 'Open findings by severity',
    description: 'Open findings broken down by severity',
    titleKey: 'dashboardMetrics.widget.severity.title',
    descriptionKey: 'dashboardMetrics.widget.severity.description',
    component: SeverityBreakdownWidget,
    defaultSize: { w: 4, h: 2 },
    requiredPermission: Permission.DashboardRead,
  },
  open_findings: {
    title: 'Open findings',
    description: 'Findings that still need work, across the organization',
    titleKey: 'dashboardMetrics.widget.openFindings.title',
    descriptionKey: 'dashboardMetrics.widget.openFindings.description',
    component: OpenFindingsWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  overdue_sla: {
    title: 'Overdue (SLA)',
    description: 'Findings past their SLA remediation deadline',
    titleKey: 'dashboardMetrics.widget.overdue.title',
    descriptionKey: 'dashboardMetrics.widget.overdue.description',
    component: OverdueSlaWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  assets_total: {
    title: 'Assets',
    description: 'Total assets in inventory',
    titleKey: 'dashboardMetrics.widget.assets.title',
    descriptionKey: 'dashboardMetrics.widget.assets.description',
    component: AssetsWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.AssetsRead,
  },
  assigned_to_me: {
    title: 'Mine · open',
    description: 'Open findings assigned to you, your team or on assets you own',
    titleKey: 'dashboardMetrics.widget.assigned.title',
    descriptionKey: 'dashboardMetrics.widget.assigned.description',
    component: AssignedToMeWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  my_critical_high: {
    title: 'My critical / high',
    description: 'Your critical and high findings',
    titleKey: 'dashboardMetrics.widget.myCriticalHigh.title',
    descriptionKey: 'dashboardMetrics.widget.myCriticalHigh.description',
    component: MyCriticalHighWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  my_overdue_sla: {
    title: 'My overdue (SLA)',
    description: 'Your findings past their SLA',
    titleKey: 'dashboardMetrics.widget.myOverdue.title',
    descriptionKey: 'dashboardMetrics.widget.myOverdue.description',
    component: MyOverdueSlaWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  risk_score: {
    title: 'Risk score',
    description: 'Current program risk score',
    titleKey: 'dashboardMetrics.widget.risk.title',
    descriptionKey: 'dashboardMetrics.widget.risk.description',
    component: RiskScoreWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  sla_compliance: {
    title: 'Open within SLA',
    description: 'Share of open findings that have an SLA and are not past it',
    titleKey: 'dashboardMetrics.widget.sla.title',
    descriptionKey: 'dashboardMetrics.widget.sla.description',
    component: SlaComplianceWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  mttr_critical: {
    title: 'Time to fix · critical (median)',
    description: 'Median hours to remediate critical findings in the period',
    titleKey: 'dashboardMetrics.widget.mttr.title',
    descriptionKey: 'dashboardMetrics.widget.mttr.description',
    component: MttrWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  p0_open: {
    title: 'P0 open',
    description: 'Open P0 — highest-priority findings',
    titleKey: 'dashboardMetrics.widget.p0.title',
    descriptionKey: 'dashboardMetrics.widget.p0.description',
    component: P0OpenWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  scan_coverage: {
    title: 'Scan coverage',
    description: 'Share of assets covered by scans',
    titleKey: 'dashboardMetrics.widget.scanCoverage.title',
    descriptionKey: 'dashboardMetrics.widget.scanCoverage.description',
    component: ScanCoverageWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  reachable_assets: {
    title: 'Assets reachable',
    description: 'Assets reachable from an exposed entry point',
    titleKey: 'dashboardMetrics.widget.reachable.title',
    descriptionKey: 'dashboardMetrics.widget.reachable.description',
    component: ReachableAssetsWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
    requiredModule: 'attack_surface',
  },
  threat_intel: {
    title: 'Known exploited',
    description: 'Your open findings in the KEV catalog and with EPSS of at least 50 %',
    titleKey: 'dashboardMetrics.widget.threatIntel.title',
    descriptionKey: 'dashboardMetrics.widget.threatIntel.description',
    component: ThreatIntelWidget,
    defaultSize: { w: 4, h: 2 },
    requiredPermission: Permission.DashboardRead,
  },
}

export type WidgetType = keyof typeof WIDGET_REGISTRY
