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
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        Turned off for your organization.
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
  const rows: Array<[string, number]> = SEVERITY_LEVELS.map((s) => [
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
            {rows.map(([label, n]) => (
              <li key={label} className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-medium tabular-nums">{n}</span>
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
      href="/findings"
    />
  )
}

function OverdueSlaWidget() {
  const { stats, isLoading, error } = useStats()
  return (
    <StatShell
      title="Overdue (SLA)"
      value={stats.findings.overdue}
      loading={isLoading}
      error={error}
      tone="danger"
      // The count is open findings overdue or exceeded: open the same list.
      href="/findings?state=open&sla_status=overdue,exceeded"
    />
  )
}

function AssetsWidget() {
  const { stats, isLoading, error } = useStats()
  return (
    <StatShell
      title="Assets"
      value={stats.assets.total}
      loading={isLoading}
      error={error}
      href="/assets"
    />
  )
}

// ── personal widgets (assigned to me) ────────────────────────────────────────

function AssignedToMeWidget() {
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    per_page: 1,
  })
  return (
    <StatShell
      title="Assigned to me · open"
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      href="/findings?related_to=me"
    />
  )
}

function MyCriticalHighWidget() {
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    severities: ['critical', 'high'],
    per_page: 1,
  })
  return (
    <StatShell
      title="My critical / high"
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href="/findings?related_to=me&state=open&severity=critical,high"
    />
  )
}

function MyOverdueSlaWidget() {
  const { data, isLoading, error } = useFindingsApi({
    assigned_to_me: true,
    exclude_statuses: OPEN_EXCLUDE,
    sla_statuses: ['overdue', 'exceeded'],
    per_page: 1,
  })
  return (
    <StatShell
      title="My overdue (SLA)"
      value={data?.total ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href="/findings?related_to=me&state=open&sla_status=overdue,exceeded"
    />
  )
}

// ── program widgets (executive summary / threat intel / coverage) ────────────

function RiskScoreWidget() {
  const { data, isLoading, error } = useSummary()
  return (
    <StatShell
      title="Risk score"
      value={Math.round(data?.risk_score_current ?? 0)}
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
  const { data, isLoading, error } = useSummary()
  return (
    <StatShell
      title="P0 open"
      value={data?.p0_open ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href={DRILL.p0Open}
    />
  )
}

function ScanCoverageWidget() {
  const { data, isLoading, error } = useCoverage()
  return (
    <StatShell
      title="Scan coverage"
      value={!data || data.total_scannable === 0 ? '—' : `${Math.round(data.coverage_percent)}%`}
      loading={isLoading}
      error={error}
      href="/scans"
    />
  )
}

function ReachableAssetsWidget() {
  const on = useModuleEnabled('attack_surface')
  const { data, isLoading, error } = useAttack()
  if (!on) return <ModuleOffShell title="Assets reachable" />
  return (
    <StatShell
      title="Assets reachable"
      value={data?.summary?.reachable_assets ?? 0}
      loading={isLoading}
      error={error}
      tone="danger"
      href="/attack-paths"
    />
  )
}

function ThreatIntelWidget() {
  const { data, isLoading } = useThreatIntel()
  const kev = data?.kev?.total_entries ?? 0
  const epss = data?.epss?.critical_risk_count ?? 0
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Threat intel</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-2xl font-semibold tabular-nums">{kev}</p>
              <p className="text-xs text-muted-foreground">KEV entries</p>
            </div>
            <div>
              <p className="text-2xl font-semibold tabular-nums">{epss}</p>
              <p className="text-xs text-muted-foreground">High EPSS</p>
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
    component: OverdueSlaWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  assets_total: {
    title: 'Assets',
    description: 'Total assets in inventory',
    component: AssetsWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.AssetsRead,
  },
  assigned_to_me: {
    title: 'Assigned to me · open',
    description: 'Open findings assigned to you',
    component: AssignedToMeWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  my_critical_high: {
    title: 'My critical / high',
    description: 'Your critical and high findings',
    component: MyCriticalHighWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  my_overdue_sla: {
    title: 'My overdue (SLA)',
    description: 'Your findings past their SLA',
    component: MyOverdueSlaWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  risk_score: {
    title: 'Risk score',
    description: 'Current program risk score',
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
    component: P0OpenWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.FindingsRead,
  },
  scan_coverage: {
    title: 'Scan coverage',
    description: 'Share of assets covered by scans',
    component: ScanCoverageWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
  },
  reachable_assets: {
    title: 'Assets reachable',
    description: 'Assets reachable from an exposed entry point',
    component: ReachableAssetsWidget,
    defaultSize: { w: 3, h: 1 },
    requiredPermission: Permission.DashboardRead,
    requiredModule: 'attack_surface',
  },
  threat_intel: {
    title: 'Threat intel',
    description: 'KEV and high-EPSS exposure context',
    component: ThreatIntelWidget,
    defaultSize: { w: 4, h: 2 },
    requiredPermission: Permission.DashboardRead,
  },
}

export type WidgetType = keyof typeof WIDGET_REGISTRY
