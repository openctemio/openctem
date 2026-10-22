'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { AlertTriangle } from 'lucide-react'
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  Cell,
  PieChart,
  Pie,
} from '@/components/charts'
import { SEVERITY_CHART_COLORS as SEVERITY_COLORS, severityChartData } from '@/lib/severity-colors'
import { CHART_TOOLTIP_PROPS } from '../lib/ctem-colors'
import { ActivityItem } from './activity-item'
import type { DashboardStats } from '../hooks/use-dashboard-stats'
import { INFORMATIONAL_LABEL, SEVERITY_LABELS, SEVERITY_LEVELS } from '@/lib/severity'

interface AnalystDetailProps {
  stats: DashboardStats
  isLoading?: boolean
}

/**
 * The analyst-detail layer below the CTEM action story: new findings per
 * month, open findings by severity, assets by type and recent activity.
 */
export function AnalystDetail({ stats, isLoading }: AnalystDetailProps) {
  const { t } = useTranslation()
  const findingsBySeverity = stats.findings.bySeverity || {}
  const assetsByType = stats.assets.byType || {}

  // Scale order, Informational as its own slice (none folds into it).
  const severityData = severityChartData(findingsBySeverity)

  const assetDistribution = Object.entries(assetsByType)
    .map(([name, count]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1).replace(/_/g, ' '),
      count,
    }))
    .sort((a, b) => b.count - a.count)

  if (isLoading) {
    return (
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-7">
        <Skeleton className="col-span-1 h-[340px] lg:col-span-4" />
        <Skeleton className="col-span-1 h-[340px] lg:col-span-3" />
      </section>
    )
  }

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-semibold tracking-tight">
        {t('dashboardMetrics.analyst.title')}
      </h2>

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-7">
        {/* Findings Trend */}
        <Card className="col-span-1 gap-4 lg:col-span-4">
          <CardHeader>
            {/* A flow (findings created per month), so columns, not a stacked
                area that reads as a stock. */}
            <CardTitle>{t('dashboardMetrics.analyst.newPerMonth')}</CardTitle>
            <CardDescription>{t('dashboardMetrics.analyst.newPerMonthDesc')}</CardDescription>
          </CardHeader>
          <CardContent>
            {stats.findingTrend.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={stats.findingTrend}>
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 12 }} tickLine={false} axisLine={false} />
                  <Tooltip {...CHART_TOOLTIP_PROPS} />
                  {/* Severity order (critical first), not alphabetical. */}
                  <Legend itemSorter={null} />
                  {SEVERITY_LEVELS.map((s) => (
                    <Bar
                      key={s}
                      dataKey={s}
                      stackId="1"
                      fill={SEVERITY_COLORS[s]}
                      name={s === 'info' ? INFORMATIONAL_LABEL : SEVERITY_LABELS[s]}
                    />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center">
                <p className="text-muted-foreground">{t('dashboardMetrics.analyst.noTrend')}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Severity Distribution */}
        <Card className="col-span-1 gap-4 lg:col-span-3">
          <CardHeader>
            <CardTitle>{t('dashboardMetrics.widget.severity.title')}</CardTitle>
            <CardDescription>{t('dashboardMetrics.analyst.severityDesc')}</CardDescription>
          </CardHeader>
          <CardContent>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip {...CHART_TOOLTIP_PROPS} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center">
                <p className="text-muted-foreground">{t('dashboardMetrics.analyst.noFindings')}</p>
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2 lg:h-[420px]">
        {/* Asset Distribution */}
        <Card className="flex h-full min-h-[380px] flex-col gap-4">
          <CardHeader>
            <CardTitle>{t('dashboardMetrics.analyst.assets')}</CardTitle>
            <CardDescription>
              {t('dashboardMetrics.analyst.assetsDesc', undefined, {
                n: stats.assets.total.toLocaleString(),
              })}
            </CardDescription>
          </CardHeader>
          <CardContent className="min-h-0 flex-1">
            {assetDistribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={assetDistribution} barCategoryGap="15%">
                  <XAxis
                    dataKey="name"
                    tick={{ fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    interval={0}
                    angle={-45}
                    textAnchor="end"
                    height={80}
                  />
                  <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} width={40} />
                  <Tooltip {...CHART_TOOLTIP_PROPS} />
                  <Bar dataKey="count" fill={SEVERITY_COLORS.low} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[250px] items-center justify-center">
                <p className="text-muted-foreground">{t('dashboardMetrics.analyst.noAssets')}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="flex h-full flex-col gap-4 overflow-hidden">
          <CardHeader className="flex-shrink-0">
            <CardTitle>{t('dashboardMetrics.analyst.activity')}</CardTitle>
            <CardDescription>{t('dashboardMetrics.analyst.activityDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="min-h-0 flex-1 overflow-y-auto">
            {stats.recentActivity.length > 0 ? (
              <div className="space-y-4">
                {stats.recentActivity.slice(0, 10).map((activity, index) => (
                  <ActivityItem
                    key={index}
                    icon={<AlertTriangle className="h-4 w-4 text-muted-foreground" />}
                    title={activity.title}
                    description={activity.description}
                    time={new Date(activity.timestamp).toLocaleDateString()}
                    href={
                      activity.type === 'finding' && activity.ref_id
                        ? `/findings/${activity.ref_id}`
                        : undefined
                    }
                  />
                ))}
              </div>
            ) : (
              <div className="flex h-[200px] items-center justify-center">
                <p className="text-muted-foreground">{t('dashboardMetrics.analyst.noActivity')}</p>
              </div>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  )
}
