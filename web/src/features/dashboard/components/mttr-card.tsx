'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatChartDate } from '@/lib/format-chart-date'
import { Clock, TrendingDown, TrendingUp } from 'lucide-react'
import { SEVERITY_CHART_COLORS } from '@/lib/severity-colors'
import { STATE_TEXT } from '../lib/ctem-colors'
import { useRiskVelocity } from '../hooks/use-dashboard-stats'
import { useMttrAnalytics } from '../hooks/use-ctem-dashboard'
import { formatHours } from '../lib/format-hours'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import {
  BarChart,
  Bar,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from '@/components/charts'
import { ACTIONABLE_SEVERITIES, SEVERITY_LABELS } from '@/lib/severity'

/**
 * Mean time to remediate. It reads the same endpoint, window and field as the
 * Executive summary's "Overall" (useMttrAnalytics), so both show one figure;
 * it no longer averages the per-severity means. A severity with nothing
 * remediated in the window is "—", never 0m.
 */
export function MTTRCard() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const { data: mttr } = useMttrAnalytics(currentTenant?.id ?? null)

  if (!mttr) return null

  const bySeverity = mttr.by_severity ?? {}
  const chartData = ACTIONABLE_SEVERITIES.map((s) => ({
    severity: SEVERITY_LABELS[s],
    hours: Math.round(bySeverity[s] ?? 0),
    fill: SEVERITY_CHART_COLORS[s],
  })).filter((d) => d.hours > 0)

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Clock className="h-4 w-4 text-muted-foreground" />
          {t('dashboardMetrics.mttr.title', 'Mean time to remediate')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{formatHours(mttr.overall_hours)}</div>
        <div className="flex gap-3 mt-1 text-xs text-muted-foreground">
          <span>
            {t('dashboardMetrics.mttr.critical', 'Critical:')}{' '}
            <span className={`font-medium ${STATE_TEXT.crit}`}>
              {formatHours(bySeverity.critical)}
            </span>
          </span>
          <span>
            {t('dashboardMetrics.mttr.high', 'High:')}{' '}
            <span className="font-medium text-foreground">{formatHours(bySeverity.high)}</span>
          </span>
        </div>
        {chartData.length > 0 && (
          <div className="mt-3 h-[80px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                layout="vertical"
                margin={{ left: 0, right: 0, top: 0, bottom: 0 }}
              >
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="severity" width={50} tick={{ fontSize: 11 }} />
                <Tooltip
                  formatter={(value) => formatHours(Number(value))}
                  contentStyle={{ fontSize: 12 }}
                />
                <Bar dataKey="hours" radius={[0, 4, 4, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function RiskVelocityCard() {
  const { currentTenant } = useTenant()
  const { data: velocity } = useRiskVelocity(currentTenant?.id ?? null, 8)

  if (!velocity || velocity.length === 0) return null

  const latest = velocity[velocity.length - 1]
  const isImproving = latest.velocity <= 0
  const Icon = isImproving ? TrendingDown : TrendingUp

  const chartData = velocity.map((v) => ({
    week: formatChartDate(v.week),
    New: v.new_count,
    Resolved: v.resolved_count,
  }))

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Icon className={`h-4 w-4 ${isImproving ? STATE_TEXT.good : STATE_TEXT.crit}`} />
          Risk Velocity
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${isImproving ? STATE_TEXT.good : STATE_TEXT.crit}`}>
          {latest.velocity > 0 ? '+' : ''}
          {latest.velocity}
        </div>
        <div className="flex gap-3 mt-1 text-xs text-muted-foreground">
          <span>New: {latest.new_count}/wk</span>
          <span>Resolved: {latest.resolved_count}/wk</span>
        </div>
        {chartData.length > 1 && (
          <div className="mt-3 h-[100px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} opacity={0.3} />
                <XAxis dataKey="week" tick={{ fontSize: 10 }} />
                <YAxis hide />
                <Tooltip contentStyle={{ fontSize: 12 }} />
                <Bar dataKey="New" fill="#ef4444" radius={[2, 2, 0, 0]} barSize={12} />
                <Bar dataKey="Resolved" fill="#22c55e" radius={[2, 2, 0, 0]} barSize={12} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
