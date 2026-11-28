'use client'

/**
 * Building blocks shared by the four exposure-type overview pages
 * (vulnerabilities, code, secrets, misconfigurations). They used to carry four
 * copies of the same charts, each with its own hex severity map and its own
 * "No data" text; one set keeps them looking — and colouring severity — alike.
 */

import type { ReactNode } from 'react'
import Link from '@/components/link'
import type { LucideIcon } from 'lucide-react'
import { BarChart3 } from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from '@/components/charts'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, SeverityBadge, type Severity } from '@/features/shared'
import { SEVERITY_CHART_COLORS, SEVERITY_ORDER, type SeverityLevel } from '@/lib/severity-colors'
import { findingsHrefForSources } from './exposures-section'
import { SEVERITY_LABELS as SHARED_SEVERITY_LABELS } from '@/lib/severity'
import { useTranslation } from '@/context/i18n-provider'
import { formatNumber } from '@/lib/app-locale'
import { useSeverityLabel } from '@/hooks/use-scale-labels'
import { CHART_AXIS, CHART_GRID, CHART_TOOLTIP_PROPS } from '@/components/charts/chart-defaults'

export const SEVERITY_LABELS: Record<SeverityLevel, string> = SHARED_SEVERITY_LABELS

/** Categorical series colours from the theme (they carry their own dark values). */
export const CATEGORY_CHART_COLORS = [
  'var(--chart-1)',
  'var(--chart-2)',
  'var(--chart-3)',
  'var(--chart-4)',
  'var(--chart-5)',
]

/**
 * The legend under a chart: the caption size in the muted ink, in the order
 * of the series (the library sorts by name unless told not to).
 */
export const LEGEND_PROPS = {
  itemSorter: null,
  wrapperStyle: { fontSize: 12, color: 'var(--muted-foreground)' },
  formatter: (value: string) => <span className="text-muted-foreground">{value}</span>,
} as const

/** Grid of four headline cards, then the chart sections. */
export const OVERVIEW_STATS_GRID = 'grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4'
export const OVERVIEW_CHARTS_GRID = 'grid grid-cols-1 gap-4 lg:grid-cols-2'
/**
 * Two chart cards and the trend: the trend takes its own row (two columns
 * wide) up to a 2048 px screen, then all three share one row (the trend two
 * of four columns), so no chart card is stretched over half a wide page.
 */
export const OVERVIEW_CHARTS_WITH_TREND_GRID =
  'grid grid-cols-1 gap-4 lg:grid-cols-2 min-[128rem]:grid-cols-4'
export const OVERVIEW_TREND_CELL = 'lg:col-span-2'

/** `in_progress` → `In progress`. */
export function humanize(value: string): string {
  const text = value.replace(/_/g, ' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
}

/**
 * `stats={false}` for the pages that dropped the headline cards; `trend` for a
 * page whose charts row ends with the trend (`OVERVIEW_CHARTS_WITH_TREND_GRID`),
 * so the skeleton has the page's shape at every width.
 */
export function OverviewSkeleton({
  stats = true,
  trend = false,
}: {
  stats?: boolean
  trend?: boolean
}) {
  return (
    <div className="space-y-5">
      {stats && (
        <div className={OVERVIEW_STATS_GRID}>
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="mb-2 h-8 w-16" />
                <Skeleton className="h-3 w-20" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      <div className={trend ? OVERVIEW_CHARTS_WITH_TREND_GRID : OVERVIEW_CHARTS_GRID}>
        {(trend ? [1, 2, 3] : [1, 2]).map((i) => (
          <Card key={i} className={i === 3 ? OVERVIEW_TREND_CELL : undefined}>
            <CardHeader>
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-48" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-[300px] w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

/**
 * Shown when the API ignored the `sources` filter on `/findings/stats` (a server
 * older than that filter): its breakdowns are tenant-wide, so rather than pass
 * them off as this type's, show the exact per-type total and hand off to the
 * Findings list, which filters by source server-side.
 */
export function TypeBreakdownUnavailable({
  icon,
  total,
  noun,
  sources,
}: {
  icon: LucideIcon
  total: number
  /** Singular and plural, e.g. ['secret', 'secrets']. */
  noun: [string, string]
  sources: readonly string[]
}) {
  const { t } = useTranslation()
  return (
    <EmptyState
      icon={icon}
      title={`${formatNumber(total)} ${total === 1 ? noun[0] : noun[1]}`}
      description={t(
        'findings.typeOverview.breakdownUnavailable',
        'The breakdown for this type is not available here. The findings list shows it in full.'
      )}
      action={
        <Button asChild variant="outline" size="sm">
          <Link href={findingsHrefForSources(sources)}>
            {t('findings.typeOverview.viewInFindings', 'View in findings')}
          </Link>
        </Button>
      }
    />
  )
}

/** A card section: sentence-case title, one-line description, content. */
export function ChartCard({
  title,
  description,
  children,
  className,
}: {
  title: string
  description?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

/** The shared empty state, sized to stand in for a chart inside its card. */
export function ChartEmpty({
  title,
  description,
  icon = BarChart3,
}: {
  title: string
  description?: string
  icon?: LucideIcon
}) {
  return <EmptyState card={false} icon={icon} title={title} description={description} />
}

export function severityRows(
  bySeverity: Record<string, number>,
  label: (s: SeverityLevel) => string
) {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    name: label(severity),
    value: bySeverity[severity] || 0,
    color: SEVERITY_CHART_COLORS[severity],
  })).filter((d) => d.value > 0)
}

export function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const data = severityRows(bySeverity, severityLabel)
  if (data.length === 0)
    return <ChartEmpty title={t('exposures.chart.noSeverity', 'No severity data yet')} />
  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={100}
          paddingAngle={2}
          dataKey="value"
          label={({ name, value }) => `${name}: ${value}`}
        >
          {data.map((entry) => (
            <Cell key={entry.severity} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip {...CHART_TOOLTIP_PROPS} />
        <Legend {...LEGEND_PROPS} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function SeverityBars({ bySeverity }: { bySeverity: Record<string, number> }) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const data = severityRows(bySeverity, severityLabel)
  if (data.length === 0)
    return <ChartEmpty title={t('exposures.chart.noSeverity', 'No severity data yet')} />
  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} barCategoryGap="20%">
        <CartesianGrid {...CHART_GRID} />
        <XAxis dataKey="name" {...CHART_AXIS} />
        <YAxis {...CHART_AXIS} allowDecimals={false} />
        <Tooltip {...CHART_TOOLTIP_PROPS} />
        <Bar
          dataKey="value"
          name={t('exposures.chart.findings', 'Findings')}
          radius={[4, 4, 0, 0]}
          barSize={40}
        >
          {data.map((entry) => (
            <Cell key={entry.severity} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function StatusBars({ byStatus }: { byStatus: Record<string, number> }) {
  const { t } = useTranslation()
  const data = Object.entries(byStatus || {})
    .map(([status, count]) => ({
      name: t(`findings.status.${status}`, humanize(status)),
      count,
    }))
    .sort((a, b) => b.count - a.count)
  if (data.length === 0)
    return <ChartEmpty title={t('exposures.chart.noStatus', 'No status data yet')} />
  return (
    <ResponsiveContainer width="100%" height={Math.max(300, data.length * 40)}>
      <BarChart data={data} layout="vertical" barCategoryGap="20%">
        <CartesianGrid {...CHART_GRID} vertical horizontal={false} />
        <XAxis type="number" hide />
        <YAxis dataKey="name" type="category" {...CHART_AXIS} width={100} />
        <Tooltip {...CHART_TOOLTIP_PROPS} />
        <Bar
          dataKey="count"
          name={t('exposures.chart.findings', 'Findings')}
          fill="var(--chart-1)"
          radius={[0, 4, 4, 0]}
          barSize={20}
        />
      </BarChart>
    </ResponsiveContainer>
  )
}

export interface TrendPoint {
  date: string
  critical?: number
  high?: number
  medium?: number
  low?: number
  info?: number
}

export function SeverityTrend({
  data,
  height = 300,
  emptyDescription,
}: {
  data: TrendPoint[]
  height?: number
  emptyDescription?: string
}) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  if (data.length === 0) {
    return (
      <ChartEmpty
        title={t('exposures.chart.noTrend', 'No trend data yet')}
        description={emptyDescription}
      />
    )
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data}>
        <CartesianGrid {...CHART_GRID} vertical={false} />
        <XAxis dataKey="date" {...CHART_AXIS} />
        <YAxis {...CHART_AXIS} allowDecimals={false} />
        <Tooltip {...CHART_TOOLTIP_PROPS} />
        <Legend {...LEGEND_PROPS} />
        {SEVERITY_ORDER.map((severity) => (
          <Area
            key={severity}
            type="monotone"
            dataKey={severity}
            stackId="1"
            stroke={SEVERITY_CHART_COLORS[severity]}
            fill={SEVERITY_CHART_COLORS[severity]}
            fillOpacity={0.8}
            name={severityLabel(severity)}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}

/**
 * Share of findings per severity as divided rows (severity badge, count, bar) —
 * rows are separated by dividers, not boxed, so there is no card inside the card.
 */
export function SeverityShareList({
  bySeverity,
  total,
  noun,
}: {
  bySeverity: Record<string, number>
  total: number
  /** Singular and plural, e.g. ['secret', 'secrets']. */
  noun: [string, string]
}) {
  const { t } = useTranslation()
  const severityLabel = useSeverityLabel()
  const rows = severityRows(bySeverity, severityLabel)
  if (rows.length === 0)
    return (
      <ChartEmpty title={t('exposures.chart.nothingToPrioritise', 'Nothing to prioritise yet')} />
    )
  return (
    <ul className="divide-y">
      {rows.map((row) => {
        const percentage = total > 0 ? (row.value / total) * 100 : 0
        return (
          <li key={row.severity} className="flex items-center gap-4 py-3 first:pt-0 last:pb-0">
            <SeverityBadge severity={row.severity as Severity} className="w-20 justify-center" />
            <div className="min-w-0 flex-1">
              <div className="mb-1 flex items-center justify-between gap-2 text-sm">
                <span className="font-medium tabular-nums">
                  {formatNumber(row.value)} {row.value === 1 ? noun[0] : noun[1]}
                </span>
                <span className="text-muted-foreground tabular-nums">{percentage.toFixed(1)}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${percentage}%`, backgroundColor: row.color }}
                />
              </div>
            </div>
          </li>
        )
      })}
    </ul>
  )
}

/** Ranked bars for a small count breakdown, as divided rows. */
export function RankedBarList({
  rows,
  unit,
}: {
  rows: { name: string; count: number }[]
  /** Singular and plural, e.g. ['asset', 'assets']. */
  unit: [string, string]
}) {
  const { t } = useTranslation()
  if (rows.length === 0) return <ChartEmpty title={t('exposures.chart.noData', 'No data yet')} />
  const max = rows[0]?.count || 1
  return (
    <ul className="divide-y">
      {rows.map((row) => (
        <li key={row.name} className="flex items-center gap-4 py-3 first:pt-0 last:pb-0">
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center justify-between gap-2 text-sm">
              <span className="truncate font-medium">{row.name}</span>
              <span className="shrink-0 text-muted-foreground tabular-nums">
                {formatNumber(row.count)} {row.count === 1 ? unit[0] : unit[1]}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-primary transition-all"
                style={{ width: `${(row.count / max) * 100}%` }}
              />
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}
